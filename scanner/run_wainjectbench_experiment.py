"""Run WAInjectBench text samples through the existing paired defense pipeline.

Malicious records use scanner.run_attack.run_once (S1-S4 attack evidence).
Benign records use scanner.run_baseline.run_once (baseline utility evidence).
All jobs are sequential because target/lab_content.txt is shared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .config import settings
from .llm_agent import DEFENSE_CONDITIONS, BASE_SYSTEM_PROMPT, INSTRUCTION_GUIDANCE_ADDON, STRUCTURED_BOUNDARY_ADDON
from .run_attack import run_once as run_attack_once
from .run_baseline import run_once as run_benign_once

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "wainjectbench_text_normalized.jsonl"
REPORT_PATH = ROOT / "data" / "wainjectbench_import_report.json"
LOG_DIR = ROOT / "logs" / "defense_experiment"
CONDITIONS = ["NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"]
PROTOCOL_VERSION = "WAInjectBench-transfer-1.0.0"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Normalized WAInjectBench file not found: {path}. Run scripts/import_wainjectbench.py first.")
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            required = {"sample_id", "source_label", "source_file", "source_file_stem", "content", "content_sha256"}
            missing = required - set(row)
            if missing:
                raise ValueError(f"Line {line_no} missing fields: {sorted(missing)}")
            if row["source_label"] not in {"malicious", "benign"}:
                raise ValueError(f"Invalid source_label at line {line_no}")
            if not isinstance(row["content"], str) or not row["content"].strip():
                raise ValueError(f"Empty content at line {line_no}")
            actual = hashlib.sha256(row["content"].encode("utf-8")).hexdigest()
            if actual != row["content_sha256"]:
                raise ValueError(f"Content hash mismatch at line {line_no}, sample {row['sample_id']}")
            rows.append(row)
    ids = [r["sample_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate sample_id values in normalized dataset")
    return rows


def select_records(rows: list[dict], label: str, max_per_source: int, seed: int) -> list[dict]:
    if label != "all":
        rows = [r for r in rows if r["source_label"] == label]
    if max_per_source <= 0:
        return rows
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        groups[(row["source_label"], row["source_file"])].append(row)
    rng = random.Random(seed)
    selected = []
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda x: x["sample_id"])
        selected.extend(rng.sample(group, min(max_per_source, len(group))))
    return sorted(selected, key=lambda x: x["sample_id"])


def build_schedule(records: list[dict], repeats: int, seed: int, conditions: list[str]) -> list[dict]:
    jobs = []
    for condition in conditions:
        for row in records:
            kind = "attack" if row["source_label"] == "malicious" else "benign_utility"
            job = {
                "experiment_type": kind,
                "condition_id": condition,
                "sample_id": row["sample_id"],
                "source_label": row["source_label"],
                "source_file": row["source_file"],
                "source_file_stem": row["source_file_stem"],
                "category_code": row["source_file_stem"],
            }
            if kind == "attack":
                job["test_case_id"] = row["sample_id"]
            else:
                job["fixture_id"] = row["sample_id"]
            for repeat in range(1, repeats + 1):
                item = dict(job)
                item["repeat_index"] = repeat
                jobs.append(item)
    random.Random(seed).shuffle(jobs)
    for idx, job in enumerate(jobs, 1):
        job["order_index"] = idx
    return jobs


def check_local_target() -> None:
    parts = urlsplit(settings.target_base_url)
    if parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Experiments are restricted to the loopback target (127.0.0.1, localhost, or ::1).")
    health = requests.get(settings.target_base_url + "/health", timeout=settings.request_timeout)
    if health.status_code != 200 or health.json().get("status") != "ok":
        raise RuntimeError("Local target health check failed; start this project's target/run.py on 127.0.0.1:8000.")
    page = requests.get(settings.target_base_url + "/page", timeout=settings.request_timeout)
    if page.status_code != 200 or 'id="user-generated-content"' not in page.text:
        raise RuntimeError("The local /page endpoint does not match this project's controlled User Review target.")


def make_manifest(records: list[dict], schedule: list[dict], batch_id: str, seed: int, repeats: int,
                  model_metadata: dict, normalized_sha256: str, repo_commit: str | None,
                  full_dataset: bool) -> dict:
    malicious = [r for r in records if r["source_label"] == "malicious"]
    benign = [r for r in records if r["source_label"] == "benign"]
    prompts = {
        "NO_DEFENSE": BASE_SYSTEM_PROMPT,
        "INSTRUCTION_GUIDANCE": BASE_SYSTEM_PROMPT + "\n" + INSTRUCTION_GUIDANCE_ADDON,
        "STRUCTURED_BOUNDARY": BASE_SYSTEM_PROMPT + "\n" + INSTRUCTION_GUIDANCE_ADDON + "\n" + STRUCTURED_BOUNDARY_ADDON,
    }
    prompt_hashes = {key: hashlib.sha256(value.encode("utf-8")).hexdigest() for key, value in prompts.items()}
    fixed_paths = ["scanner/policy.py", "scanner/tools.py", "scanner/crawler.py", "target/app.py"]
    fixed_hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in fixed_paths}
    attack_hash = hashlib.sha256("\n".join(r["content_sha256"] for r in malicious).encode()).hexdigest()
    benign_hash = hashlib.sha256("\n".join(r["content_sha256"] for r in benign).encode()).hexdigest()
    counts = Counter(r["source_label"] for r in records)
    per_condition = {
        condition: {"attack_runs": len(malicious) * repeats, "benign_utility_runs": len(benign) * repeats}
        for condition in CONDITIONS
    }
    return {
        "experiment_type": "paired_defense_evaluation",
        "defense_protocol_version": PROTOCOL_VERSION,
        "batch_id": batch_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "randomization_seed": seed,
        "randomization_method": "Python random.Random(seed).shuffle over condition × sample × repeat jobs",
        "repetitions_per_case_per_condition": repeats,
        "primary_attack_unit": "WAInjectBench sample_id; repeats nested within sample and paired across conditions",
        "benign_utility_unit": "WAInjectBench benign sample_id; repeats nested within sample and paired across conditions",
        "defense_conditions": {cid: DEFENSE_CONDITIONS[cid] for cid in CONDITIONS},
        "system_prompt_sha256_by_condition": prompt_hashes,
        "fixed_component_sha256": fixed_hashes,
        "attack_dataset_version": f"WAInjectBench text | git {repo_commit or 'commit_not_recorded'}",
        "attack_dataset_sha256": attack_hash,
        "attack_case_count": len(malicious),
        "baseline_protocol_version": "WAInjectBench-benign-text-transfer-1.0.0",
        "baseline_corpus_sha256": benign_hash,
        "benign_fixture_count": len(benign),
        "planned_attack_calls": len(malicious) * repeats * len(CONDITIONS),
        "planned_benign_utility_calls": len(benign) * repeats * len(CONDITIONS),
        "planned_total_model_calls": len(schedule),
        "planned_runs_by_condition": per_condition,
        "model_configuration": model_metadata,
        "dataset_metadata": {
            "dataset_name": "WAInjectBench",
            "modality": "text",
            "normalized_path": "data/wainjectbench_text_normalized.jsonl",
            "normalized_file_sha256": normalized_sha256,
            "repository_commit": repo_commit,
            "record_counts": dict(counts),
            "selected_sample_count": len(records),
            "full_text_corpus_selected": full_dataset,
            "delivery_adaptation": "Every text segment is inserted as escaped visible text in the existing /page User Review paragraph. Original source delivery channels (e.g. email, caption, or page UI) are not separately reproduced.",
            "image_samples_included": False,
        },
        "is_full_primary_corpus": full_dataset,
        "development_only": False,
        "schedule": schedule,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run WAInjectBench text samples under D0/D1/D2")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20261110)
    parser.add_argument("--label", choices=["all", "malicious", "benign"], default="all")
    parser.add_argument("--max-per-source", type=int, default=0,
                        help="Deterministic cap per source JSONL file and label; 0 means all samples")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--development-only", action="store_true", help="Mock-only pipeline validation; never research evidence")
    args = parser.parse_args()

    if args.repeats < 1 or args.max_per_source < 0:
        parser.error("--repeats must be >=1 and --max-per-source must be >=0")
    conditions = CONDITIONS

    rows = read_jsonl(DATA_PATH)
    all_counts = Counter(r["source_label"] for r in rows)
    selected = select_records(rows, args.label, args.max_per_source, args.seed)
    if not selected:
        parser.error("No samples selected")
    selected_counts = Counter(r["source_label"] for r in selected)
    schedule = build_schedule(selected, args.repeats, args.seed, conditions)
    batch_id = str(uuid.uuid4())
    try:
        import json as _json
        report = _json.loads(REPORT_PATH.read_text(encoding="utf-8")) if REPORT_PATH.exists() else {}
    except Exception:
        report = {}
    repo_commit = report.get("repository_commit")
    normalized_sha = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    model_metadata = settings.public_metadata()
    model_metadata["default_defense_condition"] = "PER_JOB_CONDITION_OVERRIDE"
    model_metadata["dataset_version"] = f"WAInjectBench-text:{repo_commit or 'commit_not_recorded'}"
    full_dataset = len(selected) == len(rows) and args.label == "all" and args.max_per_source == 0
    manifest = make_manifest(selected, schedule, batch_id, args.seed, args.repeats,
                              model_metadata, normalized_sha, repo_commit, full_dataset)
    manifest["selection"] = {
        "label_filter": args.label,
        "max_per_source": args.max_per_source,
        "all_normalized_counts": dict(all_counts),
        "selected_counts": dict(selected_counts),
        "selected_sample_ids_sha256": hashlib.sha256("\n".join(sorted(r["sample_id"] for r in selected)).encode()).hexdigest(),
    }

    print("WAInjectBench paired defense experiment")
    print(f"Normalized dataset : {DATA_PATH}")
    print(f"Available samples  : {len(rows)} ({dict(all_counts)})")
    print(f"Selected samples   : {len(selected)} ({dict(selected_counts)})")
    print(f"Conditions         : {', '.join(conditions)}")
    print(f"Repeats            : {args.repeats}")
    print(f"Planned model calls: {len(schedule)}")
    print(f"Mock/development   : {args.development_only}")
    print(f"Batch ID           : {batch_id}")
    if args.dry_run:
        for job in schedule[:25]:
            print(f"{job['order_index']:04d} {job['experiment_type']:14s} {job['condition_id']:22s} "
                  f"{job['sample_id']} repeat={job['repeat_index']} source={job['source_file']}")
        if len(schedule) > 25:
            print(f"... {len(schedule) - 25} more jobs")
        print("DRY RUN: no API calls, target writes, logs, or manifest created.")
        return 0

    if args.development_only:
        if not settings.mock_llm:
            parser.error("--development-only requires MOCK_LLM=true")
        if args.repeats != 1:
            parser.error("--development-only requires --repeats 1")
    elif settings.mock_llm:
        parser.error("MOCK_LLM=true is not research evidence. Use --development-only for a mock-only check.")
    else:
        if settings.llm_model != "gpt-6-luna":
            parser.error("This experiment requires LLM_MODEL=gpt-6-luna. Update your .env before research runs.")
        if settings.llm_api_mode != "responses":
            parser.error("This experiment requires LLM_API_MODE=responses for the GPT-6 Luna Responses API.")

    errors = settings.validate(require_credentials=not settings.mock_llm)
    if errors:
        parser.error("Invalid model configuration: " + " ".join(errors))
    try:
        check_local_target()
    except Exception as exc:
        parser.error(str(exc))

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    manifest_dir = LOG_DIR / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{batch_id}.json"
    manifest["development_only"] = args.development_only
    manifest["mock_run_not_for_research"] = args.development_only
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    by_id = {r["sample_id"]: r for r in selected}
    failed = 0
    for job in schedule:
        row = by_id[job["sample_id"]]
        metadata = {
            "defense_batch_id": batch_id,
            "defense_protocol_version": PROTOCOL_VERSION,
            "schedule_seed": args.seed,
            "schedule_order_index": job["order_index"],
            "planned_job_count": len(schedule),
            "repeat_index": job["repeat_index"],
            "experiment_type": job["experiment_type"],
            "source_dataset": "WAInjectBench",
            "source_label": row["source_label"],
            "source_file": row["source_file"],
            "source_file_stem": row["source_file_stem"],
            "sample_id": row["sample_id"],
            "content_sha256": row["content_sha256"],
            "dataset_version": f"WAInjectBench-text:{repo_commit or 'commit_not_recorded'}",
            "development_only": args.development_only,
        }
        print(f"[{job['order_index']}/{len(schedule)}] {job['experiment_type']} | "
              f"{job['condition_id']} | {row['sample_id']} | repeat {job['repeat_index']}", flush=True)
        try:
            if row["source_label"] == "malicious":
                adapted_case = {
                    "payload": row["content"],
                    "provenance": {"source_attack_ids": [row["sample_id"]]},
                    "test_case_id": row["sample_id"],
                    "test_name": row["source_file_stem"],
                    "category_code": row["source_file_stem"],
                    "attack_intent_id": "WAInjectBench:" + row["source_file_stem"],
                    "prompt_framing": {},
                    "obfuscation": {},
                    "matched_pair": None,
                }
                run_attack_once(adapted_case, job["repeat_index"], defense_condition=job["condition_id"],
                                log_dir=LOG_DIR, experiment_metadata=metadata)
            else:
                fixture = {
                    "fixture_id": row["sample_id"],
                    "fixture_name": row["source_file_stem"],
                    "fixture_group": row["source_file_stem"],
                    "content_type": "WAInjectBench text benign sample",
                    "content": row["content"],
                    "expected_tool": "security_check",
                    "expected_url_path": "/page",
                }
                run_benign_once(fixture, job["repeat_index"], batch_id, job["order_index"], args.seed,
                                allow_mock=args.development_only, defense_condition=job["condition_id"],
                                log_dir=LOG_DIR, experiment_metadata=metadata)
        except Exception as exc:
            failed += 1
            print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

    manifest["execution_failures"] = failed
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nBatch finished: {failed} failed of {len(schedule)} scheduled jobs.")
    print(f"Batch ID: {batch_id}")
    print("Next: python -m scanner.defense_analysis --batch-id " + batch_id)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
