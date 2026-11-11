"""Execute the pre-specified Revision 3 benign baseline schedule.

Default: 30 benign content fixtures x 3 within-fixture repetitions = 90 calls.
The 30 fixture scenarios are the primary descriptive units; three repetitions
are clustered within fixture and are not treated as 90 independent samples.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from urllib.parse import urlsplit

import requests
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .run_baseline import LOG_DIR, load_corpus, run_once

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPEATS = 3
DEFAULT_SEED = 20261105


def build_schedule(fixtures: list[dict], repeats: int, seed: int) -> list[dict]:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    schedule = [
        {"fixture_id": fixture["fixture_id"], "repeat_index": repetition}
        for fixture in fixtures
        for repetition in range(1, repeats + 1)
    ]
    random.Random(seed).shuffle(schedule)
    for index, item in enumerate(schedule, start=1):
        item["order_index"] = index
    return schedule


def make_manifest(corpus: dict, schedule: list[dict], batch_id: str, seed: int, repeats: int) -> dict:
    corpus_text = json.dumps(corpus, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    corpus_hash = hashlib.sha256(corpus_text.encode("utf-8")).hexdigest()
    return {
        "experiment_type": "benign_baseline",
        "baseline_protocol_version": "1.0.0",
        "baseline_batch_id": batch_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "randomization_seed": seed,
        "randomization_method": "Python random.Random(seed).shuffle over fixture-by-repetition schedule",
        "fixture_count": len(corpus["fixtures"]),
        "repetitions_per_fixture": repeats,
        "planned_model_calls": len(schedule),
        "primary_unit": "fixture_id (benign content scenario)",
        "repetition_interpretation": "Repeated observations nested within fixture; not independent experimental units",
        "ipi_defense": False,
        "mock_llm": settings.mock_llm,
        "model_configuration": settings.public_metadata(),
        "baseline_corpus_sha256": corpus_hash,
        "baseline_corpus_version": corpus.get("protocol_version"),
        "dataset_version_context": "2.1.0",
        "schedule": schedule,
    }



def check_local_target() -> None:
    parts = urlsplit(settings.target_base_url)
    if parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Baseline protocol is restricted to a loopback target (127.0.0.1, localhost, or ::1).")
    for path in ("/health", "/page"):
        response = requests.get(settings.target_base_url + path, timeout=settings.request_timeout)
        if response.status_code != 200:
            raise RuntimeError(f"Target preflight failed for {path}: HTTP {response.status_code}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Revision 3 benign baseline corpus")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--dry-run", action="store_true", help="Print the schedule without model calls")
    parser.add_argument("--allow-mock", action="store_true", help="Allow MOCK_LLM for pipeline tests only; never use for research results")
    parser.add_argument("--fixture-id", help="Run only one fixture (development/smoke-test mode, not the primary baseline)")
    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
    if not args.dry_run:
        if settings.resolve_defense_condition() != "NO_DEFENSE":
            parser.error("Revision 3 standalone clean baseline requires DEFENSE_CONDITION=NO_DEFENSE; use the Revision 4 paired runner for all defense arms.")
        if settings.mock_llm and not args.allow_mock:
            parser.error("MOCK_LLM=true. Use --allow-mock only for pipeline testing; mock output is not research evidence.")
        errors = settings.validate(require_credentials=not settings.mock_llm)
        if errors:
            parser.error("Invalid model configuration: " + " ".join(errors))
        try:
            check_local_target()
        except Exception as exc:
            parser.error(f"Local target preflight failed: {exc}")

    corpus = load_corpus()
    fixtures = corpus["fixtures"]
    if args.fixture_id:
        fixtures = [x for x in fixtures if x["fixture_id"] == args.fixture_id]
        if not fixtures:
            parser.error(f"Unknown fixture ID: {args.fixture_id}")
    schedule = build_schedule(fixtures, args.repeats, args.seed)
    batch_id = str(uuid.uuid4())
    manifest = make_manifest(corpus, schedule, batch_id, args.seed, args.repeats)
    manifest["selected_fixture_ids"] = [x["fixture_id"] for x in fixtures]
    manifest["is_full_primary_corpus"] = len(fixtures) == len(corpus["fixtures"]) and not args.fixture_id
    manifest["development_subset"] = bool(args.fixture_id)

    print("Revision 3 benign baseline schedule")
    print(f"Protocol: {manifest['baseline_protocol_version']}")
    print(f"Fixtures: {len(fixtures)}")
    print(f"Repeats per fixture: {args.repeats}")
    print(f"Planned calls: {len(schedule)}")
    print(f"Randomization seed: {args.seed}")
    print(f"Batch ID: {batch_id}")
    print(f"Full primary corpus: {manifest['is_full_primary_corpus']}")
    if args.dry_run:
        for item in schedule:
            print(f"{item['order_index']:03d}. {item['fixture_id']} repeat={item['repeat_index']}")
        print("DRY RUN ONLY: no API calls, target writes, or logs were created.")
        return 0

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    manifest_dir = LOG_DIR / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{batch_id}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved pre-run manifest: {manifest_path}")

    fixture_by_id = {x["fixture_id"]: x for x in fixtures}
    failures = 0
    for item in schedule:
        fixture = fixture_by_id[item["fixture_id"]]
        print(f"\n=== BASELINE {item['order_index']}/{len(schedule)}: {fixture['fixture_id']} repeat {item['repeat_index']} ===")
        try:
            run_id = run_once(
                fixture=fixture,
                repeat=item["repeat_index"],
                batch_id=batch_id,
                order_index=item["order_index"],
                schedule_seed=args.seed,
                allow_mock=args.allow_mock,
            )
            print(f"Completed run_id={run_id}")
        except Exception as exc:  # keep later runs observable; failure is logged by run_once
            failures += 1
            print(f"FAILED fixture={fixture['fixture_id']} repeat={item['repeat_index']}: {type(exc).__name__}: {exc}", file=sys.stderr)

    manifest["execution_failures"] = failures
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nBaseline batch finished with {failures} failed attempts. Analyze with:")
    print(f"python -m scanner.baseline_analysis --batch-id {batch_id}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
