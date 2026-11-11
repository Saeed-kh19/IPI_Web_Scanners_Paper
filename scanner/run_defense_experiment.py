#!/usr/bin/env python3
"""Run the full paired Revision 4 defense evaluation.

Primary design: all 348 attack cases and all 30 benign utility fixtures are
run under each of three defense conditions, with three within-case repeats.
The complete schedule is randomized and persisted before the first API call.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .config import settings
from .defense_protocol import (
    DEFAULT_REPEATS, DEFAULT_SEED, DEFENSE_CONDITION_ORDER, build_schedule, make_manifest
)
from .run_attack import load_dataset, load_attack, run_once as run_attack_once
from .run_baseline import load_corpus, run_once as run_benign_once

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs" / "defense_experiment"


def check_local_target() -> None:
    parts = urlsplit(settings.target_base_url)
    if parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Defense experiments are restricted to a loopback target (127.0.0.1, localhost, or ::1).")
    for path in ("/health", "/page"):
        response = requests.get(settings.target_base_url + path, timeout=settings.request_timeout)
        if response.status_code != 200:
            raise RuntimeError(f"Local target preflight failed for {path}: HTTP {response.status_code}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the paired, full-corpus Revision 4 defense evaluation")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--dry-run", action="store_true", help="Print the full schedule without API calls or target writes")
    parser.add_argument("--development-only", action="store_true", help="Run a tiny mock-only integration subset; never research evidence")
    parser.add_argument("--allow-mock", action="store_true", help="Required only with --development-only")
    parser.add_argument("--attack-id", help="Canonical or retained legacy attack ID for development-only mode")
    parser.add_argument("--fixture-id", help="Benign fixture ID for development-only mode")
    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
    dataset = load_dataset()
    baseline_corpus = load_corpus()
    attack_cases = list(dataset["test_cases"])
    fixtures = list(baseline_corpus["fixtures"])

    if args.development_only:
        if not (args.allow_mock and settings.mock_llm):
            parser.error("--development-only requires MOCK_LLM=true and --allow-mock")
        if not args.attack_id or not args.fixture_id:
            parser.error("--development-only requires both --attack-id and --fixture-id")
        attack_cases = [load_attack(args.attack_id)]
        fixtures = [next((x for x in fixtures if x["fixture_id"] == args.fixture_id), None)]
        if fixtures[0] is None:
            parser.error(f"Unknown benign fixture ID: {args.fixture_id}")
        if args.repeats != 1:
            parser.error("Development-only mode requires --repeats 1")
    else:
        if settings.mock_llm:
            parser.error("MOCK_LLM=true is not research evidence. Use --development-only for mock integration checks.")
        if args.allow_mock:
            parser.error("--allow-mock is accepted only with --development-only")

    schedule = build_schedule(attack_cases, fixtures, args.repeats, args.seed)
    batch_id = str(uuid.uuid4())
    model_metadata = settings.public_metadata()
    model_metadata["default_defense_condition"] = "PER_JOB_CONDITION_OVERRIDE"
    manifest = make_manifest(dataset, baseline_corpus, schedule, batch_id, args.seed, args.repeats, model_metadata)
    manifest["is_full_primary_corpus"] = len(attack_cases) == len(dataset["test_cases"]) and len(fixtures) == len(baseline_corpus["fixtures"]) and not args.development_only
    manifest["development_only"] = args.development_only
    manifest["created_at_local_note"] = "UTC timestamps are authoritative for reproducibility."

    print("Revision 4 paired defense experiment")
    print(f"Attack cases: {len(attack_cases)}")
    print(f"Benign utility fixtures: {len(fixtures)}")
    print(f"Conditions: {', '.join(DEFENSE_CONDITION_ORDER)}")
    print(f"Repeats per case/condition: {args.repeats}")
    print(f"Attack calls: {len(attack_cases) * args.repeats * len(DEFENSE_CONDITION_ORDER)}")
    print(f"Benign utility calls: {len(fixtures) * args.repeats * len(DEFENSE_CONDITION_ORDER)}")
    print(f"Total planned calls: {len(schedule)}")
    print(f"Seed: {args.seed}")
    print(f"Batch ID: {batch_id}")

    if args.dry_run:
        for job in schedule[:30]:
            print(f"{job['order_index']:04d}. {job['experiment_type']} | {job['condition_id']} | "
                  f"{job.get('test_case_id', job.get('fixture_id'))} | repeat={job['repeat_index']}")
        if len(schedule) > 30:
            print(f"... {len(schedule) - 30} additional scheduled runs")
        print("DRY RUN ONLY: no API calls, target writes, logs, or manifests were created.")
        return 0

    errors = settings.validate(require_credentials=True)
    if errors:
        parser.error("Invalid model configuration: " + " ".join(errors))
    try:
        check_local_target()
    except Exception as exc:
        parser.error(str(exc))

    if args.development_only:
        manifest["mock_run_not_for_research"] = True
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    manifest_dir = LOG_DIR / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{batch_id}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    failed = 0
    for job in schedule:
        identity = job.get("test_case_id", job.get("fixture_id"))
        metadata = {
            "defense_batch_id": batch_id,
            "defense_protocol_version": manifest["defense_protocol_version"],
            "schedule_seed": args.seed,
            "schedule_order_index": job["order_index"],
            "planned_job_count": len(schedule),
            "development_only": args.development_only,
            "experiment_type": job["experiment_type"],
            "planned_repetitions_per_fixture": args.repeats,
            "planned_repetitions_per_case_condition": args.repeats,
        }
        print(f"\n[{job['order_index']}/{len(schedule)}] {job['experiment_type']} | {job['condition_id']} | {identity} | repeat {job['repeat_index']}")
        try:
            if job["experiment_type"] == "attack":
                record = next(x for x in attack_cases if x["test_case_id"] == job["test_case_id"])
                run_attack_once(
                    record, job["repeat_index"], defense_condition=job["condition_id"],
                    log_dir=LOG_DIR, experiment_metadata=metadata,
                )
            else:
                fixture = next(x for x in fixtures if x["fixture_id"] == job["fixture_id"])
                run_benign_once(
                    fixture, job["repeat_index"], batch_id, job["order_index"], args.seed,
                    allow_mock=args.development_only, defense_condition=job["condition_id"],
                    log_dir=LOG_DIR, experiment_metadata=metadata,
                )
        except Exception as exc:
            failed += 1
            print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)

    manifest["execution_failures"] = failed
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nBatch finished: {failed} failed jobs out of {len(schedule)}.")
    print("Analyze with: python -m scanner.defense_analysis --batch-id " + batch_id)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
