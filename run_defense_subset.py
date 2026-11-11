#!/usr/bin/env python3
"""
LEGACY REPRODUCTION ONLY: run the old success-selected attack subset.
This is not the Revision 4 primary defense evaluation and must not be used
to estimate general defense effectiveness. Use scanner.run_defense_experiment.

Usage:
    set PYTHONPATH=.
    set IPI_DEFENSE=true
    python run_defense_subset.py

Optional:
    python run_defense_subset.py --ids-file successful_ids.txt
    python run_defense_subset.py --repeat 3
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "attacks" / "ipi_dataset.json"
DEFAULT_REPEAT = 3

# High-priority attacks selected from the No-Defense evaluation.
PRIORITY_SUCCESSFUL_IDS = [
    # Security-Test Manipulation
    "IPI-SEC-001",
    "IPI-SEC-EXTENDED-001",
    "IPI-SEC-EXTENDED-012",
    "IPI-SEC-ADV-005",
    "IPI-SEC-ADV-011",
    "IPI-SEC-ADV-025",
    "IPI-SEC-ADV-027",
    "IPI-SEC-ADV-039",
    "IPI-SEC-ADV-041",
    "IPI-SEC-SE-004",
    "IPI-SEC-SE-007",
    "IPI-SEC-SE-009",
    "IPI-SEC-SE-018",
    "IPI-SEC-SE-019",
    "IPI-SEC-SE-021",
    "IPI-SEC-SE-025",
    "IPI-SEC-OBF-003",

    # Unauthorized Tool / Network Action
    "IPI-TOOL-ADV-002",
    "IPI-TOOL-ADV-019",
    "IPI-TOOL-ADV-020",
    "IPI-TOOL-SE-001",
    "IPI-TOOL-SE-003",
    "IPI-TOOL-SE-006",
    "IPI-TOOL-SE-008",
    "IPI-TOOL-SE-012",
    "IPI-TOOL-SE-016",
    "IPI-TOOL-SE-017",
    "IPI-TOOL-SE-020",
    "IPI-TOOL-OBF-001",
    "IPI-TOOL-OBF-004",
    "IPI-TOOL-OBF-006",
    "IPI-TOOL-OBF-007",

    # Information Disclosure
    "IPI-INFO-ADV-013",
    "IPI-INFO-ADV-033",
    "IPI-INFO-SE-004",
    "IPI-INFO-SE-017",
    "IPI-INFO-SE-019",

    # Behavioral Manipulation
    "IPI-BHV-SE-010",
    "IPI-BHV-SE-013",
    "IPI-BHV-SE-020",
    "IPI-BHV-OBF-005",
]


def load_ids_from_file(path: Path) -> list[str]:
    ids = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ids.append(line)
    return ids


def main():
    parser = argparse.ArgumentParser(description="LEGACY ONLY: reproduce the historical success-selected defense subset; not a valid general defense estimate")
    parser.add_argument("--ids-file", type=str, default=None,
                        help="Text file with one attack_id per line (overrides built-in priority list)")
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT,
                        help=f"Number of repetitions per attack (default: {DEFAULT_REPEAT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only print the list of attacks that would be executed")
    args = parser.parse_args()

    # Select the attack IDs to run.
    if args.ids_file:
        attack_ids = load_ids_from_file(Path(args.ids_file))
        print(f"Loaded {len(attack_ids)} attack IDs from {args.ids_file}")
    else:
        attack_ids = PRIORITY_SUCCESSFUL_IDS
        print(f"Using built-in high-priority list ({len(attack_ids)} attacks)")

    # Check that every selected ID exists in the dataset.
    if not DATASET.exists():
        print(f"[ERROR] Dataset not found: {DATASET}")
        sys.exit(1)

    with open(DATASET, encoding="utf-8") as f:
        data = json.load(f)
    records_by_id = {a["test_case_id"]: a for a in data["test_cases"]}
    legacy_to_case = {}
    for record in data["test_cases"]:
        for old_id in record["provenance"].get("source_attack_ids", []):
            legacy_to_case[old_id] = record["test_case_id"]
    resolved = []
    missing = []
    for old_id in attack_ids:
        case_id = legacy_to_case.get(old_id)
        if case_id is None:
            missing.append(old_id)
        elif case_id not in resolved:
            resolved.append(case_id)
    if missing:
        print(f"[WARNING] {len(missing)} historical IDs have no active one-to-one test case:")
        for item in missing:
            print(f"  - {item}")
    attack_ids = resolved

    condition_label = "Instruction-based untrusted-content guidance"
    print(f"\nExperimental condition: {condition_label}")
    print(f"  IPI_DEFENSE env  : {os.getenv('IPI_DEFENSE', '(not set)')}")
    print(f"  Unique curated cases to run: {len(attack_ids)}")
    print(f"  Repeats each     : {args.repeat}")
    print(f"  Total runs       : {len(attack_ids) * args.repeat}")
    print("=" * 50)

    if args.dry_run:
        print("\n[DRY-RUN] Attacks that would be executed:")
        for aid in attack_ids:
            record = records_by_id[aid]
            print(f"  {record.get('test_case_id')} | {record.get('test_name')} | {record['provenance'].get('source_attack_ids', [])}")
        return

    # Warn when the defense flag is disabled.
    if os.getenv("IPI_DEFENSE", "false").lower() != "true":
        print("\n[WARNING] IPI_DEFENSE is not set to 'true'.")
        print("          Set it before running, e.g.:")
        print("              set IPI_DEFENSE=true")
        print("          Continuing anyway in 5 seconds...")
        import time
        time.sleep(5)

    failed = []
    for i, aid in enumerate(attack_ids, 1):
        record = records_by_id[aid]
        print(f"\n[{i}/{len(attack_ids)}] {record.get('test_case_id')} | {record.get('test_name')} | {aid}")
        result = subprocess.run(
            [sys.executable, "-m", "scanner.run_attack", record["test_case_id"], "--repeat", str(args.repeat)],
            cwd=ROOT,
        )
        if result.returncode != 0:
            print(f"  --> FAILED (exit {result.returncode})")
            failed.append(aid)
        else:
            print(f"  --> OK")

    print("\n" + "=" * 50)
    print(f"Finished. Failed: {len(failed)} / {len(attack_ids)}")
    if failed:
        print("Failed IDs:")
        for fid in failed:
            print(f"  - {fid}")


if __name__ == "__main__":
    main()