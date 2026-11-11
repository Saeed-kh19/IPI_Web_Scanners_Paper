import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "attacks" / "ipi_dataset.json"
DEFAULT_REPEAT = 3


def main():
    parser = argparse.ArgumentParser(description="Run the curated integrated IPI test corpus")
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, help="Repetitions per test case (default: 3)")
    parser.add_argument("--category", choices=["BHV", "SEC", "INFO", "TOOL"], help="Run only one attack category")
    parser.add_argument("--dry-run", action="store_true", help="List planned test cases without contacting the LLM")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if not DATASET.exists():
        print(f"[ERROR] Dataset not found: {DATASET}")
        sys.exit(1)
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    if data.get("dataset_version") != "2.1.0":
        raise SystemExit("This runner requires dataset version 2.1.0")
    cases = data["test_cases"]
    if args.category:
        cases = [x for x in cases if x["category_code"] == args.category]
    print("IPI scanner evaluation plan")
    print(f"Dataset      : {DATASET}")
    print(f"Version      : {data['dataset_version']}")
    print(f"Test cases   : {len(cases)}")
    print(f"Repetitions  : {args.repeat}")
    print(f"Planned runs : {len(cases) * args.repeat}")
    print("=" * 72)
    if args.dry_run:
        for i, case in enumerate(cases, 1):
            pair = case.get("matched_pair") or {}
            pair_label = f" | {pair.get('pair_id')} ({pair.get('role')})" if pair else ""
            print(f"[{i:03d}] {case['test_case_id']} | {case['category_code']} | {case['test_name']}{pair_label}")
        return
    failed = []
    for index, case in enumerate(cases, 1):
        print(f"\n[{index}/{len(cases)}] {case['test_case_id']} | {case['test_name']}")
        result = subprocess.run([sys.executable, "-m", "scanner.run_attack", case["test_case_id"], "--repeat", str(args.repeat)], cwd=ROOT)
        if result.returncode != 0:
            print(f"  --> FAILED (exit code {result.returncode})")
            failed.append(case["test_case_id"])
        else:
            print("  --> OK")
    print("\n" + "=" * 72)
    print(f"Finished. Failed: {len(failed)} / {len(cases)}")
    if failed:
        print("Failed test_case_id values:")
        for item in failed:
            print(f"  - {item}")
        sys.exit(1)


if __name__ == "__main__":
    main()
