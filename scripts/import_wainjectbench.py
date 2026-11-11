#!/usr/bin/env python3
"""Import WAInjectBench text JSONL into a stable, auditable project format.

Expected source layout: <data_dir>/{benign,malicious}/**/*.jsonl
The source corpus is preserved; exact duplicate text is flagged, never removed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def infer_label(path: Path) -> str:
    parts = {part.lower() for part in path.parts}
    if "malicious" in parts:
        return "malicious"
    if "benign" in parts:
        return "benign"
    raise ValueError(f"Cannot infer benign/malicious label from path: {path}")


def get_text(record: dict[str, Any], path: Path, line_number: int) -> str:
    value = record.get("text")
    if value is None:
        value = record.get("content")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing non-empty 'text'/'content' in {path}:{line_number}")
    return value


def repository_commit(data_dir: Path) -> str | None:
    # data_dir is normally <repo>/data/text; walk up to find the git root.
    for candidate in [data_dir, *data_dir.parents]:
        if (candidate / ".git").exists():
            try:
                result = subprocess.run(
                    ["git", "-C", str(candidate), "rev-parse", "HEAD"],
                    capture_output=True, text=True, check=True,
                )
                return result.stdout.strip()
            except (OSError, subprocess.CalledProcessError):
                return None
    return None


def load_records(data_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not data_dir.exists():
        raise FileNotFoundError(data_dir)
    files = sorted(data_dir.rglob("*.jsonl"))
    if not files:
        raise FileNotFoundError(f"No .jsonl files found under {data_dir}")

    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    by_file: Counter[str] = Counter()
    errors: list[dict[str, Any]] = []
    text_hashes: Counter[str] = Counter()

    for file_path in files:
        relative = file_path.relative_to(data_dir).as_posix()
        try:
            label = infer_label(Path(relative))
        except ValueError:
            # Ignore non-label JSONL files rather than importing training/config files.
            continue
        with file_path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError("JSONL row must be an object")
                    content = get_text(raw, Path(relative), line_number)
                except Exception as exc:
                    errors.append({"source_file": relative, "source_line": line_number, "error": str(exc)})
                    continue

                digest = sha256(content)
                stable_seed = f"{relative}\n{line_number}\n{digest}"
                sample_id = "WAI-" + hashlib.sha256(stable_seed.encode("utf-8")).hexdigest()[:16].upper()
                stem = Path(relative).stem
                metadata = {
                    key: value for key, value in raw.items()
                    if key not in {"text", "content"} and isinstance(value, (str, int, float, bool, type(None)))
                }
                rows.append({
                    "sample_id": sample_id,
                    "source_dataset": "WAInjectBench",
                    "source_label": label,
                    "label_value": 1 if label == "malicious" else 0,
                    "source_file": relative,
                    "source_file_stem": stem,
                    "source_line": line_number,
                    "modality": "text",
                    "content": content,
                    "content_sha256": digest,
                    "exact_text_duplicate": False,
                    "source_metadata": metadata,
                })
                counts[label] += 1
                by_file[f"{label}/{relative}"] += 1
                text_hashes[digest] += 1

    # Keep all records, but explicitly flag exact text duplicates.
    for row in rows:
        row["exact_text_duplicate"] = text_hashes[row["content_sha256"]] > 1

    if not rows:
        raise ValueError("No valid text samples were imported. Check the data directory and JSONL fields.")

    report = {
        "dataset": "WAInjectBench",
        "modality": "text",
        "source_data_dir": str(data_dir.resolve()),
        "repository_commit": repository_commit(data_dir),
        "total_records": len(rows),
        "records_by_label": dict(counts),
        "records_by_source_file": dict(sorted(by_file.items())),
        "unique_content_hashes": len(text_hashes),
        "exact_duplicate_records_included": sum(1 for row in rows if row["exact_text_duplicate"]),
        "normalization_errors": errors,
        "expected_paper_counts": {"malicious": 991, "benign": 2707},
        "count_check": {
            "matches_paper_counts": counts.get("malicious", 0) == 991 and counts.get("benign", 0) == 2707,
            "note": "A mismatch is reported, not silently corrected. Verify the selected release and import errors.",
        },
        "normalization_policy": "Preserve every valid text sample; do not deduplicate; retain source file, line, label, and content hash.",
    }
    return rows, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Import WAInjectBench text JSONL files")
    parser.add_argument("--data-dir", type=Path, required=True, help="WAInjectBench/data/text")
    parser.add_argument("--output", type=Path, default=Path("data/wainjectbench_text_normalized.jsonl"))
    parser.add_argument("--report", type=Path, default=Path("data/wainjectbench_import_report.json"))
    parser.add_argument("--strict-counts", action="store_true", help="Fail unless counts equal 991 malicious + 2707 benign")
    args = parser.parse_args()

    rows, report = load_records(args.data_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Imported records : {report['total_records']}")
    print(f"Malicious        : {report['records_by_label'].get('malicious', 0)}")
    print(f"Benign           : {report['records_by_label'].get('benign', 0)}")
    print(f"Exact duplicates : {report['exact_duplicate_records_included']} (retained)")
    print(f"Import errors    : {len(report['normalization_errors'])}")
    print(f"Commit           : {report['repository_commit'] or 'not detected'}")
    print(f"Output           : {args.output}")
    print(f"Report           : {args.report}")
    if report["normalization_errors"]:
        print("WARNING: Some malformed rows were skipped. Inspect the report before running.")
    if args.strict_counts and (
        not report["count_check"]["matches_paper_counts"]
        or report["normalization_errors"]
    ):
        print("ERROR: Import did not pass strict validation. Check the counts and normalization_errors in the report.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
