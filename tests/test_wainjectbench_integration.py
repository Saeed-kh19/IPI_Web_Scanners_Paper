import json
from pathlib import Path

from scripts.import_wainjectbench import load_records
from scanner.run_wainjectbench_experiment import build_schedule, select_records


def test_importer_preserves_benign_malicious_and_duplicates(tmp_path: Path):
    root = tmp_path / "text"
    (root / "malicious").mkdir(parents=True)
    (root / "benign").mkdir(parents=True)
    (root / "malicious" / "VPI.jsonl").write_text(
        json.dumps({"text": "injected text"}) + "\n" + json.dumps({"content": "injected text"}) + "\n",
        encoding="utf-8",
    )
    (root / "benign" / "web.jsonl").write_text(json.dumps({"text": "ordinary text"}) + "\n", encoding="utf-8")
    rows, report = load_records(root)
    assert len(rows) == 3
    assert report["records_by_label"] == {"malicious": 2, "benign": 1}
    assert sum(row["exact_text_duplicate"] for row in rows) == 2
    assert len({row["sample_id"] for row in rows}) == 3


def test_selection_is_repeatable_and_schedule_paired():
    rows = [
        {"sample_id": f"M{i}", "source_label": "malicious", "source_file": "malicious/a.jsonl", "source_file_stem": "a"}
        for i in range(5)
    ] + [
        {"sample_id": f"B{i}", "source_label": "benign", "source_file": "benign/b.jsonl", "source_file_stem": "b"}
        for i in range(4)
    ]
    a = select_records(rows, "all", 2, 7)
    b = select_records(rows, "all", 2, 7)
    assert [x["sample_id"] for x in a] == [x["sample_id"] for x in b]
    assert len(a) == 4
    schedule = build_schedule(a, 2, 7, ["NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"])
    assert len(schedule) == 24
    assert len({x["order_index"] for x in schedule}) == 24
    assert {x["condition_id"] for x in schedule} == {"NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"}
    assert {x["experiment_type"] for x in schedule} == {"attack", "benign_utility"}
