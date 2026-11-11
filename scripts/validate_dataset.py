#!/usr/bin/env python3
"""Validate the integrated IPI dataset v2.1.0 using only the JSON file."""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "attacks" / "ipi_dataset.json"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main():
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    assert data["dataset_version"] == "2.1.0"
    cases = data["test_cases"]
    assert len(cases) == data["dataset_statistics"]["final_test_case_count"] == 348
    ids = [x["test_case_id"] for x in cases]
    assert len(ids) == len(set(ids)), "Duplicate test_case_id"
    payloads = [x["payload"] for x in cases]
    assert len(payloads) == len(set(payloads)), "Duplicate active payload text"
    counts = Counter(x["category_code"] for x in cases)
    assert counts == Counter({"BHV": 97, "SEC": 92, "INFO": 83, "TOOL": 76}), counts

    all_source_ids = []
    by_id = {x["test_case_id"]: x for x in cases}
    framing_taxonomy = data["prompt_framing_taxonomy"]["framing_devices"]
    obf_taxonomy = data["obfuscation_taxonomy"]
    for case in cases:
        assert case["payload"].strip()
        assert case["provenance"]["payload_sha256"] == sha(case["payload"])
        framing = case["prompt_framing"]
        assert isinstance(framing["instruction_forms"], list)
        assert set(framing["framing_devices"]).issubset(framing_taxonomy)
        assert all("device" in cue and "matched_text_normalized" in cue for cue in framing["matched_cues"])
        assert isinstance(framing["instruction_form_cues"], list)
        assert {cue["form"] for cue in framing["instruction_form_cues"]} == set(framing["instruction_forms"])
        assert framing["framing_status"] == ("explicit_cue_detected" if framing["framing_devices"] else "no_explicit_cue_detected")
        assert {cue["device"] for cue in framing["matched_cues"]} == set(framing["framing_devices"])
        obf = case["obfuscation"]
        assert set(obf["technique_codes"]).issubset(obf_taxonomy)
        assert obf["applied"] == bool(obf["technique_codes"])
        all_source_ids.extend(case["provenance"].get("source_attack_ids", []))
        pair = case.get("matched_pair")
        if pair:
            assert pair["partner_test_case_id"] in by_id
            other = by_id[pair["partner_test_case_id"]]
            assert other["matched_pair"]["pair_id"] == pair["pair_id"]
            assert other["matched_pair"]["partner_test_case_id"] == case["test_case_id"]

    assert len(all_source_ids) == 390, f"Expected all 390 legacy IDs to be traceable, got {len(all_source_ids)}"
    assert len(all_source_ids) == len(set(all_source_ids)), "A legacy source ID appears in more than one active case"
    pairs = data["matched_pair_design"]["pairs"]
    assert len(pairs) == 30
    assert len({p["pair_id"] for p in pairs}) == 30, "Matched-pair IDs must be unique"
    for pair in pairs:
        plain = by_id[pair["plain_control_test_case_id"]]
        obf = by_id[pair["obfuscated_test_case_id"]]
        assert plain["matched_pair"]["role"] == "plain_control"
        assert obf["matched_pair"]["role"] == "obfuscated_treatment"
        assert obf["provenance"]["matched_parent_payload_sha256"] == plain["provenance"]["payload_sha256"]
        assert obf["obfuscation"]["technique_codes"] == pair["obfuscation_methods"]
        assert plain["prompt_framing"]["framing_devices"] == obf["prompt_framing"]["framing_devices"]
        assert plain["prompt_framing"]["instruction_forms"] == obf["prompt_framing"]["instruction_forms"]

    excluded = data["excluded_source_records"]
    assert len(excluded) == 42
    assert data["dataset_statistics"]["near_duplicate_candidates_reviewed"] == 28
    assert data["dataset_statistics"]["near_duplicate_semantic_pairs_consolidated_from_screen"] == 4
    assert data["similarity_screen"]["non_matched_pairs_screened"] == 60348
    assert data["similarity_screen"]["remaining_candidates_above_threshold"] == 0
    assert data["dataset_statistics"]["exact_payload_aliases_removed"] == 25
    assert data["dataset_statistics"]["semantic_redundant_records_removed"] == 17
    print("Dataset validation: PASS")
    print(f"Dataset version: {data['dataset_version']}")
    print(f"Active test cases: {len(cases)}")
    print(f"Category counts: {dict(counts)}")
    print(f"Matched plain/obfuscated pairs: {len(pairs)}")
    print(f"Exact duplicate aliases removed: {data['dataset_statistics']['exact_payload_aliases_removed']}")
    print(f"Semantic redundancies removed: {data['dataset_statistics']['semantic_redundant_records_removed']}")
    print(f"Legacy source IDs traceable: {len(all_source_ids)}")


if __name__ == "__main__":
    main()
