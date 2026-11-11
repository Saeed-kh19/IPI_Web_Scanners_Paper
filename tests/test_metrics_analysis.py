import unittest
import tempfile
from pathlib import Path

from scanner.metrics_analysis import (
    analyze_records,
    holm_adjust,
    mcnemar_exact_p,
    wilson_interval,
)


CONDITIONS = ["NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"]


def make_manifest():
    schedule = []
    order = 1
    for condition in CONDITIONS:
        for case_id, category in [("TC-A", "BHV"), ("TC-B", "SEC"), ("TC-C", "TOOL")]:
            for repeat in (1, 2, 3):
                schedule.append({
                    "order_index": order,
                    "experiment_type": "attack",
                    "condition_id": condition,
                    "test_case_id": case_id,
                    "category_code": category,
                    "repeat_index": repeat,
                })
                order += 1
        for fixture_id in ("BNC-1", "BNC-2"):
            for repeat in (1, 2, 3):
                schedule.append({
                    "order_index": order,
                    "experiment_type": "benign_utility",
                    "condition_id": condition,
                    "fixture_id": fixture_id,
                    "repeat_index": repeat,
                })
                order += 1
    return {
        "schedule": schedule,
        "randomization_seed": 20261105,
        "defense_protocol_version": "1.0.0",
        "repetitions_per_case_per_condition": 3,
        "attack_case_count": 3,
        "benign_fixture_count": 2,
        "planned_total_model_calls": len(schedule),
        "model_configuration": {"requested_model_id": "test-model"},
    }


def make_classified_rows(manifest):
    rows = []
    by_key = {}
    for job in manifest["schedule"]:
        if job["experiment_type"] != "attack":
            continue
        cond = job["condition_id"]
        case = job["test_case_id"]
        rep = job["repeat_index"]
        # No-defense: TC-A is majority success via S2; TC-C has S3+S4 overlap.
        # D1: only TC-C is majority success. D2: all three are negative.
        positive = (
            (cond == "NO_DEFENSE" and case in {"TC-A", "TC-C"})
            or (cond == "INSTRUCTION_GUIDANCE" and case == "TC-C")
        )
        s2 = positive and case == "TC-A"
        s3 = positive and case == "TC-C"
        s4 = s3 and rep == 2
        row = {
            "run_id": f"{cond}-{case}-{rep}",
            "test_case_id": case,
            "category_code": next(x["category_code"] for x in manifest["schedule"] if x.get("test_case_id") == case),
            "condition_id": cond,
            "repeat_index": str(rep),
            "schedule_order_index": str(job["order_index"]),
            "mock_run_not_for_research": "False",
            "run_complete": "True",
            "payload_present_in_llm_input": "True",
            "classification_status": "CLASSIFIED_COMPLETE",
            "s1_decision_influence": "False",
            "s0_no_observed_outcome": str(not positive),
            "s2_unexpected_tool_request": str(s2),
            "s3_unexpected_tool_invocation": str(s3),
            "s4_synthetic_marker_in_model_output": str(s4),
            "policy_blocked_unexpected_request": str(s2),
            "impact_level_0_to_4": "3" if s3 else ("2" if s2 else "0"),
        }
        rows.append(row)
    return rows


def make_defense_rows(manifest):
    rows = []
    for job in manifest["schedule"]:
        if job["experiment_type"] != "benign_utility":
            continue
        successful = job["condition_id"] != "STRUCTURED_BOUNDARY" or job["fixture_id"] == "BNC-1"
        rows.append({
            "experiment_type": "benign_utility",
            "condition_id": job["condition_id"],
            "fixture_id": job["fixture_id"],
            "repeat_index": str(job["repeat_index"]),
            "schedule_order_index": str(job["order_index"]),
            "mock_run_not_for_research": "False",
            "failed": "False",
            "baseline_utility_success": str(successful),
        })
    return rows


class MetricsAnalysisTests(unittest.TestCase):
    def _analyze(self, batch_id, manifest, classified_rows, defense_rows):
        with tempfile.TemporaryDirectory() as tmpdir:
            return analyze_records(
                batch_id, manifest, classified_rows, defense_rows,
                annotation_agreement={"raw_binary_agreement": 0.9, "cohens_kappa_s1_binary": 0.8},
                bootstrap_iterations=200,
                output_dir=Path(tmpdir),
            )

    def test_wilson_interval(self):
        low, high = wilson_interval(5, 10)
        self.assertLess(low, 0.5)
        self.assertGreater(high, 0.5)

    def test_mcnemar_exact(self):
        self.assertEqual(mcnemar_exact_p(0, 0), 1.0)
        self.assertEqual(mcnemar_exact_p(5, 0), 0.0625)
        self.assertEqual(mcnemar_exact_p(4, 4), 1.0)

    def test_holm_adjustment_is_monotone_and_bounded(self):
        adjusted = holm_adjust([0.01, 0.04, 0.03])
        self.assertEqual(adjusted, [0.03, 0.06, 0.06])

    def test_analyze_records_uses_case_level_majority_and_union(self):
        manifest = make_manifest()
        report = self._analyze("test-batch", manifest, make_classified_rows(manifest), make_defense_rows(manifest))
        no_defense = next(x for x in report["condition_summaries"] if x["condition_id"] == "NO_DEFENSE")
        self.assertEqual(no_defense["ASR_primary_majority_attack_ids_success"], 2)
        self.assertEqual(no_defense["ASR_primary_majority_attack_ids_total"], 3)
        self.assertEqual(no_defense["S3_attack_ids_majority"], 1)
        self.assertEqual(no_defense["S4_attack_ids_majority"], 0)
        # D0 vs D2 produces two control-only successful cases and no treatment-only cases.
        paired = next(x for x in report["paired_attack_comparisons"]
                      if x["control_condition"] == "NO_DEFENSE" and x["treatment_condition"] == "STRUCTURED_BOUNDARY")
        self.assertEqual(paired["control_positive_treatment_negative"], 2)
        self.assertEqual(paired["control_negative_treatment_positive"], 0)
        self.assertEqual(report["missing_schedule_jobs"], [])

    def test_incomplete_repeat_set_excluded_without_imputing_failure(self):
        manifest = make_manifest()
        rows = make_classified_rows(manifest)
        # Remove one repeat for TC-A in D0.
        rows = [r for r in rows if not (r["condition_id"] == "NO_DEFENSE" and r["test_case_id"] == "TC-A" and r["repeat_index"] == "3")]
        report = self._analyze("missing", manifest, rows, make_defense_rows(manifest))
        no_defense = next(x for x in report["condition_summaries"] if x["condition_id"] == "NO_DEFENSE")
        self.assertEqual(no_defense["ASR_primary_majority_attack_ids_total"], 2)
        self.assertEqual(len(report["missing_schedule_jobs"]), 1)

    def test_unresolved_s1_is_not_assumed_negative_when_machine_flags_are_negative(self):
        manifest = make_manifest()
        rows = make_classified_rows(manifest)
        # TC-B/D0: two known negative repeats and one unresolved S1; majority is
        # still determinably negative, without imputing the unknown repeat.
        target = next(r for r in rows if r["condition_id"] == "NO_DEFENSE" and r["test_case_id"] == "TC-B" and r["repeat_index"] == "3")
        target["s1_decision_influence"] = ""
        target["classification_status"] = "ADJUDICATION_REQUIRED"
        report = self._analyze("unknown-s1-negative", manifest, rows, make_defense_rows(manifest))
        d0 = next(x for x in report["condition_summaries"] if x["condition_id"] == "NO_DEFENSE")
        self.assertEqual(d0["ASR_primary_majority_attack_ids_total"], 3)
        self.assertEqual(report["input_counts"]["classification_status_counts"]["ADJUDICATION_REQUIRED"], 1)

    def test_unresolved_s1_with_positive_machine_evidence_is_definite_success(self):
        manifest = make_manifest()
        rows = make_classified_rows(manifest)
        # Make all three TC-A/D0 runs S1-unresolved. Two S2-positive repeats
        # force a successful majority; unresolved S1 is not required to count it.
        target_rows = [r for r in rows if r["condition_id"] == "NO_DEFENSE" and r["test_case_id"] == "TC-A"]
        for row in target_rows:
            row["s1_decision_influence"] = ""
            row["classification_status"] = "ADJUDICATION_REQUIRED"
        report = self._analyze("unknown-s1-positive", manifest, rows, make_defense_rows(manifest))
        d0 = next(x for x in report["condition_summaries"] if x["condition_id"] == "NO_DEFENSE")
        self.assertEqual(d0["ASR_primary_majority_attack_ids_success"], 2)
        self.assertEqual(d0["ASR_primary_majority_attack_ids_total"], 3)

    def test_overlapping_flags_are_counted_as_union_not_sum(self):
        manifest = make_manifest()
        rows = make_classified_rows(manifest)
        # TC-C has S3 and one S4-positive repeat; attack-ID majority S3 is true,
        # while the per-run S4 appears once and does not become a majority flag.
        report = self._analyze("overlap", manifest, rows, make_defense_rows(manifest))
        no_defense = next(x for x in report["condition_summaries"] if x["condition_id"] == "NO_DEFENSE")
        self.assertEqual(no_defense["ASR_primary_majority_attack_ids_success"], 2)


if __name__ == "__main__":
    unittest.main()
