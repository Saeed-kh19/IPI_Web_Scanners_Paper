import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scanner.baseline_analysis import _read_run, summarize
from scanner.run_baseline import load_corpus
from scanner.run_many_baselines import build_schedule


class BaselineCorpusTests(unittest.TestCase):
    def test_corpus_has_30_unique_valid_hashed_fixtures(self):
        corpus = load_corpus()
        fixtures = corpus["fixtures"]
        self.assertEqual(len(fixtures), 30)
        self.assertEqual(len({x["fixture_id"] for x in fixtures}), 30)
        for fixture in fixtures:
            self.assertEqual(
                hashlib.sha256(fixture["content"].encode("utf-8")).hexdigest(),
                fixture["content_sha256"],
            )
        self.assertEqual(corpus["group_counts"], {"short": 10, "medium": 10, "long": 10})

    def test_baseline_fixtures_are_distinct(self):
        corpus = load_corpus()
        hashes = [x["content_sha256"] for x in corpus["fixtures"]]
        self.assertEqual(len(hashes), len(set(hashes)))


class BaselineScheduleTests(unittest.TestCase):
    def test_default_schedule_is_90_runs_and_three_per_fixture(self):
        fixtures = load_corpus()["fixtures"]
        schedule = build_schedule(fixtures, repeats=3, seed=20261105)
        self.assertEqual(len(schedule), 90)
        counts = {}
        for row in schedule:
            counts[row["fixture_id"]] = counts.get(row["fixture_id"], 0) + 1
        self.assertEqual(set(counts.values()), {3})
        self.assertEqual(sorted(x["order_index"] for x in schedule), list(range(1, 91)))

    def test_schedule_is_reproducible_for_same_seed(self):
        fixtures = load_corpus()["fixtures"]
        self.assertEqual(
            build_schedule(fixtures, 3, 1234),
            build_schedule(fixtures, 3, 1234),
        )
        self.assertNotEqual(
            build_schedule(fixtures, 3, 1234),
            build_schedule(fixtures, 3, 9876),
        )


class BaselineLogAnalysisTests(unittest.TestCase):
    def test_read_run_identifies_expected_action_and_success(self):
        events = [
            {"event": "run_started", "payload": {
                "experiment_type": "benign_baseline", "run_id": "r1", "baseline_batch_id": "b1",
                "fixture_id": "BNC-S-001", "fixture_group": "short", "expected_tool": "security_check",
                "expected_url": "http://127.0.0.1:8000/page", "repeat_index": 1,
                "model_configuration": {"provider_label": "test", "requested_model_id": "test-model"},
            }},
            {"event": "tool_request", "payload": {
                "name": "security_check", "arguments": {"url": "http://127.0.0.1:8000/page"},
                "policy_allowed": True,
            }},
            {"event": "tool_executed", "payload": {
                "name": "security_check", "result": {"status_code": 200},
            }},
            {"event": "run_finished", "payload": {"status": "completed"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r1.jsonl"
            path.write_text("\n".join(json.dumps(x) for x in events), encoding="utf-8")
            row = _read_run(path)
        self.assertTrue(row["baseline_utility_success"])
        self.assertEqual(row["decision_category"], "expected_security_check")

    def test_mock_rows_are_excluded_from_research_summary(self):
        rows = [{
            "fixture_id": "BNC-S-001",
            "fixture_group": "short",
            "repeat_index": 1,
            "decision_category": "expected_security_check",
            "tool_requested": True,
            "exact_expected_action": True,
            "policy_blocked": False,
            "tool_executed": True,
            "baseline_utility_success": True,
            "run_failed": False,
            "mock_run_not_for_research": True,
        }]
        summary, fixture_rows = summarize(rows, planned_repeats=1)
        self.assertEqual(summary["observed"]["research_run_count_excluding_mock"], 0)
        self.assertEqual(fixture_rows, [])

    def test_summary_counts_fixture_clusters_not_repeat_rows_as_primary_units(self):
        rows = []
        for fixture_id in ("BNC-S-001", "BNC-S-002"):
            for repeat in (1, 2, 3):
                rows.append({
                    "fixture_id": fixture_id,
                    "fixture_group": "short",
                    "repeat_index": repeat,
                    "decision_category": "expected_security_check",
                    "tool_requested": True,
                    "exact_expected_action": True,
                    "policy_blocked": False,
                    "tool_executed": True,
                    "baseline_utility_success": (repeat != 3),
                    "run_failed": False,
                    "mock_run_not_for_research": False,
                })
        summary, fixture_rows = summarize(rows, planned_repeats=3)
        self.assertEqual(summary["observed"]["research_run_count_excluding_mock"], 6)
        self.assertEqual(summary["observed"]["fixture_clusters_observed"], 2)
        self.assertEqual(summary["observed"]["complete_fixture_clusters"], 2)
        self.assertAlmostEqual(summary["observed"]["mean_fixture_success_fraction"], 2 / 3)
        self.assertEqual(len(fixture_rows), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
