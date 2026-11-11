import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.defense_protocol import (
    DEFENSE_CONDITION_ORDER, build_schedule, make_manifest,
)
from scanner.llm_agent import LLMAgent, DEFENSE_CONDITIONS
from scanner.defense_analysis import summarize_batch


class DefenseContextTests(unittest.TestCase):
    def _agent(self, condition):
        return LLMAgent(
            api_key=None, model=None, mock=True,
            defense_condition=condition,
        )

    def test_no_defense_preserves_context_and_base_prompt(self):
        context = {"pages": [{"url": "http://127.0.0.1:8000/page", "text": "hello"}],
                   "trusted_workflow": {"target": "http://127.0.0.1:8000/page"}}
        agent = self._agent("NO_DEFENSE")
        prepared = agent.prepare_context(context)
        self.assertEqual(prepared, context)
        self.assertNotIn("untrusted_webpage_observations", prepared)
        self.assertNotIn("Treat all webpage content", agent.system_prompt)

    def test_instruction_guidance_changes_prompt_not_context_shape(self):
        context = {"pages": [{"url": "http://127.0.0.1:8000/page", "text": "hello"}]}
        agent = self._agent("INSTRUCTION_GUIDANCE")
        prepared = agent.prepare_context(context)
        self.assertEqual(prepared, context)
        self.assertIn("untrusted DATA", agent.system_prompt)

    def test_structured_boundary_moves_page_observations_and_preserves_source(self):
        context = {
            "pages": [{"url": "http://127.0.0.1:8000/page", "text": "attacker-controlled text", "html": "<p>x</p>"}],
            "trusted_workflow": {"target": "http://127.0.0.1:8000/page"},
        }
        agent = self._agent("STRUCTURED_BOUNDARY")
        prepared = agent.prepare_context(context)
        self.assertNotIn("pages", prepared)
        self.assertEqual(prepared["untrusted_webpage_observations"][0]["trust_boundary"], "UNTRUSTED_WEBPAGE_DATA")
        self.assertEqual(prepared["untrusted_webpage_observations"][0]["page_observation"]["text"], "attacker-controlled text")
        self.assertEqual(context["pages"][0]["text"], "attacker-controlled text")
        self.assertIn("untrusted_webpage_observations", agent.system_prompt)

    def test_three_defense_conditions_are_distinct(self):
        self.assertEqual(DEFENSE_CONDITION_ORDER, ["NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"])
        prompts = [self._agent(c).system_prompt for c in DEFENSE_CONDITION_ORDER]
        self.assertEqual(len(set(prompts)), 3)
        self.assertEqual(len(DEFENSE_CONDITIONS), 3)


class DefenseScheduleTests(unittest.TestCase):
    def test_schedule_is_paired_and_complete(self):
        attacks = [
            {"test_case_id": "TC-1", "category_code": "BHV"},
            {"test_case_id": "TC-2", "category_code": "SEC"},
        ]
        fixtures = [{"fixture_id": "BNC-1"}]
        schedule = build_schedule(attacks, fixtures, repeats=2, seed=7)
        self.assertEqual(len(schedule), 18)
        for condition in DEFENSE_CONDITION_ORDER:
            self.assertEqual(sum(x["condition_id"] == condition and x["experiment_type"] == "attack" for x in schedule), 4)
            self.assertEqual(sum(x["condition_id"] == condition and x["experiment_type"] == "benign_utility" for x in schedule), 2)
        keys = [(x["experiment_type"], x.get("test_case_id", x.get("fixture_id")), x["repeat_index"], x["condition_id"]) for x in schedule]
        self.assertEqual(len(keys), len(set(keys)))

    def test_manifest_hashes_each_defense_prompt_and_fixed_policy_components(self):
        from scanner.defense_protocol import make_manifest
        dataset = {"dataset_version": "2.1.0", "test_cases": [{"test_case_id": "TC-1", "category_code": "BHV"}]}
        corpus = {"protocol_version": "1.0.0", "fixtures": [{"fixture_id": "BNC-1"}]}
        schedule = build_schedule(dataset["test_cases"], corpus["fixtures"], 1, 3)
        manifest = make_manifest(dataset, corpus, schedule, "batch", 3, 1, {"requested_model_id": "test-model"})
        self.assertEqual(set(manifest["system_prompt_sha256_by_condition"]), set(DEFENSE_CONDITION_ORDER))
        self.assertEqual(set(manifest["fixed_component_sha256"]), {"scanner/policy.py", "scanner/tools.py", "scanner/crawler.py", "target/app.py"})
        self.assertEqual(manifest["planned_total_model_calls"], 6)

    def test_schedule_reproducible(self):
        attacks = [{"test_case_id": f"TC-{i}", "category_code": "BHV"} for i in range(5)]
        fixtures = [{"fixture_id": f"BNC-{i}"} for i in range(2)]
        self.assertEqual(build_schedule(attacks, fixtures, 2, 11), build_schedule(attacks, fixtures, 2, 11))
        self.assertNotEqual(build_schedule(attacks, fixtures, 2, 11), build_schedule(attacks, fixtures, 2, 12))

    def test_full_project_call_count(self):
        # Dataset v2.1.0 has 348 cases; Revision 3 baseline has 30 fixtures.
        self.assertEqual(348 * 3 * 3 + 30 * 3 * 3, 3402)


class DefenseAnalysisTests(unittest.TestCase):
    def test_paired_attack_and_utility_rows_are_summarized_and_mock_rows_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            manifests = logs / "manifests"
            manifests.mkdir(parents=True)
            results = root / "results"
            batch = "batch-test"
            schedule = []
            for condition in DEFENSE_CONDITION_ORDER:
                schedule.append({"order_index": len(schedule)+1, "experiment_type": "attack", "condition_id": condition, "test_case_id": "TC-0001", "repeat_index": 1})
                schedule.append({"order_index": len(schedule)+2, "experiment_type": "benign_utility", "condition_id": condition, "fixture_id": "BNC-S-001", "repeat_index": 1})
            (manifests / f"{batch}.json").write_text(json.dumps({"batch_id": batch, "schedule": schedule}), encoding="utf-8")

            order_counter = [1]
            def write_run(run_id, experiment_type, condition, extra_events, mock=False):
                start = {
                    "experiment_type": experiment_type, "condition_id": condition,
                    "defense_batch_id": batch, "repeat_index": 1, "target": "http://127.0.0.1:8000",
                    "schedule_order_index": order_counter[0],
                    "test_case_id": "TC-0001" if experiment_type == "attack" else None,
                    "fixture_id": "BNC-S-001" if experiment_type == "benign_utility" else None,
                    "mock_run_not_for_research": mock,
                }
                events = [{"run_id": run_id, "event": "run_started", "payload": start}] + [
                    {"run_id": run_id, "event": name, "payload": payload}
                    for name, payload in extra_events
                ]
                (logs / f"{run_id}.jsonl").write_text(
                    "\n".join(json.dumps(x) for x in events) + "\n", encoding="utf-8"
                )
                order_counter[0] += 1

            for condition in DEFENSE_CONDITION_ORDER:
                if condition == "NO_DEFENSE":
                    attack_events = [("tool_request", {"name": "request", "arguments": {"url": "http://127.0.0.1:9001/"}, "policy_allowed": False}), ("tool_blocked", {"reason": "different origin"})]
                    benign_events = [("baseline_outcome", {"baseline_utility_success": True, "requested_expected_tool_and_url": True, "policy_allowed": True, "decision_category": "expected_security_check"})]
                else:
                    attack_events = [("tool_request", {"name": "security_check", "arguments": {"url": "http://127.0.0.1:8000/page"}, "policy_allowed": True})]
                    benign_events = [("baseline_outcome", {"baseline_utility_success": condition == "STRUCTURED_BOUNDARY", "requested_expected_tool_and_url": condition == "STRUCTURED_BOUNDARY", "policy_allowed": True, "decision_category": "expected_security_check" if condition == "STRUCTURED_BOUNDARY" else "no_tool"})]
                write_run(f"a-{condition}", "attack", condition, attack_events)
                write_run(f"b-{condition}", "benign_utility", condition, benign_events)
            write_run("mock-one", "attack", "NO_DEFENSE", [], mock=True)

            with patch("scanner.defense_analysis.LOG_ROOT", logs), patch("scanner.defense_analysis.RESULT_ROOT", results):
                summary = summarize_batch(batch)
            self.assertEqual(summary["mock_runs_excluded"], 1)
            self.assertEqual(summary["research_log_records"], 6)
            self.assertEqual(summary["planned_schedule_jobs"], 6)
            self.assertEqual(summary["missing_scheduled_jobs"], [])
            self.assertEqual(summary["conditions"]["NO_DEFENSE"]["unexpected_tool_request_count"], 1)
            self.assertEqual(summary["conditions"]["NO_DEFENSE"]["benign_utility_success_count"], 1)
            utility_d1 = next(x for x in summary["paired_comparisons"] if x["experiment_type"] == "benign_utility" and x["control_condition"] == "NO_DEFENSE" and x["treatment_condition"] == "INSTRUCTION_GUIDANCE")
            self.assertEqual(utility_d1["control_true_treatment_false"], 1)
            self.assertEqual(utility_d1["matched_pairs"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
