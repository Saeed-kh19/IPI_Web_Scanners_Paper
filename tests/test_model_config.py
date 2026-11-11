"""Offline checks for Revision 2 model decision formatting."""
import json
import unittest
from types import SimpleNamespace

from scanner.llm_agent import DECISION_SCHEMA, LLMAgent


class MockWorkflowTests(unittest.TestCase):
    def test_mock_prefers_explicit_trusted_workflow_target(self):
        agent = LLMAgent(api_key=None, model=None, mock=True)
        context = {
            "pages": [{"url": "http://127.0.0.1:8000/"}],
            "trusted_workflow": {"required_action": "security_check", "target": "http://127.0.0.1:8000/page"},
        }
        raw, request = agent.decide(context)
        self.assertEqual(request.name, "security_check")
        self.assertEqual(request.arguments["url"], "http://127.0.0.1:8000/page")
        self.assertIn("not a research result", raw)


class DecisionNormalizationTests(unittest.TestCase):
    def test_security_check_normalization(self):
        raw = json.dumps({
            "decision": "check_headers",
            "selected_tool": "security_check",
            "arguments": {"url": "http://127.0.0.1:8000/page", "method": "", "params_json": ""},
            "rationale": "Expected workflow.",
        })
        _, request = LLMAgent._normalize_decision(raw)
        self.assertEqual(request.name, "security_check")
        self.assertEqual(request.arguments, {"url": "http://127.0.0.1:8000/page"})

    def test_request_normalization(self):
        raw = json.dumps({
            "decision": "inspect_page",
            "selected_tool": "request",
            "arguments": {"url": "http://127.0.0.1:8000/page", "method": "GET", "params_json": "{\"sample\": \"1\"}"},
            "rationale": "Test request.",
        })
        _, request = LLMAgent._normalize_decision(raw)
        self.assertEqual(request.arguments["method"], "GET")
        self.assertEqual(request.arguments["params"], {"sample": "1"})

    def test_no_tool_request(self):
        raw = json.dumps({
            "decision": "no_action",
            "selected_tool": None,
            "arguments": {"url": "", "method": "", "params_json": ""},
            "rationale": "No page context.",
        })
        _, request = LLMAgent._normalize_decision(raw)
        self.assertIsNone(request)

    def test_invalid_tool_rejected(self):
        raw = json.dumps({
            "decision": "run_shell",
            "selected_tool": "shell",
            "arguments": {"url": "http://127.0.0.1:8000/page", "method": "", "params_json": ""},
            "rationale": "Not allowed.",
        })
        with self.assertRaises(ValueError):
            LLMAgent._normalize_decision(raw)

    def test_schema_requires_all_decision_fields(self):
        self.assertEqual(
            set(DECISION_SCHEMA["required"]),
            set(DECISION_SCHEMA["properties"]),
        )
        self.assertFalse(DECISION_SCHEMA["additionalProperties"])


class APIRequestShapeTests(unittest.TestCase):
    def _agent(self, mode="responses"):
        agent = LLMAgent.__new__(LLMAgent)
        agent.mock = False
        agent.model = "gpt-6-luna"
        agent.api_mode = mode
        agent.reasoning_effort = "low"
        agent.max_output_tokens = 1200
        agent.provider_name = "OpenAI API"
        agent.defense_condition = "NO_DEFENSE"
        agent.system_prompt = "test system prompt"
        agent.sdk_version = "test-sdk"
        agent.last_response_metadata = {}
        return agent

    def test_responses_api_uses_strict_schema_without_temperature(self):
        decision = {
            "decision": "no_action",
            "selected_tool": None,
            "arguments": {"url": "", "method": "", "params_json": ""},
            "rationale": "Preflight has no page context.",
        }
        class FakeResponses:
            def __init__(self):
                self.kwargs = None
            def create(self, **kwargs):
                self.kwargs = kwargs
                return SimpleNamespace(
                    output_text=json.dumps(decision), model="gpt-6-luna",
                    id="resp_test", status="completed", usage=None,
                )
        fake = FakeResponses()
        agent = self._agent("responses")
        agent.client = SimpleNamespace(responses=fake)
        raw, request = agent.decide({"pages": []})
        self.assertIsNone(request)
        self.assertEqual(json.loads(raw)["selected_tool"], None)
        self.assertEqual(fake.kwargs["reasoning"], {"effort": "low"})
        self.assertEqual(fake.kwargs["text"]["format"]["type"], "json_schema")
        self.assertTrue(fake.kwargs["text"]["format"]["strict"])
        self.assertNotIn("temperature", fake.kwargs)
        self.assertNotIn("top_p", fake.kwargs)
        self.assertEqual(agent.last_response_metadata["response_model_id"], "gpt-6-luna")
        self.assertEqual(agent.last_response_metadata["openai_sdk_version"], "test-sdk")

    def test_chat_completions_fallback_omits_temperature(self):
        decision = {
            "decision": "no_action",
            "selected_tool": None,
            "arguments": {"url": "", "method": "", "params_json": ""},
            "rationale": "No page context.",
        }
        class FakeCompletions:
            def __init__(self):
                self.kwargs = None
            def create(self, **kwargs):
                self.kwargs = kwargs
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(decision)), finish_reason="stop")],
                    model="gpt-6-luna", id="chatcmpl_test", usage=None,
                )
        fake = FakeCompletions()
        agent = self._agent("chat_completions")
        agent.client = SimpleNamespace(chat=SimpleNamespace(completions=fake))
        _, request = agent.decide({"pages": []})
        self.assertIsNone(request)
        self.assertEqual(fake.kwargs["reasoning_effort"], "low")
        self.assertEqual(fake.kwargs["response_format"], {"type": "json_object"})
        self.assertNotIn("temperature", fake.kwargs)
        self.assertNotIn("top_p", fake.kwargs)
        self.assertEqual(agent.last_response_metadata["api_mode"], "chat_completions")


if __name__ == "__main__":
    unittest.main(verbosity=2)
