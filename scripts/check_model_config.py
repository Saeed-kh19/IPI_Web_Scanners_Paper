#!/usr/bin/env python3
"""Inspect model configuration or make one non-scanning live API preflight.

Examples:
  python scripts/check_model_config.py
  python scripts/check_model_config.py --live

The live check sends one small synthetic request, does not crawl the target,
never executes tools, and should not be mixed with experiment runs.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.config import settings  # noqa: E402
from scanner.llm_agent import LLMAgent  # noqa: E402


def make_agent() -> LLMAgent:
    return LLMAgent(
        api_key=settings.llm_api_key,
        model=settings.llm_model,
        mock=settings.mock_llm,
        base_url=settings.llm_base_url,
        ipi_defense=False,
        api_mode=settings.llm_api_mode,
        reasoning_effort=settings.llm_reasoning_effort,
        max_output_tokens=settings.llm_max_output_tokens,
        api_timeout=settings.llm_api_timeout,
        max_retries=settings.llm_max_retries,
        provider_name=settings.llm_provider_name,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the configured LLM provider and model.")
    parser.add_argument("--live", action="store_true", help="Send one real model request (may incur API cost).")
    args = parser.parse_args()

    errors = settings.validate(require_credentials=args.live and not settings.mock_llm)
    report = settings.public_metadata()
    report["configuration_errors"] = errors
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if errors:
        return 2

    if not args.live:
        print("\nConfiguration-only check passed. No API request was sent.")
        print("Run with --live to verify provider access and the model's structured-output response.")
        return 0

    if settings.mock_llm:
        print("ERROR: MOCK_LLM=true. Disable mock mode before a live preflight.", file=sys.stderr)
        return 2

    agent = make_agent()
    preflight_context = {
        "scan_goal": "This is a model-configuration preflight, not a scan. There is no target and no page content. Return no tool request.",
        "pages": [],
        "policy": {"same_origin_only": True, "allowed_methods": ["GET", "POST"]},
        "trusted_workflow": {"required_action": "none", "target": "none"},
        "laboratory_context": {},
    }
    raw, tool_request = agent.decide(preflight_context)
    print("\nLive preflight result:")
    print(json.dumps({
        "raw_decision": json.loads(raw),
        "tool_request_proposed": None if tool_request is None else {
            "name": tool_request.name,
            "arguments": tool_request.arguments,
        },
        "model_metadata": agent.last_response_metadata,
        "tools_executed": False,
    }, ensure_ascii=False, indent=2))
    if tool_request is not None:
        print("WARNING: The model proposed a tool during an empty-context preflight. No tool was executed.", file=sys.stderr)
        return 1
    print("\nLive model/API preflight passed. This was not an experimental run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
