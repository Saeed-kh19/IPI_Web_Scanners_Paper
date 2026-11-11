"""Render one JSON object per run using Revision 1 research names.

Usage:
  python -m scanner.analyze_logs              # all logs
  python -m scanner.analyze_logs TC-0004       # canonical test_case_id
  python -m scanner.analyze_logs IPI-SEC-001  # legacy attack_id

This is a legacy extraction utility. Use scanner.outcome_classification for
the versioned S0-S4 evidence protocol; final aggregate metrics are handled in
the later metrics revision.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
identifier_filter = sys.argv[1] if len(sys.argv) > 1 else None

TOOL_DISPLAY_NAMES = {
    "request": "HTTP request",
    "inspect_response": "HTTP response metadata inspection",
    "security_check": "Security-header presence check",
}

rows = []
for path in sorted(LOG_DIR.glob("*.jsonl")):
    try:
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError):
        continue
    if not events:
        continue

    start = next((event.get("payload", {}) for event in events if event.get("event") == "run_started"), {})
    legacy_attack_id = start.get("attack_id")
    test_case_id = start.get("test_case_id")
    source_attack_ids = start.get("source_attack_ids", [legacy_attack_id])
    if identifier_filter and identifier_filter not in set(source_attack_ids) | {legacy_attack_id, test_case_id}:
        continue

    output = next((event.get("payload", {}) for event in events if event.get("event") == "llm_output"), {})
    request = next((event.get("payload", {}) for event in events if event.get("event") == "tool_request"), None)
    executed = next((event.get("payload", {}) for event in events if event.get("event") == "tool_executed"), None)
    blocked = next((event.get("payload", {}) for event in events if event.get("event") == "tool_blocked"), None)
    requested_tool = request.get("name") if request else None

    rows.append({
        "run_id": start.get("run_id", path.stem),
        "test_case_id": test_case_id,
        "test_name": start.get("test_name"),
        "legacy_attack_id": legacy_attack_id,
        "source_attack_ids": source_attack_ids,
        "category_code": start.get("category_code"),
        "attack_intent_id": start.get("attack_intent_id"),
        "prompt_framing": start.get("prompt_framing"),
        "obfuscation": start.get("obfuscation"),
        "matched_pair": start.get("matched_pair"),
        "dataset_version": start.get("dataset_version"),
        "repetition_index": start.get("repeat"),
        "condition_id": start.get("condition_id"),
        "condition_label": start.get("condition_label"),
        "ipi_defense_enabled_legacy_flag": start.get("ipi_defense"),
        "tool_requested": request is not None,
        "requested_tool": requested_tool,
        "requested_tool_label": TOOL_DISPLAY_NAMES.get(requested_tool),
        "tool_executed": executed is not None,
        "tool_blocked_by_policy": blocked is not None,
        "llm_raw_output": output.get("raw_output", ""),
    })

for row in rows:
    print(json.dumps(row, ensure_ascii=False))
