import json
from pathlib import Path
from datetime import datetime, timezone

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "api_key", "password", "token", "secret"}

def redact(obj):
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj

def write_event(log_dir: str, run_id: str, event: str, payload: dict):
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "event": event,
        "payload": redact(payload),
    }
    path = Path(log_dir) / f"{run_id}.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
