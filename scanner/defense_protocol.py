"""Pre-specified paired defense-evaluation protocol (Revision 4)."""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timezone
from typing import Any
from pathlib import Path

from .llm_agent import (
    BASE_SYSTEM_PROMPT, DEFENSE_CONDITIONS, INSTRUCTION_GUIDANCE_ADDON, STRUCTURED_BOUNDARY_ADDON
)

ROOT = Path(__file__).resolve().parents[1]
DEFENSE_PROTOCOL_VERSION = "1.0.0"
DEFENSE_CONDITION_ORDER = ["NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"]
DEFAULT_REPEATS = 3
DEFAULT_SEED = 20261105


def stable_sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_schedule(attack_cases: list[dict], fixtures: list[dict], repeats: int, seed: int) -> list[dict]:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    jobs: list[dict] = []
    for condition_id in DEFENSE_CONDITION_ORDER:
        for case in attack_cases:
            for repeat_index in range(1, repeats + 1):
                jobs.append({
                    "experiment_type": "attack",
                    "condition_id": condition_id,
                    "test_case_id": case["test_case_id"],
                    "category_code": case["category_code"],
                    "repeat_index": repeat_index,
                })
        for fixture in fixtures:
            for repeat_index in range(1, repeats + 1):
                jobs.append({
                    "experiment_type": "benign_utility",
                    "condition_id": condition_id,
                    "fixture_id": fixture["fixture_id"],
                    "repeat_index": repeat_index,
                })
    random.Random(seed).shuffle(jobs)
    for order_index, job in enumerate(jobs, start=1):
        job["order_index"] = order_index
    return jobs


def make_manifest(dataset: dict, baseline_corpus: dict, schedule: list[dict], batch_id: str, seed: int, repeats: int, model_metadata: dict) -> dict:
    attack_count = len(dataset["test_cases"])
    fixture_count = len(baseline_corpus["fixtures"])
    per_condition = {
        cid: {"attack_runs": attack_count * repeats, "benign_utility_runs": fixture_count * repeats}
        for cid in DEFENSE_CONDITION_ORDER
    }
    prompt_texts = {
        "NO_DEFENSE": BASE_SYSTEM_PROMPT,
        "INSTRUCTION_GUIDANCE": BASE_SYSTEM_PROMPT + "\n" + INSTRUCTION_GUIDANCE_ADDON,
        "STRUCTURED_BOUNDARY": BASE_SYSTEM_PROMPT + "\n" + INSTRUCTION_GUIDANCE_ADDON + "\n" + STRUCTURED_BOUNDARY_ADDON,
    }
    prompt_hashes = {
        condition: hashlib.sha256(text.encode("utf-8")).hexdigest()
        for condition, text in prompt_texts.items()
    }
    fixed_component_paths = [
        "scanner/policy.py", "scanner/tools.py", "scanner/crawler.py", "target/app.py"
    ]
    fixed_component_hashes = {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in fixed_component_paths
    }
    return {
        "experiment_type": "paired_defense_evaluation",
        "defense_protocol_version": DEFENSE_PROTOCOL_VERSION,
        "batch_id": batch_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "randomization_seed": seed,
        "randomization_method": "Python random.Random(seed).shuffle over the complete condition × case × repeat schedule",
        "repetitions_per_case_per_condition": repeats,
        "primary_attack_unit": "test_case_id; repeat observations nested within case and paired across conditions",
        "benign_utility_unit": "fixture_id; repeat observations nested within fixture and paired across conditions",
        "defense_conditions": {cid: DEFENSE_CONDITIONS[cid] for cid in DEFENSE_CONDITION_ORDER},
        "system_prompt_sha256_by_condition": prompt_hashes,
        "fixed_component_sha256": fixed_component_hashes,
        "attack_dataset_version": dataset.get("dataset_version"),
        "attack_dataset_sha256": stable_sha256(dataset),
        "attack_case_count": attack_count,
        "baseline_protocol_version": baseline_corpus.get("protocol_version"),
        "baseline_corpus_sha256": stable_sha256(baseline_corpus),
        "benign_fixture_count": fixture_count,
        "planned_attack_calls": attack_count * repeats * len(DEFENSE_CONDITION_ORDER),
        "planned_benign_utility_calls": fixture_count * repeats * len(DEFENSE_CONDITION_ORDER),
        "planned_total_model_calls": len(schedule),
        "planned_runs_by_condition": per_condition,
        "model_configuration": model_metadata,
        "analysis_status": "descriptive operational outcomes only; S0-S4 and inferential analysis are deferred to later revisions",
        "schedule": schedule,
    }
