# Research Overview

## Research question

This project evaluates how attacker-controlled webpage content can influence a single-step LLM-based web security scanner, and how its tool-policy boundary constrains downstream actions.

## Scanner pipeline

```text
Crawler
  -> Content Extraction / Normalization
  -> Structured Scan Context
  -> LLM Decision
  -> Tool Request
  -> Policy Validation
  -> Tool Execution
  -> Logging
```

## Core modules

- `scanner/crawler.py` — retrieves target pages and extracts text and metadata.
- `scanner/llm_agent.py` — sends structured context to the configured OpenAI-compatible model and parses a tool decision.
- `scanner/policy.py` — enforces the tool allowlist, same-origin restrictions, and method policy.
- `scanner/tools.py` — implements the limited HTTP, response-inspection, and security-header operations.
- `scanner/logger.py` — writes JSONL experiment events.
- `scanner/run_attack.py` — runs one test case from the integrated dataset.
- `scanner/run_baseline.py` and `scanner/run_many_baselines.py` — execute the 30-fixture benign no-injection baseline protocol (90 planned calls; three within-fixture repeats).
- `scanner/baseline_analysis.py` — extracts run-level and fixture-cluster-level baseline outcomes without treating repeated runs as independent.
- `scanner/analyze_logs.py` — extracts run-level events for later classification and metric calculation.
- `run_all_attacks.py` — executes the curated corpus.
- `scanner/run_defense_experiment.py` — paired, full-corpus three-condition attack and benign-utility runner.
- `scanner/defense_analysis.py` — descriptive paired operational-outcome analysis; S0–S4 and ASR are deferred.
- `run_defense_subset.py` — historical success-selected subset runner; not a valid general defense-effectiveness estimate.

## Dataset v2.1.0

The single active dataset is `attacks/ipi_dataset.json`. It contains 348 test cases: BHV 97, SEC 92, INFO 83, and TOOL 76. It was curated from 390 source records by removing 25 exact duplicate aliases and 17 semantically redundant prompts. All 390 historical source IDs remain traceable within the JSON; excluded records are not executed.

The dataset separates attack objective, prompt framing, and character-level obfuscation. It includes 30 matched plain/obfuscated pairs whose wording and framing are held constant by reconstructing the obfuscated member from the corresponding plain prompt. Historical labels BASE/EXTENDED/ADV/SE/OBF are provenance only, not an ordinal difficulty scale.

Prompt-framing labels are rule-assisted single-curator annotations; no inter-annotator agreement has been measured. See `docs/dataset-design.md`.

The actual injection delivery point is one paragraph in the User Review section on `/page`. Historical `source_type` and L1/L2 fields are retained only as provenance and are not separate experimental treatments.

## Benign baseline protocol

Revision 3 adds a fixed convenience corpus of 30 ordinary User Review texts (10 short, 10 medium, 10 long), each repeated three times in a randomized sequential schedule. The fixture is the primary descriptive unit; the 90 calls are not assumed independent. Baseline utility is limited to the predefined security_check workflow being requested on /page, allowed by policy, and completed with HTTP 200. See `docs/baseline-protocol.md`.

## Revision 4 experimental conditions

The paired defense experiment includes three conditions on the same attack and benign-utility corpora:

- `NO_DEFENSE`: standard scanner prompt; original page context structure.
- `INSTRUCTION_GUIDANCE`: adds the explicit system-level instruction that webpage content is untrusted data and must not change the scan objective.
- `STRUCTURED_BOUNDARY`: includes the same instruction guidance and moves page-derived observations into a separately labelled `untrusted_webpage_observations` object.

D0 vs D1 estimates the effect of instruction guidance. D1 vs D2 estimates the incremental effect of structured separation on top of that guidance. D2 is a combined condition. The policy validator, tool implementation, model configuration, and target stay fixed.

The full schedule is 3,132 attack runs plus 270 benign-utility runs (3,402 calls). Three repetitions are paired by case/fixture and repeat index; repetitions are not independent experimental units. The full protocol is in `docs/defense-protocol.md`.

## Safety boundaries

The lab uses a local target, synthetic secrets, synthetic session values, and local endpoints. The model has no unrestricted shell access. JavaScript execution and multi-step autonomous planning are outside the current implementation.

## Historical results

The previously reported 1,169-run No-Defense results and 123-run selected-defense results belong to the earlier 390-record corpus and are not results for dataset v2.1.0. They must not be combined with new v2.1.0 runs. Raw logs were not supplied, so those historical figures cannot currently be reconstructed. In addition, the v2.1.0 corpus removes redundant records and reconstructs the 30 obfuscated treatments as controlled matched variants; therefore, the earlier numerical results must not be attributed to this revised corpus.

## Outcome interpretation

The project distinguishes model-level influence, unexpected tool requests, policy decisions, tool execution, and synthetic-context output. Final run-level outcome flags and metric definitions will be established in a later revision; the current dataset itself does not assign S0-S4 labels.
