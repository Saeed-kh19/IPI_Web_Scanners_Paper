# Revision 4 change log

**Revision:** 4.0.0  
**Base:** Revision 3 integrated project ZIP  
**Status:** Implementation and offline validation completed; no live model experiments performed.

## Added
- `scanner/defense_protocol.py`: three-condition defense taxonomy, full paired schedule, hashes, and manifest generator.
- `scanner/run_defense_experiment.py`: one sequential runner for attack and benign-utility jobs under all three conditions.
- `scanner/defense_analysis.py`: descriptive operational-event summaries and paired transitions; intentionally does not assign S0–S4 or calculate ASR.
- `tests/test_defense_protocol.py`: defense prompt/context and schedule tests.
- `docs/defense-protocol.md`: complete experiment protocol.
- `docs/paper_revision4_defense_protocol.md`: proposed paper replacement text.

## Modified
- `scanner/llm_agent.py`: explicit defense conditions; structured boundary context preparation.
- `scanner/config.py`: `DEFENSE_CONDITION` and legacy `IPI_DEFENSE` compatibility.
- `scanner/run_attack.py`: per-run defense-condition override, centralized logging, condition metadata, and actual model-input hashing.
- `scanner/run_baseline.py`: per-run defense-condition support and logging directory override.
- `scanner/run_many_baselines.py`: refuses a non-NO_DEFENSE default condition; directs paired evaluation to Revision 4 runner.
- `.env.example`, README, research overview, and reproduction documentation.

## Primary protocol
- D0 `NO_DEFENSE`: standard prompt and original context representation.
- D1 `INSTRUCTION_GUIDANCE`: existing system-level untrusted-content instruction.
- D2 `STRUCTURED_BOUNDARY`: D1 plus a separately labelled `untrusted_webpage_observations` object.
- 348 attack cases × 3 repeats × 3 conditions = 3,132 attack calls.
- 30 benign fixtures × 3 repeats × 3 conditions = 270 benign-utility calls.
- Total: 3,402 planned calls.
- One fixed-seed randomized schedule; paired by case/fixture ID and repeat index.
- SHA-256 hashes of each system prompt and the fixed policy, tools, crawler, and target modules are stored in the manifest.
- The analyzer checks scheduled versus observed order indices and reports missing, unexpected, and duplicate jobs.

## Methodological qualifications
- D1 vs D2 is an incremental comparison; D2 is not structural labelling in isolation.
- The local policy validator and tool allowlist are unchanged across conditions.
- Revision 4 reports operational counts only. S0–S4 and final ASR are deferred to Revision 5/6.
- Mock runs are excluded from research summaries.
- Historical 41-case success-selected defense results are not used as general defense-effectiveness estimates.

## Validation
- Offline unit tests: see final run output in the Revision 4 handoff.
- Python compilation, full schedule dry run, small mock-only integration, log provenance, input-boundary transformation, and mock-exclusion checks performed.
- No live API calls or research runs performed.
