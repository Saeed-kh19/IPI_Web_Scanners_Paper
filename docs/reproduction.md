# Reproduction

1. Create the Python environment and install `requirements.txt` as described in the root README.
2. Copy `.env.example` to `.env` and configure the primary GPT-6 Luna (`gpt-6-luna`) model/API settings locally. Do not commit credentials. See `docs/model-configuration.md`.
3. Run `python scripts/validate_dataset.py`.
4. Run `python run_all_attacks.py --dry-run` to verify that the intended 348-case corpus is selected without making API calls.
5. Start `target/run.py` and, when required, `target/network_service.py`.
6. Run `python scripts/check_model_config.py`; after credentials are configured, run `python scripts/check_model_config.py --live` once. This preflight is not a research run.
7. Execute one test (`python -m scanner.run_attack TC-0001 --repeat 1`) before any batch.
8. Preserve all JSONL logs and pre-run manifests. They include requested/returned model IDs, provider, API mode, reasoning effort, response ID/status, usage, SDK version, prompt hash, date, timeout, retry policy, and condition metadata. The request implementation omits `temperature` and `top_p`; use the reasoning-effort value recorded in the manifest/log.
9. Validate the Revision 3 baseline schedule with `python -m scanner.run_many_baselines --dry-run`. The real Revision 4 paired defense/benign-utility schedule may be run only after the Revision 5 classification protocol is frozen and the live model preflight succeeds.

The active attack dataset is the single file `attacks/ipi_dataset.json`. The runner must not load historical CSVs, crosswalks, or previous dataset versions. The benign baseline fixtures are a separate, self-contained corpus in `baseline/benign_baseline_corpus.json`; they represent no-injection control content rather than attack test cases.

## Revision 3 baseline execution (after Revision 5)

```bash
python -m scanner.run_many_baselines --repeats 3 --seed 20261105
python -m scanner.baseline_analysis --batch-id <BATCH_ID>
```

The first command schedules 30 fixture scenarios × 3 within-fixture repetitions = 90 model calls. The fixture is the primary unit (`n=30`); repeats are not independent observations. Keep the resolved defense condition at `NO_DEFENSE`, `MOCK_LLM=false`, and run the schedule sequentially. For the paired Revision 4 study, use the unified defense runner instead of separately running this clean-only baseline. See `docs/baseline-protocol.md` for the original protocol and `docs/defense-protocol.md` for the paired design.


## Revision 4 paired defense experiment

Use the integrated runner, not `run_defense_subset.py`, for primary defense evaluation. The runner applies all three conditions to every active attack case and benign utility fixture, with a single randomized schedule and pre-run manifest. It is sequential and must not be run concurrently with another process because the target content file is shared.

```bash
python -m scanner.run_defense_experiment --dry-run
```

The dry run should report 348 attack cases, 30 benign fixtures, three conditions, three repeats, 3,132 attack calls, 270 benign-utility calls, and 3,402 total calls. It must not write target content or logs.

For an offline pipeline check, start the local target, set `MOCK_LLM=true`, and run:

```bat
set MOCK_LLM=true
python -m scanner.run_defense_experiment --development-only --allow-mock --attack-id TC-0001 --fixture-id BNC-S-001 --repeats 1
```

This produces six mock runs and is not research evidence. The analyzer excludes them.

After the later protocol revisions and live model preflight, execute the full run:

```bat
set MOCK_LLM=false
python -m scanner.run_defense_experiment --repeats 3 --seed 20261105
```

Then analyze the printed batch ID:

```bash
python -m scanner.defense_analysis --batch-id <BATCH_ID>
```

Preserve the manifest, every JSONL file, and the generated CSV/JSON analysis. Do not edit the raw logs.


## Revision 5 outcome classification and S1 annotation

Run this only after a Revision 4 experiment batch has completed and its manifest and JSONL logs have been preserved.

Export machine-derived events and a blinded S1 annotation template:

```bash
python -m scanner.outcome_classification --batch-id <BATCH_ID> --export-annotations
```

Three key files are created under `results/outcome_classification/`:

- `<BATCH_ID>_machine_evidence.csv`: condition-visible, automatically extracted S2/S3/S4 evidence and run-validity fields.
- `<BATCH_ID>_s1_annotation_blinded.csv`: condition-blinded rows for two independent annotators.
- `<BATCH_ID>_annotation_key_PRIVATE.csv`: private mapping from annotation IDs to run IDs, cases, repetitions, and conditions. Never distribute this file to annotators.

Each annotator independently fills `s1_decision_influence` with `yes` or `no`, uses one of the documented `s1_subtype` values for a positive label, quotes the exact model-output evidence in `s1_evidence_excerpt`, and supplies an `annotator_id`. Do not discuss labels before both files are complete.

Merge the two files:

```bash
python -m scanner.outcome_classification --batch-id <BATCH_ID> --merge-annotations annotator_A.csv annotator_B.csv
```

If the generated adjudication template contains unresolved cases, complete it using a third reviewer and rerun:

```bash
python -m scanner.outcome_classification --batch-id <BATCH_ID> --merge-annotations annotator_A.csv annotator_B.csv --adjudication-csv adjudication.csv
```

The merge writes `<BATCH_ID>_classified_runs.csv` and `<BATCH_ID>_annotation_agreement.json`. S0 is assigned only to completed, payload-confirmed runs with resolved S1–S4 all negative. S1–S4 are independent flags and may overlap. S4 is a scanner-side model-output marker match, not attacker-visible exfiltration. Level 5 external/network-side effect remains unmeasured by the current prototype. Follow `docs/outcome-classification.md` and `docs/s1-annotation-guide.md` exactly; do not infer or fabricate missing annotations.

## Revision 6 statistical analysis

Run Revision 6 only after the Revision 4 experiment and Revision 5 annotation/merge process are complete. Keep the raw logs and manifest unchanged. The classifier must have generated both the classified run table and its annotation-agreement JSON.

```bash
python -m scanner.metrics_analysis --batch-id <BATCH_ID>
```

The analysis rebuilds the Revision 4 run-level schedule summary from the raw JSONL event files, then reads:

- `logs/defense_experiment/manifests/<BATCH_ID>.json`
- `results/outcome_classification/<BATCH_ID>_classified_runs.csv`
- `results/outcome_classification/<BATCH_ID>_annotation_agreement.json`

Outputs are written to `results/statistical_analysis/`. Check the missing-schedule file and the metric-specific denominators before using the generated manuscript tables. The primary attack unit is `test_case_id`, with majority aggregation over the three planned repetitions. Wilson intervals and bootstrap intervals are cluster-level; McNemar tests compare matched cases; Holm correction covers the three planned condition comparisons. The 30 benign fixtures are likewise aggregated by `fixture_id`.

Do not submit `.env`, API keys, provider tokens, or any real secrets. For external review, send the raw experiment logs and manifest plus the classified CSV and annotation-agreement report. The private annotation key should be kept away from annotators; it is not required for the statistical calculation once the classified CSV has been produced. See `docs/metrics-statistical-protocol.md` for all formulas, eligibility rules, and caveats.
