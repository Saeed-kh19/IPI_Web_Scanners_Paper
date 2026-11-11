# WAInjectBench + GPT-6 Luna: quick runbook

Run these commands from the project root in PowerShell. Keep the original `.env` private; this ZIP intentionally does not include it.

## 1. Environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

Set `LLM_MODEL=gpt-6-luna`, `LLM_API_MODE=responses`, `LLM_REASONING_EFFORT=low`, `LLM_MAX_RETRIES=0`, `MOCK_LLM=false`, and your own `LLM_API_KEY`. For the official OpenAI endpoint leave `LLM_BASE_URL=` empty. Do not put the key into source files or share `.env`.

## 2. Download only WAInjectBench text files

```powershell
git clone --depth 1 --filter=blob:none --sparse https://github.com/Norrrrrrr-lyn/WAInjectBench.git
Set-Location WAInjectBench
git sparse-checkout set data/text
Set-Location ..
```

## 3. Import and validate

```powershell
python scripts/import_wainjectbench.py --data-dir .\WAInjectBench\data\text --strict-counts
Get-Content .\data\wainjectbench_import_report.json
```

Continue only if import errors are zero and the counts match the published text corpus: 991 malicious and 2,707 benign. If not, inspect the report and repository version before proceeding.

## 4. Start the local target (Terminal 1)

```powershell
Set-Location target
python run.py
```

Leave it running at `http://127.0.0.1:8000`.

## 5. Model preflight and dry run (Terminal 2, project root)

```powershell
Set-Location ..
python scripts/check_model_config.py
python scripts/check_model_config.py --live
python -m scanner.run_wainjectbench_experiment --dry-run --max-per-source 5 --repeats 3 --seed 20261110
```

The live preflight costs one API request. The dry run costs nothing. Read the exact selected sample count and planned call count before continuing.

## 6. Run the quick stratified experiment

```powershell
python -m scanner.run_wainjectbench_experiment --max-per-source 5 --repeats 3 --seed 20261110
```

`--max-per-source 5` randomly selects up to five records from each original JSONL source file, separately for benign and malicious labels. All three conditions run for every selected record, sequentially. Save the printed `Batch ID`.

For the full text corpus use `--max-per-source 0`; expect 11,094 calls for one repeat or 33,282 calls for three repeats. Do not start that full run unless the time and API budget are available.

## 7. Analyze and annotate

Replace `<BATCH_ID>` below with the UUID printed by the runner:

```powershell
python -m scanner.defense_analysis --batch-id <BATCH_ID>
python -m scanner.outcome_classification --batch-id <BATCH_ID> --export-annotations
```

Give each of two annotators a separate copy of `<BATCH_ID>_s1_annotation_blinded.csv`. Keep `<BATCH_ID>_annotation_key_PRIVATE.csv` private. After both files are completed:

```powershell
python -m scanner.outcome_classification --batch-id <BATCH_ID> --merge-annotations .\annotator_A.csv .\annotator_B.csv
python -m scanner.metrics_analysis --batch-id <BATCH_ID>
```

If adjudication is requested, complete the generated adjudication template and pass it using `--adjudication-csv <FILE>` to `--merge-annotations`.

## Important scope note

The scanner injects each text segment into the controlled `/page` User Review paragraph. This is a text-transfer adaptation, not a reproduction of WAInjectBench's original email, caption, or interface delivery channels. Image samples are not included because this scanner does not process image pixels. Keep this limitation in the experimental methodology. WAInjectBench's benign/malicious labels are input labels, not S1-S4 scanner outcomes.
