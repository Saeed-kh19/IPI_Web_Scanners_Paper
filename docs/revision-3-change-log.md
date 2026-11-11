# Revision 3 change log

## Starting point

Revision 3 is built cumulatively on the complete Revision 2 integrated project ZIP. The Revision 1.1 integrated JSON attack corpus and the Revision 2 model/API integration are preserved.

## Added

- `baseline/benign_baseline_corpus.json`: 30 fixed benign review fixtures (10 short, 10 medium, 10 long), with IDs, hashes, expected action and endpoint metadata.
- `scanner/baseline_analysis.py`: run-level and fixture-cluster-level extraction, summary metrics, Wilson interval, and fixture-cluster bootstrap interval.
- `tests/test_baseline_protocol.py`: fixture, schedule, log extraction, and clustered-summary tests.
- `docs/baseline-protocol.md`: full protocol, metric definitions, execution, and limitation notes.
- `docs/paper_revision3_baseline_protocol.md`: proposed manuscript methods text.

## Updated

- `scanner/run_baseline.py`: runs one named fixture, sets/restores `target/lab_content.txt`, logs fixture and model provenance, checks exact expected tool/URL, policy decision, and HTTP 200 execution.
- `scanner/run_many_baselines.py`: pre-randomizes and records a sequential baseline schedule; defaults to 30 × 3 = 90 planned calls; supports dry-run and a clearly labeled development-only single-fixture mode.
- `README.md` and `docs/reproduction.md`: replace the historical ten-identical-run baseline instruction with Revision 3 protocol and commands.

## Protocol decisions

- Primary baseline unit: 30 distinct benign fixture scenarios.
- Within-fixture repetitions: 3; not independent observations.
- Primary condition: no injected instruction, `IPI_DEFENSE=false`, `MOCK_LLM=false`.
- Primary operational success: expected `security_check` on exact `/page` URL, policy allowed, tool executed, HTTP 200.
- Planned total: 90 model calls.
- All API/crawl/tool errors remain logged; no silent deletion.

## Not performed

No live model baseline experiment was run while preparing this revision. No numerical baseline results are claimed. Mock runs are only for integration testing and are excluded from research analysis.
