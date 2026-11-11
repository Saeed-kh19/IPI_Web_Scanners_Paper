# Revision 6 Change Log

**Revision:** 6.0.0  
**Base:** Revision 5 integrated project ZIP  
**Status:** Analysis pipeline and synthetic unit validation completed; no live research analysis performed.

## Added

- `scanner/metrics_analysis.py`: run-level, attack-ID-level, category, paired-defense, benign-utility, confidence-interval, exact McNemar, and Holm-adjustment analysis.
- `tests/test_metrics_analysis.py`: synthetic tests for estimators, paired tests, overlap handling, and missing repetitions.
- `docs/metrics-statistical-protocol.md`: metric formulas, denominators, aggregation rules, inference, missing data, and limitations.
- `docs/paper_revision6_metrics.md`: manuscript-ready statistical methods and results template.
- `docs/revision-6-change-log.md`.

## Statistical decisions

- Primary unit is `test_case_id`; repeated model calls are nested.
- Primary attack success is the majority outcome across three planned valid repeats.
- ASR is the union S1 OR S2 OR S3 OR S4; overlapping outcomes are never summed.
- Unknown S1 is never assumed negative. A positive S2/S3/S4 can nevertheless determine a positive ASR run outcome.
- UDR is S1 OR S2; UTRR is S2; UTE is S3; SDR is S4.
- Policy block rate is conditional on unexpected tool requests.
- 95% Wilson intervals are reported at the independent case/fixture level; cluster bootstrap resamples case/fixture IDs.
- Paired comparisons use exact two-sided McNemar tests and paired cluster bootstrap risk-difference intervals.
- Holm correction is applied across the three planned pairwise defense comparisons.
- Benign utility is analyzed at fixture level using the Revision 3 success rule.
- Missing/failed/incomplete/payload-unconfirmed/mock/ambiguous observations are not imputed as failures or successes.
- Category × payload-family causal claims and the historical TOOL × OBF result remain deferred to Revision 7.

## Not performed

- No actual experiment logs or human annotations were present in the base ZIP.
- No live API calls, attack runs, baseline runs, statistical results, p-values, or confidence intervals from empirical data were generated.
- Test data are synthetic and serve only to validate the analysis implementation.
