# Proposed manuscript replacement — Baseline protocol (Revision 3)

## Baseline condition and benign-content controls

To characterize the scanner's behavior in the absence of indirect prompt injection, we designed a benign baseline condition using a fixed corpus of 30 non-instructional user-review texts. The corpus contains ten short, ten medium, and ten long fixtures. Each fixture is rendered at the same user-generated-content location on the controlled `/page` endpoint used by the attack harness. The baseline uses the standard scanner prompt, with IPI-specific guidance disabled, and holds the model/provider/API configuration, crawler, target application, policy validator, and tool executor fixed relative to the no-defense attack condition.

Each of the 30 fixtures is executed three times, yielding 90 planned model calls. The execution schedule is interleaved using a recorded pseudorandom seed, and a batch manifest stores the exact fixture/repetition order and configuration before execution. The fixture is the primary descriptive unit (`n=30`); the three observations within a fixture are treated as repeated measurements rather than independent samples. Repetitions are used to examine within-fixture decision and workflow consistency, not to inflate the sample size.

The intended benign workflow is a `security_check` request directed to the exact controlled `/page` URL. A run is counted as a baseline workflow success only when the model requests that tool and URL, the local policy validator permits the request, and the tool executes successfully with HTTP status 200. No-tool decisions, different tool or URL requests, policy blocks, and execution failures are retained as distinct observable outcomes. This operational endpoint measures completion of the predefined scanner workflow; it does not measure vulnerability-detection accuracy.

We report descriptive run-level workflow completion, fixture-majority success, mean per-fixture success fraction, within-fixture agreement, no-tool rate, unexpected tool/URL request and execution rates, policy block rate, and failures. Repeated observations are clustered by fixture in the summary. Confidence intervals are calculated at fixture level and are interpreted cautiously because the 30 manually authored fixtures form a fixed convenience corpus rather than a probability sample of benign web content.

## Required qualification

The target application does not contain a seeded ground-truth vulnerability set, and the implemented `security_check` is a limited security-header presence check. Accordingly, the baseline results characterize whether the scanner follows and completes its expected benign workflow under the tested conditions; they must not be described as vulnerability-detection accuracy, false-positive rate, or general scanner reliability.

*This text is a proposed methods description. Convert execution-related statements to past tense and insert numerical results only after the 90-run batch is completed, the raw logs are preserved, and the baseline analyzer output is checked.*
