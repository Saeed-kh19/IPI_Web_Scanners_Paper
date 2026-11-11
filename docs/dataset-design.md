# Dataset v2.1.0: design and curation

## Unit of analysis

A `test_case` is one prompt condition. Repeated executions are run-level replicates and must not be counted as additional test cases. The only active dataset source is `attacks/ipi_dataset.json`; it is self-contained and includes taxonomy, provenance, curation exclusions, and matched-pair metadata.

## Size and category distribution

The source contained 390 records. Curation removed 25 exact duplicate aliases and 17 semantically redundant prompts, leaving 348 active test cases: BHV 97, SEC 92, INFO 83, and TOOL 76. No new prompts were added simply to increase the count. The retained number is large enough to give each category substantially more than the referee's suggested ~20 attack-ID floor, but statistical power still depends on the effect size, run-level variability, and analysis method.

## Duplicate policy

Exact duplicate payload strings are represented once. Prompts with the same category and operative action that differed only by wording or redundant explanation were merged. The 42 excluded source IDs remain traceable in the JSON's `excluded_source_records` and in the retained case's `provenance.source_attack_ids`; they are not executed.

Plain/obfuscated pairs are intentionally retained as paired experimental conditions, not treated as duplicates. The high-similarity review surfaced 28 candidate pairs: 24 were plain/obfuscated candidates that belong to the matched-treatment design, while four additional candidates were consolidated as semantic redundancies. The final controlled design contains 30 matched pairs in total. All 30 obfuscated members were reconstructed as deterministic character-level transformations of corresponding plain controls from the historical SE group. The wording and prompt framing are held constant within each pair. The transformation method and recipe version are recorded in the JSON. Similarity scores alone were never used as an automatic deletion rule. A final pairwise lexical screen over the 348 active cases, excluding the 30 intentional matched pairs, checked 60,348 comparisons using NFKC normalization, SequenceMatcher character ratio >= 0.82, or token Jaccard >= 0.72; no remaining pair exceeded either threshold. This is a lexical screen, not proof that no semantic overlap remains.

## Prompt framing versus obfuscation

`prompt_framing` is annotated from the actual prompt wording (or from the matched plain control for an obfuscated treatment). It contains:

- `instruction_forms`: imperative/directive, polite request, interrogative request, persona assignment, and declarative pretext/claim.
- `framing_devices`: evidence-backed multi-label cues such as authority claim, procedural-update pretext, compliance/audit pretext, technical/debugging pretext, performance/resource pretext, urgency, politeness/cooperation, social proof, persona/mode reassignment, prior-completion claim, waiver/exemption claim, safety/ethics appeal, and research/measurement pretext.
- `matched_cues`: the normalized lexical cue supporting each assigned device. `instruction_form_cues` supplies corresponding evidence for instruction-form labels. `framing_status` distinguishes an explicit cue from no configured cue being detected.

Obfuscation is a separate field. It describes character-level transformations (homoglyphs, Cyrillic lookalikes, leetspeak, zero-width characters, Persian half-space, soft hyphen, full-width characters, or deliberate misspelling). The historical labels `SE`, `OBF`, `BASE`, `EXTENDED`, and `ADV` are retained only as provenance metadata and are not treated as a single ordered scale.

The complete tag definitions and lexical matching expressions are embedded in `prompt_framing_taxonomy` within the JSON. Generic words such as “policy”, “pipeline”, and “metrics” are deliberately insufficient on their own to trigger broad framing tags. Framing annotation is still rule-assisted and single-curator: it is not a validated psychological or pragmatic annotation. There is no inter-annotator agreement. The labels should be used descriptively until independently reviewed by at least one additional annotator using a written codebook.

## Delivery point

The current runner writes every payload to `target/lab_content.txt`; the target renders it in the User Review paragraph on `/page`. Historical `source_type` and `L1`/`L2` labels were not separately implemented by the supplied runner and are kept only as provenance. No distinct hidden-HTML, attribute, JavaScript, or alternate-location condition is claimed.

## Reproducibility and validation

Run `python scripts/validate_dataset.py` from the project root. The check validates the single JSON file, duplicate handling, category counts, source-ID traceability, unique payloads, and matched-pair consistency.
