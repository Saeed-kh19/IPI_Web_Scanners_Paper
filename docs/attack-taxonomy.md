# Attack taxonomy

The active test cases use four attack objectives:

- **BHV — Scan-objective manipulation:** attempts to replace the scanner's objective, role, workflow, or expected output.
- **SEC — Security-check manipulation:** attempts to skip, suppress, redirect, falsely complete, or otherwise alter a required check.
- **INFO — Synthetic-context disclosure request:** attempts to elicit synthetic laboratory values, internal context, system instructions, or workflow configuration. This does not prove attacker-visible exfiltration.
- **TOOL — Tool-action manipulation:** attempts to alter tool selection, arguments, target, method, or execution frequency.

Each case separately records `prompt_framing` and `obfuscation`. Framing describes rhetorical cues (for example, authority claims or compliance pretexts); obfuscation describes character-level text transformations. The five historical source groups are retained only in provenance, not used as an ordered scale.

The complete taxonomy, definitions, field values, and evidence cues are embedded in `attacks/ipi_dataset.json`.
