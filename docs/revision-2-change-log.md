# Revision 2 Change Log — Model and Experiment Configuration

## Starting point

Integrated Revision 1.1 project ZIP (`ipi_web_security_revision1_1_integrated.zip`). The dataset `attacks/ipi_dataset.json` and all Revision 1.1 curation/provenance data are preserved.

## Changes

1. Selected GPT-6.1 Sol (`gpt-6.1-sol`) as the primary revised-study model.
2. Migrated the default direct OpenAI path from Chat Completions to the Responses API.
3. Added strict JSON Schema output for the model's proposed scanner decision.
4. Added a gateway compatibility mode for explicitly configured Chat Completions endpoints.
5. Replaced ambiguous `OPENAI_*`-only settings with documented `LLM_*` settings while retaining legacy environment-variable compatibility.
6. Set reasoning effort to `low`; stopped sending `temperature=0` and `top_p` to the GPT-6.1 Sol reasoning request.
7. Disabled automatic SDK retries by default so failed calls remain visible as failed run attempts.
8. Added API timeout, output-token limit, provider label, and API-mode settings.
9. Added per-run model configuration, system-prompt hash, response ID/status, returned model ID, SDK version, and token-usage metadata to logs.
10. Added a safe configuration checker and one-request live preflight script.
11. Updated README and reproduction instructions.

## Tests completed

- Python compilation.
- Dataset v2.1.0 validation.
- Model configuration validation without credentials.
- Mock decision output parsing and tool-request normalization.
- Strict schema shape check.
- Runner dry-run and preflight help.
- No live API call was made from the build environment because no user's API key/provider access is available here.

## Not done in Revision 2

- No corpus experiments were run.
- No baseline repetitions were increased (Revision 3).
- No defense design/experiment was changed (Revision 4).
- No second-model comparison was run.
- No model cost, latency, or attack-success measurement was claimed.

## Subsequent model update (after Revision 6)

The current project configuration was subsequently updated to request `gpt-6-luna`. The original Revision 2 entries above document the earlier GPT-6.1 Sol configuration and are retained as historical change history. The active README, model-configuration documentation, reproduction guidance, defense protocol, and model-request test fixtures now describe Luna. The reasoning-effort value in the checked-in environment template remains `low`; no scanner, crawler, policy, tool-execution, defense, dataset, classification, or statistical-analysis logic was changed as part of this model-ID update. Existing JSONL run logs and manifests were left byte-for-byte unchanged and remain authoritative for the model used in those historical calls.
