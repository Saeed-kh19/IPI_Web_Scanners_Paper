# Draft manuscript text — Revision 2: Model and API Configuration

> **Status:** Configuration/method text for the revised experiment protocol. Convert to past tense and insert the provider-confirmed response model ID only after the live preflight and actual experimental runs have been completed.

## Model and API Configuration

The revised evaluation is configured to use GPT-6 Luna (model identifier: `gpt-6-luna`) through the configured OpenAI-compatible Responses API endpoint. The model is invoked with the `low` reasoning-effort setting and a strict JSON Schema response format. The model produces at most one structured scanner-action proposal per run. The proposal is then passed to the prototype's local policy validator; only a policy-approved proposal may be executed by the local tool executor. Thus, the model does not directly invoke provider-hosted tools.

Sampling parameters `temperature` and `top_p` are omitted by the request implementation. The request uses a maximum output budget of 1,200 tokens, a 90-second API timeout, and zero automatic SDK retries. Failed API requests are recorded as failed attempts rather than retried invisibly within the same experiment run. No generation seed is configured; repeated observations are therefore not assumed to be deterministic or statistically independent.

For each run, the logging subsystem records the provider label, API mode, requested model identifier, model identifier returned by the provider when available, response identifier and status, token-usage metadata, SDK version, reasoning effort, output limit, timeout, retry policy, dataset version, and SHA-256 hashes of the system prompt and serialized model input. API credentials are not included in the logs. A model-access preflight is executed separately from the experiment corpus and is not counted as a research observation.

The configuration is held constant within an experimental condition. The historical GPT-4.1 observations are treated as a separate, earlier condition and are not pooled with results collected using GPT-6 Luna. Any earlier GPT-6.1 Sol observations are also retained as a distinct historical configuration and must not be pooled with Luna observations.

> **Author action after live testing:** Replace any provider label with the actual provider name, record the exact `response_model_id` observed in run logs, add the experiment date, and report the actual token-usage summary. If a third-party gateway is used, report its name and exact exposed model identifier and do not describe the calls as direct OpenAI API calls.
