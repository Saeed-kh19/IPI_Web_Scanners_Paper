# Revision 2 — Model and API Configuration

## Primary model

The primary model for the revised experiment is **GPT-6 Luna**, requested model ID:

```text
gpt-6-luna
```

The project requests the provider model identifier `gpt-6-luna`. Existing archived run records show completed Responses API calls that returned `gpt-6-luna` and used strict JSON Schema structured output. This records prior behavior of the configured endpoint; it is not a guarantee that every provider or endpoint exposes the same model identifier.

The experiment uses `reasoning.effort=low` as the fixed primary configuration because the scanner task is a bounded structured decision/routing task. This is an experimental setting, not a claim that low effort is optimal. Any change to model ID, reasoning effort, endpoint, or prompt requires a new experiment condition and must not be pooled silently with previous runs.

Do not estimate research cost from a model name alone. Record actual `usage` fields returned by the provider for every run and retain the provider/endpoint details in the manifest.

## API interface

The scanner sends requests through the **Responses API** with strict JSON Schema structured output. The included `.env` is configured with the GapGPT-compatible base URL `https://api.gapgpt.app/v1`; the OpenAI SDK-compatible interface does not mean the request is sent directly to OpenAI. The model proposes a structured action; the local `PolicyValidator` checks that proposal, and only the local `ToolExecutor` can execute an allowed tool. This is not provider-hosted function/tool calling.

The compatibility mode `chat_completions` exists for OpenAI-compatible gateways that do not expose `/v1/responses`. It uses JSON mode and local validation. Do not change API mode during an experiment. A gateway's support for GPT-6 Luna must be verified independently; model availability on one endpoint does not prove that another gateway exposes it.

## Fixed primary configuration

| Parameter | Primary setting |
|---|---|
| Configured provider label | `OpenAI API` (as recorded in the archived `.env`) |
| Configured base URL | `https://api.gapgpt.app/v1` |
| Model ID | `gpt-6-luna` |
| API mode | `responses` |
| Reasoning effort | `low` |
| Temperature | Not sent |
| Top-p | Not sent |
| Output format | Strict JSON Schema |
| Maximum output tokens | 1,200 |
| API timeout | 90 seconds |
| SDK automatic retries | 0 |
| Tool calls | Not provider tool calls; local policy-mediated dispatch |
| Mock mode | Off for research runs |

The checked-in `.env.example` uses `LLM_REASONING_EFFORT=low`, matching the existing completed Luna preflight/run records in this archive. The `temperature` and `top_p` parameters are omitted by the request implementation. Do not describe these runs as temperature-zero runs. The value actually used in an experiment is the value recorded in its manifest and run logs; keep it fixed throughout a batch.

Automatic SDK retries are disabled (`LLM_MAX_RETRIES=0`) so a transient API failure becomes a visibly failed experiment run instead of being silently retried inside one run. A manually restarted run receives a new `run_id` and must remain identifiable as a separate attempt.

## API-call and model provenance recorded per run

The JSONL log records:

- provider label and sanitized base URL;
- API mode and requested model ID;
- returned model ID from the response, when provided;
- response ID and status/finish reason;
- token usage returned by the API;
- reasoning effort, output-token limit, timeout, and retry count;
- Python OpenAI SDK version;
- system-prompt SHA-256 hash (the hash changes when the defense add-on is enabled);
- serialized LLM-input SHA-256 hash;
- dataset version, defense condition, target settings, and UTC timestamps.

API keys and credentials are never written to logs. The returned model identifier is recorded because a provider alias may not by itself establish an immutable model snapshot. A requested model alias does not necessarily identify an immutable snapshot. Retain the model identifier returned in each response whenever the provider supplies it.

## Configuration

Copy `.env.example` to `.env` and set:

```env
LLM_API_KEY=YOUR_OPENAI_API_KEY
LLM_PROVIDER_NAME="OpenAI API"
LLM_API_MODE=responses
LLM_BASE_URL=
LLM_MODEL=gpt-6-luna
LLM_REASONING_EFFORT=low
LLM_MAX_OUTPUT_TOKENS=1200
LLM_API_TIMEOUT=90
LLM_MAX_RETRIES=0
MOCK_LLM=false
IPI_DEFENSE=false
```

Do not commit `.env`. If migrating from an earlier project configuration, remove stale `OPENAI_MODEL` and `OPENAI_BASE_URL` variables from `.env` after moving to the `LLM_*` variables. Legacy `OPENAI_API_KEY`, `OPENAI_MODEL`, and `OPENAI_BASE_URL` are still read for migration compatibility when the corresponding new variable is not set.

For a custom OpenAI-compatible gateway (including the GapGPT endpoint used in the earlier project configuration), set its documented model ID, actual provider label, base URL, and API mode explicitly. For example, if the gateway exposes only Chat Completions:

```env
LLM_API_KEY=YOUR_GATEWAY_KEY
LLM_PROVIDER_NAME="GapGPT"
LLM_API_MODE=chat_completions
LLM_BASE_URL=https://api.gapgpt.app/v1
LLM_MODEL=THE_EXACT_MODEL_ID_EXPOSED_BY_THE_GATEWAY
LLM_REASONING_EFFORT=low
```

This is a configuration example. Although this archive contains prior completed calls returning `gpt-6-luna`, confirm the selected gateway endpoint and reasoning-effort parameter with the live preflight before starting a new experiment batch. Use `chat_completions` only if that gateway supports the required endpoint and parameters. If it does not expose the chosen model, do not silently substitute another model; record a different model as a separate experiment condition.

## Preflight procedure

Configuration-only check (no network request):

```bash
python scripts/check_model_config.py
```

One live API check (one request, possible token charge, no crawler and no tool execution):

```bash
python scripts/check_model_config.py --live
```

The live check verifies that credentials, endpoint, model access, response parsing, and structured output work. It is a preflight, not a research run. Save its terminal output with the experiment records.

## Scientific interpretation and limitations

- GPT-6 Luna replaces GPT-4.1 as the primary model for the revised experiments; the old GPT-4.1 results are historical and must not be pooled with new results.
- GPT-6 Luna at the recorded reasoning-effort setting is a distinct model/configuration condition. Differences from the earlier model cannot be attributed solely to prompt-injection susceptibility because model and API settings changed.
- No API seed is configured. Do not claim deterministic generation. Repeated runs are repeated observations under a fixed request configuration; record model response metadata and report within-test-case agreement in the later statistical revision.
- The project still makes one structured model decision per scan; this revision does not turn the scanner into a multi-step agent.
- The primary model is not a second-model comparison. A second model, if included, must be treated as a separate condition and evaluated under the same dataset and protocol in a later revision.
