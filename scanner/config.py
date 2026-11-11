"""Central, reproducible configuration for model and lab execution.

New configuration variables use the LLM_* prefix. OPENAI_* values remain
supported as a migration path for existing local .env files.
"""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _safe_base_url(value: str | None) -> str | None:
    """Return a base URL without userinfo, query strings, or fragments."""
    if not value:
        return None
    parts = urlsplit(value.strip())
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path.rstrip("/"), "", ""))


@dataclass(frozen=True)
class Settings:
    target_base_url: str = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    max_pages: int = int(os.getenv("MAX_PAGES", "5"))
    request_timeout: float = float(os.getenv("REQUEST_TIMEOUT", "10"))

    # Preferred names; legacy OPENAI_* names remain accepted.
    llm_api_key: str | None = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or None
    llm_model: str = os.getenv("LLM_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-6-luna"
    llm_base_url: str | None = (
        (os.getenv("LLM_BASE_URL") or None) if "LLM_BASE_URL" in os.environ
        else (os.getenv("OPENAI_BASE_URL") or None)
    )
    llm_provider_name: str = os.getenv("LLM_PROVIDER_NAME") or (
        "OpenAI API" if not ((os.getenv("LLM_BASE_URL") or None) if "LLM_BASE_URL" in os.environ else (os.getenv("OPENAI_BASE_URL") or None))
        else "OpenAI-compatible gateway (provider label not verified)"
    )
    llm_api_mode: str = os.getenv("LLM_API_MODE") or (
        "chat_completions" if ((os.getenv("LLM_BASE_URL") or None) if "LLM_BASE_URL" in os.environ else (os.getenv("OPENAI_BASE_URL") or None)) else "responses"
    )
    llm_reasoning_effort: str = os.getenv("LLM_REASONING_EFFORT", "none").strip().lower()
    llm_max_output_tokens: int = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "1200"))
    llm_api_timeout: float = float(os.getenv("LLM_API_TIMEOUT", "90"))
    llm_max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "0"))

    # Retained only to detect and report legacy .env configuration. It is NOT
    # sent to GPT-6.1 Luna with non-none reasoning effort.
    legacy_temperature: str | None = os.getenv("LLM_TEMPERATURE")

    mock_llm: bool = _env_bool("MOCK_LLM", False)
    # New explicit multi-arm defense condition. Empty preserves legacy IPI_DEFENSE behavior.
    defense_condition: str = os.getenv("DEFENSE_CONDITION", "").strip().upper()
    ipi_defense: bool = _env_bool("IPI_DEFENSE", False)  # legacy compatibility
    secret_value: str = os.getenv("LAB_SYNTHETIC_SECRET", "LAB_SECRET_2026_SYNTHETIC")
    session_value: str = os.getenv("LAB_SYNTHETIC_SESSION", "LAB_SESSION_2026_SYNTHETIC")
    internal_context_value: str = os.getenv("LAB_INTERNAL_CONTEXT", "LAB_INTERNAL_CONTEXT_2026_SYNTHETIC")

    def resolve_defense_condition(self, override: str | None = None) -> str:
        """Resolve an explicit condition, falling back to legacy IPI_DEFENSE."""
        value = (override or self.defense_condition or "").strip().upper()
        if not value:
            value = "INSTRUCTION_GUIDANCE" if self.ipi_defense else "NO_DEFENSE"
        allowed = {"NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"}
        if value not in allowed:
            raise ValueError(f"Unknown defense condition {value!r}; expected one of {sorted(allowed)}")
        return value

    @property
    def safe_base_url(self) -> str | None:
        return _safe_base_url(self.llm_base_url)

    def validate(self, require_credentials: bool = True) -> list[str]:
        errors: list[str] = []
        if self.defense_condition and self.defense_condition not in {"NO_DEFENSE", "INSTRUCTION_GUIDANCE", "STRUCTURED_BOUNDARY"}:
            errors.append("DEFENSE_CONDITION must be NO_DEFENSE, INSTRUCTION_GUIDANCE, or STRUCTURED_BOUNDARY.")
        if self.llm_api_mode not in {"responses", "chat_completions"}:
            errors.append("LLM_API_MODE must be 'responses' or 'chat_completions'.")
        if self.llm_reasoning_effort not in {"low", "medium", "high", "xhigh", "max", "none"}:
            errors.append("LLM_REASONING_EFFORT must be low, medium, high, xhigh, max, or none.")
        if self.llm_max_output_tokens < 128:
            errors.append("LLM_MAX_OUTPUT_TOKENS must be at least 128.")
        if self.llm_api_timeout <= 0:
            errors.append("LLM_API_TIMEOUT must be positive.")
        if self.llm_max_retries < 0:
            errors.append("LLM_MAX_RETRIES cannot be negative.")
        if self.llm_base_url:
            parts = urlsplit(self.llm_base_url)
            if parts.scheme not in {"http", "https"} or not parts.netloc:
                errors.append("LLM_BASE_URL must be an absolute http(s) URL.")
        if require_credentials and not self.mock_llm:
            if not self.llm_api_key:
                errors.append("Set LLM_API_KEY (or legacy OPENAI_API_KEY) in .env.")
            if not self.llm_model:
                errors.append("Set LLM_MODEL in .env.")
        return errors

    def public_metadata(self) -> dict:
        """Return safe, credential-free metadata suitable for experiment logs."""
        return {
            "provider_label": "mock" if self.mock_llm else self.llm_provider_name,
            "api_mode": "mock" if self.mock_llm else self.llm_api_mode,
            "base_url": self.safe_base_url,
            "requested_model_id": "mock" if self.mock_llm else self.llm_model,
            "reasoning_effort": None if self.mock_llm else self.llm_reasoning_effort,
            "temperature": None,
            "temperature_status": "not_sent_to_model",
            "top_p": None,
            "seed": None,
            "sampling_control": "provider/model default; temperature and top_p omitted",
            "legacy_temperature_env_detected": self.legacy_temperature is not None,
            "max_output_tokens": self.llm_max_output_tokens,
            "api_timeout_seconds": self.llm_api_timeout,
            "max_retries": self.llm_max_retries,
            "mock_llm": self.mock_llm,
            "ipi_defense": self.ipi_defense,  # legacy flag
            "default_defense_condition": self.resolve_defense_condition(),
            "target_base_url": self.target_base_url,
            "max_pages": self.max_pages,
            "request_timeout_seconds": self.request_timeout,
            "dataset_version": "2.1.0",
        }


settings = Settings()
