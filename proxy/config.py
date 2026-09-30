"""
Configuration for the LLM Security Proxy.
"""

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "llm-security-proxy"
    APP_ENV: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = False

    # Client authentication. Required outside development unless explicitly disabled.
    REQUIRE_API_KEY: bool = True
    PROXY_API_KEY: Optional[str] = None

    # Upstream providers
    OPENAI_API_BASE: str = "https://api.openai.com/v1"
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_BASE: str = "https://api.anthropic.com/v1"
    ANTHROPIC_API_KEY: Optional[str] = None

    # Request limits / budgets
    MAX_PROMPT_TOKENS: int = 4096
    MAX_MESSAGES: int = 100
    MAX_MESSAGE_CHARS: int = 200_000
    MAX_REQUEST_BODY_BYTES: int = 1_000_000

    # PII
    REDACT_PII: bool = True
    PII_SENSITIVITY_THRESHOLD: float = 0.7
    PII_REDACTION_PLACEHOLDER: str = "[REDACTED]"
    PII_ENTITIES_TO_FILTER: str = (
        "EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,CREDIT_CARD,IP_ADDRESS"
    )

    # Guardrails
    ENABLE_GUARDRAILS: bool = True
    PROMPT_INJECTION_THRESHOLD: float = 0.85
    BLOCK_TOXIC_CONTENT: bool = True

    # Audit
    AUDIT_LOG_PATH: str = "/var/log/llm-security-proxy/audit.log"
    SIGN_AUDIT_LOGS: bool = False
    LOG_SIGNING_KEY: Optional[str] = None


settings = Settings()
