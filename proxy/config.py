"""
MIT License

Copyright (c) 2026 Acadify Solutions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Settings and configuration loader for the LLM Security Proxy.
    Loads settings from environment variables or a .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # API Configuration
    APP_NAME: str = "llm-security-proxy"
    APP_ENV: str = "production"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = False

    # Upstream Providers
    OPENAI_API_BASE: str = "https://api.openai.com/v1"
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_BASE: str = "https://api.anthropic.com/v1"
    ANTHROPIC_API_KEY: Optional[str] = None

    # PII Redaction Configuration
    REDACT_PII: bool = True
    PII_SENSITIVITY_THRESHOLD: float = 0.7  # Confidence threshold for PII entity matches
    PII_REDACTION_PLACEHOLDER: str = "[REDACTED]"
    
    # Supported PII Entities to filter (e.g., EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD, etc.)
    PII_ENTITIES_TO_FILTER: str = "EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,CREDIT_CARD,IP_ADDRESS"

    # Guardrails and Filtering Configuration
    ENABLE_GUARDRAILS: bool = True
    PROMPT_INJECTION_THRESHOLD: float = 0.85  # Model classification confidence threshold
    BLOCK_TOXIC_CONTENT: bool = True
    MAX_PROMPT_TOKENS: int = 4096

    # Security Log Auditing Configuration
    AUDIT_LOG_PATH: str = "/var/log/llm-security-proxy/audit.log"
    SIGN_AUDIT_LOGS: bool = False
    LOG_SIGNING_KEY: Optional[str] = None  # Key used to cryptographically sign logs for tamper-proofing


settings = Settings()
