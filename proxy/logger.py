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

import hmac
import hashlib
import json
import logging
import time
from typing import Dict, Any, Optional
from proxy.config import settings


class AuditLogger:
    """
    Structured security auditing engine. Output logs are written in standardized JSON format
    to facilitate easy ingestion by SIEM tools like Splunk, Datadog, or AWS CloudWatch.
    """

    def __init__(self):
        self.logger = logging.getLogger("llm-security-proxy-audit")
        self.logger.setLevel(logging.INFO)
        
        # Configure file handler for compliance audit trail
        try:
            handler = logging.FileHandler(settings.AUDIT_LOG_PATH)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        except Exception:
            # Fallback to stdout logging in case directory is missing or permissions fail
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str],
        request_metadata: Dict[str, Any],
        redacted_entities: list,
        guardrail_score: float,
        status: str
    ) -> None:
        """
        Creates, signs, and writes a compliance-level security audit event.
        
        Args:
            event_type: The class of transaction (e.g., chat.completion, system.configuration).
            user_id: The ID of the enterprise user triggering the event.
            request_metadata: Headers, source IP, etc.
            redacted_entities: Summary metadata of fields redacted.
            guardrail_score: Injection risk assessment score.
            status: SUCCESS or BLOCKED/FAILED.
        """
        event_payload = {
            "timestamp": time.time(),
            "event_type": event_type,
            "user_id": user_id or "anonymous",
            "ip_address": request_metadata.get("ip_address"),
            "user_agent": request_metadata.get("user_agent"),
            "redacted_entities_count": len(redacted_entities),
            "redacted_types": [e["entity_type"] for e in redacted_entities],
            "guardrail_score": guardrail_score,
            "status": status,
            "app_name": settings.APP_NAME,
            "app_env": settings.APP_ENV
        }

        # Cryptographic sign log payload if key is configured (SOC2 / HIPAA compliance)
        if settings.SIGN_AUDIT_LOGS and settings.LOG_SIGNING_KEY:
            signature = self._generate_hmac_signature(event_payload, settings.LOG_SIGNING_KEY)
            event_payload["cryptographic_signature"] = signature
            event_payload["signature_algorithm"] = "HMAC-SHA256"

        # Log as single line JSON string for SIEM parser ingestion
        self.logger.info(json.dumps(event_payload))

    def _generate_hmac_signature(self, payload: Dict[str, Any], secret_key: str) -> str:
        """
        Generates HMAC-SHA256 signature to guarantee log integrity.
        """
        serialized = json.dumps(payload, sort_keys=True).encode('utf-8')
        return hmac.new(
            secret_key.encode('utf-8'),
            serialized,
            hashlib.sha256
        ).hexdigest()
