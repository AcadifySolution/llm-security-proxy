import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from proxy.config import settings
from proxy.guardrails import GuardrailEngine
from proxy.logger import AuditLogger
from proxy.redactor import PIIRedactor

app = FastAPI(
    title="Enterprise LLM Security Proxy",
    description="Policy enforcement gateway for PII redaction, prompt-injection screening, and auditable LLM forwarding.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type"],
)

guardrail_engine = GuardrailEngine()
pii_redactor = PIIRedactor()
audit_logger = AuditLogger()


def _authenticate(x_api_key: str | None, authorization: str | None) -> None:
    if not settings.REQUIRE_API_KEY or (
        settings.APP_ENV == "development" and not settings.PROXY_API_KEY
    ):
        return

    expected = settings.PROXY_API_KEY
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Proxy authentication is not configured.",
        )

    supplied = x_api_key
    if not supplied and authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            supplied = token

    if supplied != expected:
        raise HTTPException(status_code=401, detail="Invalid proxy credentials.")


def _extract_prompt_text(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for message in messages:
        content = message.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    parts.append(part["text"])
    return "
".join(parts)


@app.middleware("http")
async def request_limits(request: Request, call_next):
    if request.url.path == "/healthz":
        return await call_next(request)

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body exceeds configured limit.")

    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return {"status": "healthy", "service": settings.APP_NAME}


@app.get("/readyz")
def readyz():
    upstream_configured = bool(settings.OPENAI_API_KEY or settings.ANTHROPIC_API_KEY)
    return {
        "status": "ready",
        "service": settings.APP_NAME,
        "upstream_configured": upstream_configured,
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    payload: dict[str, Any],
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    _authenticate(x_api_key, authorization)

    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=422, detail="messages must be a non-empty array.")
    if len(messages) > settings.MAX_MESSAGES:
        raise HTTPException(status_code=413, detail="Too many messages in request.")

    prompt_text = _extract_prompt_text(messages)
    if len(prompt_text) > settings.MAX_MESSAGE_CHARS:
        raise HTTPException(status_code=413, detail="Prompt content exceeds configured limit.")

    blocked, risk_score, reason = guardrail_engine.check_injection(prompt_text)
    if blocked:
        audit_logger.log_security_event(
            event_type="chat.completion.blocked",
            user_id=None,
            request_metadata={"request_id": request_id},
            redacted_entities=[],
            guardrail_score=risk_score,
            status="BLOCKED",
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Security violation",
                "reason": reason,
                "code": "PROMPT_SECURITY_BLOCK",
                "request_id": request_id,
            },
        )

    redacted_messages = []
    redacted_entities = []
    for message in messages:
        copied = dict(message)
        content = message.get("content", "")
        if isinstance(content, str):
            cleaned, entities = pii_redactor.redact_text(content)
            copied["content"] = cleaned
            redacted_entities.extend(entities)
        redacted_messages.append(copied)

    audit_logger.log_security_event(
        event_type="chat.completion.accepted",
        user_id=None,
        request_metadata={"request_id": request_id},
        redacted_entities=redacted_entities,
        guardrail_score=risk_score,
        status="SUCCESS",
    )

    # Preserve the existing mock/provider forwarding behavior below.
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "id": f"chatcmpl-{request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.get("model", "unknown"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Security proxy accepted the request after policy checks.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": len(prompt_text.split()), "completion_tokens": 10, "total_tokens": len(prompt_text.split()) + 10},
        "security_proxy_metrics": {
            "pii_redacted_count": len(redacted_entities),
            "guardrail_score": risk_score,
            "request_id": request_id,
            "latency_ms": elapsed_ms,
        },
    }
