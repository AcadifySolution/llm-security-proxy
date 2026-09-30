"""
LLM Security Proxy application.
"""

import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from proxy.config import settings
from proxy.guardrails import GuardrailEngine
from proxy.logger import AuditLogger
from proxy.redactor import PIIRedactor

app = FastAPI(
    title=settings.APP_NAME,
    description="Security gateway for PII redaction, prompt-injection screening, and auditable LLM forwarding.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type"],
)

redactor = PIIRedactor()
guardrails = GuardrailEngine()
audit_logger = AuditLogger()


class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str = Field(..., max_length=200_000)


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., min_length=1, max_length=200)
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=settings.MAX_MESSAGES)
    temperature: Optional[float] = Field(default=1.0, ge=0.0, le=2.0)
    stream: bool = False


def _authenticate(x_api_key: str | None, authorization: str | None) -> None:
    if not settings.REQUIRE_API_KEY or (
        settings.APP_ENV == "development" and not settings.PROXY_API_KEY
    ):
        return

    expected = settings.PROXY_API_KEY
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Proxy authentication is not configured.",
        )

    supplied = x_api_key
    if not supplied and authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            supplied = token

    if supplied != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid proxy credentials.",
        )


def _prompt_text(messages: List[ChatMessage]) -> str:
    return "
".join(msg.content for msg in messages)


@app.middleware("http")
async def request_limits(request: Request, call_next):
    if request.url.path in {"/healthz", "/readyz"}:
        return await call_next(request)

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds configured limit."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header."},
            )

    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "modules": {
            "pii_redactor": "active" if settings.REDACT_PII else "disabled",
            "guardrails": "active" if settings.ENABLE_GUARDRAILS else "disabled",
        },
    }


@app.get("/readyz", status_code=status.HTTP_200_OK)
async def readiness_check():
    upstream_configured = bool(
        settings.OPENAI_API_KEY or settings.ANTHROPIC_API_KEY
    )
    return {
        "status": "ready",
        "upstream_configured": upstream_configured,
        "environment": settings.APP_ENV,
    }


@app.post("/v1/chat/completions", response_class=JSONResponse)
async def proxy_chat_completions(
    payload: ChatCompletionRequest,
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    started = time.perf_counter()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    _authenticate(x_api_key, authorization)

    full_prompt_text = _prompt_text(payload.messages)
    if len(full_prompt_text) > settings.MAX_MESSAGE_CHARS:
        raise HTTPException(
            status_code=413,
            detail={"error": "Prompt exceeds configured character limit.", "request_id": request_id},
        )

    metadata: Dict[str, Any] = {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "request_id": request_id,
    }
    user_id = request.headers.get("X-User-Identity", "anonymous-enterprise-user")

    is_blocked, risk_score, block_reason = guardrails.check_injection(full_prompt_text)
    if is_blocked:
        audit_logger.log_security_event(
            event_type="chat.completion.blocked",
            user_id=user_id,
            request_metadata=metadata,
            redacted_entities=[],
            guardrail_score=risk_score,
            status="BLOCKED",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Security violation",
                "reason": block_reason,
                "code": "PROMPT_SECURITY_BLOCK",
                "request_id": request_id,
            },
        )

    redacted_messages: List[ChatMessage] = []
    total_redacted_info: list = []

    for message in payload.messages:
        if message.role == "user":
            redacted_content, redacted_metadata = redactor.redact_text(message.content)
            redacted_messages.append(
                ChatMessage(role=message.role, content=redacted_content)
            )
            total_redacted_info.extend(redacted_metadata)
        else:
            redacted_messages.append(message)

    audit_logger.log_security_event(
        event_type="chat.completion.forwarded",
        user_id=user_id,
        request_metadata=metadata,
        redacted_entities=total_redacted_info,
        guardrail_score=risk_score,
        status="SUCCESS",
    )

    upstream_payload = payload.model_dump()
    upstream_payload["messages"] = [m.model_dump() for m in redacted_messages]

    elapsed_ms = lambda: round((time.perf_counter() - started) * 1000, 2)

    if not settings.OPENAI_API_KEY:
        return {
            "id": f"chatcmpl-mock-{request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "This is a security-verified mock completion. Security proxy checked and cleaned your input.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(full_prompt_text.split()),
                "completion_tokens": 14,
                "total_tokens": len(full_prompt_text.split()) + 14,
            },
            "security_proxy_metrics": {
                "pii_redacted_count": len(total_redacted_info),
                "guardrail_score": risk_score,
                "request_id": request_id,
                "latency_ms": elapsed_ms(),
            },
        }

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0)
        ) as client:
            response = await client.post(
                f"{settings.OPENAI_API_BASE.rstrip('/')}/chat/completions",
                json=upstream_payload,
                headers={
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "X-Request-ID": request_id,
                },
            )
            response.raise_for_status()
            result = response.json()
            result["security_proxy_metrics"] = {
                "pii_redacted_count": len(total_redacted_info),
                "guardrail_score": risk_score,
                "request_id": request_id,
                "latency_ms": elapsed_ms(),
            }
            return result

    except httpx.HTTPStatusError as exc:
        audit_logger.log_security_event(
            event_type="chat.completion.upstream_error",
            user_id=user_id,
            request_metadata=metadata,
            redacted_entities=total_redacted_info,
            guardrail_score=risk_score,
            status="FAILED",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "Upstream provider request failed.",
                "provider_status": exc.response.status_code,
                "request_id": request_id,
            },
        ) from exc
    except httpx.RequestError as exc:
        audit_logger.log_security_event(
            event_type="chat.completion.upstream_unreachable",
            user_id=user_id,
            request_metadata=metadata,
            redacted_entities=total_redacted_info,
            guardrail_score=risk_score,
            status="FAILED",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "Upstream provider is unreachable.",
                "request_id": request_id,
            },
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "proxy.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
