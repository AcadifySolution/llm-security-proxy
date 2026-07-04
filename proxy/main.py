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

from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx

from proxy.config import settings
from proxy.redactor import PIIRedactor
from proxy.guardrails import GuardrailEngine
from proxy.logger import AuditLogger

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise Security Gateway and Proxy for upstream LLM providers.",
    version="1.0.0"
)

# Initialize security engines
redactor = PIIRedactor()
guardrails = GuardrailEngine()
audit_logger = AuditLogger()


class ChatMessage(BaseModel):
    role: str = Field(..., description="Role of the sender (e.g. system, user, assistant)")
    content: str = Field(..., description="Content of the message")


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="The target LLM model name")
    messages: List[ChatMessage] = Field(..., description="List of chat messages to send")
    temperature: Optional[float] = 1.0
    stream: Optional[bool] = False


@app.get("/healthz", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Service health check endpoint for AWS ECS / Kubernetes liveness probes.
    """
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "modules": {
            "pii_redactor": "active" if settings.REDACT_PII else "disabled",
            "guardrails": "active" if settings.ENABLE_GUARDRAILS else "disabled"
        }
    }


@app.post("/v1/chat/completions", response_class=JSONResponse)
async def proxy_chat_completions(payload: ChatCompletionRequest, request: Request):
    """
    Standard OpenAI-compatible Chat Completions proxy endpoint.
    Filters prompts, redacts PII, logs security metrics, and forwards to the upstream engine.
    """
    # Extract request metadata for security auditing
    metadata = {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user_agent", "unknown"),
        "authorization_header": request.headers.get("authorization", "")
    }

    # Extract user identity header if present (e.g., set by auth gateway or Cognito)
    user_id = request.headers.get("X-User-Identity", "anonymous-enterprise-user")

    # 1. Audit / Guardrails check on incoming request prompts
    full_prompt_text = " ".join([msg.content for msg in payload.messages if msg.role == "user"])
    
    is_blocked, risk_score, block_reason = guardrails.check_injection(full_prompt_text)
    
    if is_blocked:
        # Record blocked event in security audit logs
        audit_logger.log_security_event(
            event_type="chat.completion.blocked",
            user_id=user_id,
            request_metadata=metadata,
            redacted_entities=[],
            guardrail_score=risk_score,
            status="BLOCKED"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Security violation",
                "reason": block_reason,
                "code": "PROMPT_SECURITY_BLOCK"
            }
        )

    # 2. PII Redaction
    redacted_messages = []
    total_redacted_info = []
    
    for message in payload.messages:
        if message.role == "user":
            redacted_content, redacted_metadata = redactor.redact_text(message.content)
            redacted_messages.append(ChatMessage(role=message.role, content=redacted_content))
            total_redacted_info.extend(redacted_metadata)
        else:
            # Leave non-user (assistant/system) messages unredacted in this gateway filter flow
            redacted_messages.append(message)

    # 3. Log security transaction audit
    audit_logger.log_security_event(
        event_type="chat.completion.forwarded",
        user_id=user_id,
        request_metadata=metadata,
        redacted_entities=total_redacted_info,
        guardrail_score=risk_score,
        status="SUCCESS"
    )

    # 4. Prepare and Forward to Upstream provider (OpenAI / Anthropic / SageMaker)
    upstream_payload = payload.model_dump()
    upstream_payload["messages"] = [m.model_dump() for m in redacted_messages]

    # Check if upstream API keys are configured. If not, return skeleton payload as mock success.
    if not settings.OPENAI_API_KEY:
        # Dry-run / mock mode for local validation and proof-of-concept testing
        return {
            "id": "chatcmpl-mock-security-proxy-id",
            "object": "chat.completion",
            "created": 1677652288,
            "model": payload.model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a security-verified mock completion. Security proxy checked and cleaned your input."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 14,
                "total_tokens": 26
            },
            "security_proxy_metrics": {
                "pii_redacted_count": len(total_redacted_info),
                "guardrail_score": risk_score
            }
        }

    # Forward downstream request to official upstream API endpoint
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{settings.OPENAI_API_BASE}/chat/completions",
                json=upstream_payload,
                headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                timeout=30.0
            )
            response.raise_for_status()
            res_json = response.json()
            # Append proxy metadata for transparency
            res_json["security_proxy_metrics"] = {
                "pii_redacted_count": len(total_redacted_info),
                "guardrail_score": risk_score
            }
            return res_json
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=f"Upstream provider returned error: {exc.response.text}"
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to reach upstream provider: {str(exc)}"
            )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
