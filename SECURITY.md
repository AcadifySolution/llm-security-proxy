# Security Policy

This repository implements a reference security gateway for LLM traffic. It provides enforceable controls, but it is not a certification and does not by itself establish GDPR, HIPAA, SOC 2, or other regulatory compliance.

## Security controls

The proxy supports:

- client authentication with an API key
- request and prompt size budgets
- bounded message counts
- prompt-injection screening
- configurable PII redaction
- structured security audit events
- optional HMAC-SHA256 audit signing
- non-root container execution
- health/readiness probes
- upstream request IDs

## Important limitations

The prompt-injection detector is heuristic. No pattern list can guarantee complete detection of jailbreaks or indirect prompt injection.

The built-in PII detector is also a baseline. Production deployments processing regulated or high-risk data should use a tested entity-recognition solution and domain-specific validation.

The current upstream adapter is OpenAI-compatible. Additional provider adapters should preserve the same security pipeline and policy boundaries.

## Production requirements

Before exposing this proxy to untrusted clients, add:

- identity-based authentication and authorization
- tenant isolation
- edge rate limiting and abuse controls
- TLS termination and certificate management
- upstream host allowlisting / egress controls
- secret-manager integration and key rotation
- centralized log retention and access control
- security monitoring and alerting
- red-team testing for prompt injection and data leakage
- provider-specific retention/residency review

Never commit API keys, raw prompts, customer data, or sensitive audit payloads.
