# Security Policy

This project is a reference security gateway for LLM traffic. It provides policy-enforcement primitives but does not itself establish regulatory certification.

## Security controls

The proxy can enforce:

- client authentication with an API key
- prompt and request-size budgets
- prompt-injection screening
- configurable PII redaction
- structured audit logging
- optional HMAC signing of audit events
- non-root container execution
- health/readiness endpoints
- explicit upstream provider configuration

## Important limitations

The included injection detector is heuristic and should not be treated as complete protection against prompt injection, jailbreaks, or malicious tool output.

The regex PII detector is a baseline. Production deployments handling sensitive data should use a tested entity detector and add domain-specific patterns.

Before public deployment, add:

- identity-based authorization and tenant isolation
- rate limiting at the edge
- TLS termination
- upstream allowlists and egress controls
- key rotation
- secrets manager integration
- SIEM retention controls
- incident response procedures
- red-team security evaluation
- provider-specific privacy and retention review

Never commit real API keys or sensitive prompts.
