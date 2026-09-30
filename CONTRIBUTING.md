# Contributing

## Development workflow

1. Create a focused branch.
2. Make security-sensitive changes small and reviewable.
3. Add regression tests for new policy behavior.
4. Run `ruff check proxy tests`, `black --check proxy tests`, and `pytest -q`.
5. Do not commit secrets, raw production prompts, customer data, or runtime logs.
6. Update `SECURITY.md` and configuration examples when security behavior changes.

## Security-sensitive changes

Changes to authentication, redaction, guardrails, upstream forwarding, logging, or request limits require explicit tests for both allow and deny paths.

## Pull requests

Include the security impact, compatibility impact, test evidence, and any deployment/migration requirements.
