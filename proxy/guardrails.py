"""
Prompt security guardrails.
"""

import re

from proxy.config import settings


class GuardrailEngine:
    def __init__(self):
        self.injection_keywords: list[str] = [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"system\s+(?:override|bypass)",
            r"you\s+are\s+now\s+(?:a|an)\s+unrestricted",
            r"developer\s+mode",
            r"do\s+anything\s+now\s+dan",
            r"act\s+as\s+a\s+computer\s+terminal\s+with\s+no\s+restrictions",
            r"jailbreak",
            r"bypass\s+safety\s+filters",
        ]
        self.compiled_keywords = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.injection_keywords
        ]

    def check_injection(self, prompt: str) -> tuple[bool, float, str]:
        if not settings.ENABLE_GUARDRAILS:
            return False, 0.0, "Guardrails are disabled"

        if len(prompt.split()) > settings.MAX_PROMPT_TOKENS:
            return (
                True,
                1.0,
                f"Prompt length exceeds limit of {settings.MAX_PROMPT_TOKENS} tokens",
            )

        for idx, pattern in enumerate(self.compiled_keywords):
            if pattern.search(prompt):
                return (
                    True,
                    0.95,
                    f"Adversarial signature pattern detected (Rule #{idx + 1})",
                )

        is_ml_blocked, ml_risk, ml_reason = self._run_ml_guard_inference(prompt)
        if is_ml_blocked:
            return True, ml_risk, ml_reason

        return False, 0.0, "Prompt passed security filters"

    def _run_ml_guard_inference(self, prompt: str) -> tuple[bool, float, str]:
        return False, 0.0, ""
