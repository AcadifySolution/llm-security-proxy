"""
Prompt security guardrails.
"""

import re
from typing import List, Tuple

from proxy.config import settings


class GuardrailEngine:
    def __init__(self):
        self.injection_keywords: List[str] = [
            r"ignores+(?:alls+)?previouss+instructions",
            r"systems+(?:override|bypass)",
            r"yous+ares+nows+(?:a|an)s+unrestricted",
            r"developers+mode",
            r"dos+anythings+nows+dan",
            r"acts+ass+as+computers+terminals+withs+nos+restrictions",
            r"jailbreak",
            r"bypasss+safetys+filters",
        ]
        self.compiled_keywords = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.injection_keywords
        ]

    def check_injection(self, prompt: str) -> Tuple[bool, float, str]:
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

    def _run_ml_guard_inference(self, prompt: str) -> Tuple[bool, float, str]:
        return False, 0.0, ""
