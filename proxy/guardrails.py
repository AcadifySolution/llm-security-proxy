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

import re
from typing import List, Tuple
from proxy.config import settings


class GuardrailEngine:
    """
    Detects and blocks adversarial prompt injections, system override attempts,
    and jailbreaks before sending prompts to the upstream LLM.
    """

    def __init__(self):
        # High-risk adversarial terms commonly found in jailbreaks and injection payloads
        self.injection_keywords: List[str] = [
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

    def check_injection(self, prompt: str) -> Tuple[bool, float, str]:
        """
        Evaluates a prompt against security guardrails.
        
        Args:
            prompt: The input user prompt.
            
        Returns:
            A tuple of (is_blocked: bool, risk_score: float, reason: str)
        """
        if not settings.ENABLE_GUARDRAILS:
            return False, 0.0, "Guardrails are globally disabled"

        # 1. Check prompt length constraints (Denial of Wallet / Buffer overflow preventions)
        if len(prompt.split()) > settings.MAX_PROMPT_TOKENS:
            return True, 1.0, f"Prompt length exceeds limit of {settings.MAX_PROMPT_TOKENS} tokens"

        # 2. Local signature and pattern matching (Heuristic Injection Rules)
        for idx, pattern in enumerate(self.compiled_keywords):
            if pattern.search(prompt):
                return True, 0.95, f"Adversarial signature pattern detected (Rule #{idx + 1})"

        # 3. Structural integration hooks for LLM classification models (e.g. Llama Guard, Rebilly, Guardrails AI)
        is_ml_blocked, ml_risk, ml_reason = self._run_ml_guard_inference(prompt)
        if is_ml_blocked:
            return True, ml_risk, ml_reason

        return False, 0.0, "Prompt passed security filters"

    def _run_ml_guard_inference(self, prompt: str) -> Tuple[bool, float, str]:
        """
        Skeleton hook for enterprise ML-based injection detectors (e.g. Llama Guard).
        Calls local classification models or cloud guardrail endpoints.
        """
        # Example API client request:
        # payload = {"model": "meta-llama/Llama-Guard-3-8B", "prompt": prompt}
        # response = client.post("/v1/moderations", json=payload)
        # return response.is_blocked, response.risk_score, response.reason
        return False, 0.0, ""
