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
from typing import Dict, List, Tuple
from proxy.config import settings


class PIIRedactor:
    """
    Handles PII (Personally Identifiable Information) detection and redaction.
    Signals compliance with regulations like GDPR, HIPAA, and CCPA by removing
    sensitive information before it leaves the corporate network.
    """

    def __init__(self):
        # Configure regex patterns for default local validation
        self.patterns: Dict[str, re.Pattern] = {
            "EMAIL_ADDRESS": re.compile(
                r"[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,10}", re.IGNORECASE
            ),
            "PHONE_NUMBER": re.compile(
                r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
            ),
            "CREDIT_CARD": re.compile(
                r"\b(?:\d[ -]*?){13,16}\b"
            ),
            "US_SSN": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),
            "IP_ADDRESS": re.compile(
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            ),
        }
        # Parse entities that need to be filtered from config
        self.active_entities = [
            e.strip() for e in settings.PII_ENTITIES_TO_FILTER.split(",") if e.strip()
        ]

    def detect_entities(self, text: str) -> List[Dict]:
        """
        Scans text for configured PII entities.
        
        In production, this function integrates with an enterprise-grade NLP PII detector
        such as Microsoft Presidio or AWS Comprehend.
        
        Args:
            text: The raw prompt string.
            
        Returns:
            A list of dictionaries containing found entities, confidence, starts, and ends.
        """
        detected_items = []
        
        if not settings.REDACT_PII:
            return detected_items

        for entity_type in self.active_entities:
            pattern = self.patterns.get(entity_type)
            if not pattern:
                continue

            for match in pattern.finditer(text):
                detected_items.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    "value": match.group(),
                    "confidence": 1.0,  # Regex matches have absolute confidence in this skeleton
                })

        # Add structural hook for enterprise NLP system integrations (e.g. Microsoft Presidio Analyzer)
        # self._run_presidio_analyzer(text, detected_items)

        return detected_items

    def redact_text(self, text: str) -> Tuple[str, List[Dict]]:
        """
        Redacts detected PII fields from the text.
        
        Args:
            text: The original prompt.
            
        Returns:
            A tuple of (redacted_text, list_of_redacted_entities_metadata).
        """
        if not settings.REDACT_PII:
            return text, []

        entities = self.detect_entities(text)
        if not entities:
            return text, []

        # Sort entities by start index descending to replace from end to front (avoids offset shifts)
        entities.sort(key=lambda x: x["start"], reverse=True)
        
        redacted_text = text
        redacted_log_metadata = []

        for entity in entities:
            placeholder = f"{settings.PII_REDACTION_PLACEHOLDER}_{entity['entity_type']}"
            
            # Replace characters in range
            start = entity["start"]
            end = entity["end"]
            redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]
            
            # Save metadata for security audit logs (without storing the actual sensitive values)
            redacted_log_metadata.append({
                "entity_type": entity["entity_type"],
                "confidence": entity["confidence"],
                "character_length": end - start
            })

        return redacted_text, redacted_log_metadata

    def _run_presidio_analyzer(self, text: str, existing_matches: List[Dict]) -> None:
        """
        Skeleton hook for Presidio Analyzer engine.
        Example integration code for Enterprise deployment.
        """
        # from presidio_analyzer import AnalyzerEngine
        # analyzer = AnalyzerEngine()
        # results = analyzer.analyze(text=text, language="en", entities=self.active_entities)
        # ...
        pass
