"""
MIT License

Copyright (c) 2026 Acadify Solutions
"""

from proxy.redactor import PIIRedactor


def test_redact_email():
    redactor = PIIRedactor()
    text = "Please email support@acadify.com for help."
    redacted, metadata = redactor.redact_text(text)
    
    assert "support@acadify.com" not in redacted
    assert "[REDACTED]_EMAIL_ADDRESS" in redacted
    assert len(metadata) == 1
    assert metadata[0]["entity_type"] == "EMAIL_ADDRESS"


def test_redact_multiple_entities():
    redactor = PIIRedactor()
    text = "Contact 555-019-2831 or check 192.168.1.1."
    redacted, metadata = redactor.redact_text(text)
    
    assert "555-019-2831" not in redacted
    assert "192.168.1.1" not in redacted
    assert "[REDACTED]_PHONE_NUMBER" in redacted
    assert "[REDACTED]_IP_ADDRESS" in redacted
    assert len(metadata) == 2


def test_no_pii_clean():
    redactor = PIIRedactor()
    text = "Hello world, this is a clean prompt."
    redacted, metadata = redactor.redact_text(text)
    
    assert redacted == text
    assert len(metadata) == 0
