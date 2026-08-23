"""Tests for bounded structured logs and reusable redaction."""

import json
import logging

from ai_business_automation.logging import JsonFormatter, configure_logging, redact


def test_recursive_redaction() -> None:
    source = {
        "password": "one",
        "nested": {"api_key": "two", "safe": "visible"},
        "items": [{"token": "three"}],
        "tuple": ({"secret": "four"},),
    }
    cleaned = redact(source)
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["nested"]["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["safe"] == "visible"
    assert cleaned["items"][0]["token"] == "[REDACTED]"
    assert cleaned["tuple"][0]["secret"] == "[REDACTED]"


def test_formatter_uses_allowlist_and_bounds_fields() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "x" * 200, (), None)
    record.request_id = "r" * 200
    record.untrusted_payload = "must-not-appear"
    result = json.loads(JsonFormatter().format(record))
    assert len(result["event"]) == 128
    assert len(result["request_id"]) == 128
    assert "untrusted_payload" not in result
    assert result["level"] == "INFO"
    assert result["timestamp"].endswith("+00:00")


def test_logging_configuration_is_idempotent() -> None:
    configure_logging("WARNING")
    configure_logging("INFO")
    logger = logging.getLogger("ai_business_automation")
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    assert logger.propagate is False
