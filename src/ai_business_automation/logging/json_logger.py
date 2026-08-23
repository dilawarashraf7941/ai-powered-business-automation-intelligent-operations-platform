"""Minimal JSON logging with a reusable redaction boundary."""

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_FRAGMENTS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
)
_ALLOWED_EXTRA = (
    "request_id",
    "operation",
    "outcome",
    "status_class",
    "event_id",
    "event_type",
    "source",
    "category",
    "error_category",
    "provider",
    "latency_ms",
)


def redact(value: Any) -> Any:
    """Recursively redact values whose keys suggest sensitive material."""

    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if any(fragment in str(key).lower() for fragment in _SENSITIVE_FRAGMENTS)
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


class JsonFormatter(logging.Formatter):
    """Serialize a deliberately small set of log record attributes."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "event": record.getMessage()[:128],
        }
        for field in _ALLOWED_EXTRA:
            if hasattr(record, field):
                data[field] = str(getattr(record, field))[:128]
        return json.dumps(redact(data), separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: str) -> None:
    """Configure only the application's logger without exposing global internals."""

    logger = logging.getLogger("ai_business_automation")
    logger.setLevel(level)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
