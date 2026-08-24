"""Minimal JSON logging with a reusable redaction boundary."""

import json
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ai_business_automation.logging.context import current_request_context

_SENSITIVE_FRAGMENTS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "credential",
)
_MAX_DEPTH = 4
_MAX_FIELDS = 32
_MAX_ITEMS = 20
_MAX_KEY_LENGTH = 64
_MAX_VALUE_LENGTH = 256
_MAX_LOG_BYTES = 4_096
_BOUNDED_MARKER = "[TRUNCATED]"
_SAFE_EVENT_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ALLOWED_EXTRA = (
    "request_id",
    "actor_id",
    "role",
    "operation",
    "endpoint_category",
    "outcome",
    "status_class",
    "event_id",
    "event_type",
    "source",
    "category",
    "error_category",
    "failure_category",
    "provider",
    "latency_ms",
    "duration_ms",
    "decision",
    "action",
    "risk",
    "policy_version",
    "approval_id",
    "status",
    "execution_id",
    "result_code",
)


def redact(value: Any) -> Any:
    """Recursively redact and bound nested structured values."""

    budget = [_MAX_FIELDS]
    return _redact(value, depth=0, budget=budget)


def _redact(value: Any, *, depth: int, budget: list[int]) -> Any:
    if depth > _MAX_DEPTH:
        return _BOUNDED_MARKER

    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if budget[0] <= 0:
                cleaned[_BOUNDED_MARKER] = _BOUNDED_MARKER
                break
            budget[0] -= 1
            safe_key = str(key)[:_MAX_KEY_LENGTH]
            lowered = safe_key.lower()
            cleaned[safe_key] = (
                "[REDACTED]"
                if any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS)
                else _redact(item, depth=depth + 1, budget=budget)
            )
        return cleaned
    if isinstance(value, list):
        return _redact_sequence(value, depth=depth, budget=budget)
    if isinstance(value, tuple):
        return tuple(_redact_sequence(value, depth=depth, budget=budget))
    if isinstance(value, str):
        return value[:_MAX_VALUE_LENGTH] if len(value) <= _MAX_VALUE_LENGTH else _BOUNDED_MARKER
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[UNSUPPORTED]"


def _redact_sequence(
    value: list[Any] | tuple[Any, ...], *, depth: int, budget: list[int]
) -> list[Any]:
    cleaned: list[Any] = []
    for item in value[:_MAX_ITEMS]:
        if budget[0] <= 0:
            cleaned.append(_BOUNDED_MARKER)
            break
        budget[0] -= 1
        cleaned.append(_redact(item, depth=depth + 1, budget=budget))
    return cleaned


class JsonFormatter(logging.Formatter):
    """Serialize a deliberately small set of log record attributes."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "event": _event_name(record.getMessage()),
        }
        context = current_request_context()
        if context is not None:
            data["request_id"] = context.request_id
            if context.actor_id is not None:
                data["actor_id"] = context.actor_id
            if context.role is not None:
                data["role"] = context.role
        for field in _ALLOWED_EXTRA:
            if hasattr(record, field):
                data[field] = str(getattr(record, field))[:128]
        serialized = json.dumps(redact(data), separators=(",", ":"), ensure_ascii=True)
        while len(serialized.encode("utf-8")) > _MAX_LOG_BYTES and len(data) > 3:
            data.popitem()
            serialized = json.dumps(redact(data), separators=(",", ":"), ensure_ascii=True)
        return serialized


def _event_name(message: str) -> str:
    return message if _SAFE_EVENT_NAME.fullmatch(message) else "unclassified_event"


def configure_logging(level: str) -> None:
    """Configure only the application's logger without exposing global internals."""

    logger = logging.getLogger("ai_business_automation")
    logger.setLevel(level)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
