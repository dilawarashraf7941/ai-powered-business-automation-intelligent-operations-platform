"""Deterministic serialization for canonical internal events."""

import json

from ai_business_automation.models import CanonicalBusinessEvent
from ai_business_automation.services.normalization import EventNormalizationError

MAX_CANONICAL_EVENT_BYTES = 8_192


def canonical_event_bytes(event: CanonicalBusinessEvent) -> bytes:
    """Serialize with stable keys, enum values, UTC datetimes, and UTF-8 encoding."""

    serialized = json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(serialized) > MAX_CANONICAL_EVENT_BYTES:
        raise EventNormalizationError
    return serialized
