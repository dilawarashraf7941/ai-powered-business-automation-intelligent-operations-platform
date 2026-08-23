"""Canonical event normalization with bounded clock skew and server identity."""

import copy
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from ai_business_automation.models import (
    CanonicalBusinessEvent,
    ExternalEvent,
    InternalEventMetadata,
)

MAX_PAST_SKEW = timedelta(days=365)
MAX_FUTURE_SKEW = timedelta(minutes=5)


class EventNormalizationError(Exception):
    """Base error whose code is safe to expose to clients."""

    code = "NORMALIZATION_ERROR"


class InvalidTimestampError(EventNormalizationError):
    code = "INVALID_TIMESTAMP"


def utc_now() -> datetime:
    return datetime.now(UTC)


def generate_event_id() -> str:
    return f"evt_{secrets.token_urlsafe(18)}"


@dataclass(frozen=True, slots=True)
class EventNormalizer:
    """Convert validated external data into a canonical internal event."""

    clock: Callable[[], datetime] = utc_now
    event_id_factory: Callable[[], str] = generate_event_id

    def normalize(self, external: ExternalEvent) -> CanonicalBusinessEvent:
        received_at = self.clock()
        if received_at.tzinfo is None or received_at.utcoffset() is None:
            raise EventNormalizationError
        received_at = received_at.astimezone(UTC)
        occurred_at = external.occurred_at.astimezone(UTC)
        if occurred_at < received_at - MAX_PAST_SKEW:
            raise InvalidTimestampError
        if occurred_at > received_at + MAX_FUTURE_SKEW:
            raise InvalidTimestampError

        try:
            return CanonicalBusinessEvent(
                event_id=self.event_id_factory(),
                event_type=external.event_type,
                source=external.source,
                occurred_at=occurred_at,
                received_at=received_at,
                payload=copy.deepcopy(external.payload),
                metadata=InternalEventMetadata(
                    external_event_reference=external.external_event_reference
                ),
            )
        except ValidationError as exc:
            raise EventNormalizationError from exc
