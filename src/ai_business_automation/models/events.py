"""Strict models for the untrusted business-event boundary."""

import json
import math
import re
from datetime import UTC, datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from ai_business_automation.models.ghl import GHLAddContactTagParameters
from ai_business_automation.models.taxonomy import EventCategory, EventSource, EventType

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

MAX_PAYLOAD_BYTES = 4_096
MAX_PAYLOAD_DEPTH = 4
MAX_PAYLOAD_FIELDS = 50
MAX_FIELDS_PER_OBJECT = 20
MAX_ARRAY_ITEMS = 20
MAX_PAYLOAD_NODES = 100
MAX_STRING_LENGTH = 500

_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_FORBIDDEN_KEYS = re.compile(
    r"(^|_)(cmd|command|shell|execute|execution|exec|eval|code|script|instruction|"
    r"instructions|prompt|action|actions|tool|function|"
    r"url|uri|endpoint|callback|webhook|password|passwd|secret|token|api_key|apikey|"
    r"authorization|credential|private_key)($|_)",
    re.IGNORECASE,
)
_URL_VALUE = re.compile(r"(?:https?://|ftp://|file://|data:|javascript:)", re.IGNORECASE)
_CREDENTIAL_VALUE = re.compile(
    r"(?:\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bsk-[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
_COMMAND_VALUE = re.compile(
    r"(?:^|\s)(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh|curl|wget|sudo|rm|del|"
    r"remove-item|invoke-expression|python|node)\s+|"
    r"(?:&&|\|\||;\s*(?:rm|del|curl|wget|sh|cmd)\b)|`[^`]+`|\$\(",
    re.IGNORECASE,
)


class PayloadLimitError(ValueError):
    """Payload exceeded a server-owned structural or size limit."""


class UnsafePayloadError(ValueError):
    """Payload contained capability-bearing or sensitive content."""


def _validate_payload(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except ValueError as exc:
        raise UnsafePayloadError("payload contains an unsupported numeric value") from exc
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise PayloadLimitError("payload exceeds the serialized size limit")

    fields = 0
    nodes = 0

    def visit(item: JsonValue, depth: int) -> None:
        nonlocal fields, nodes
        nodes += 1
        if nodes > MAX_PAYLOAD_NODES:
            raise PayloadLimitError("payload contains too many values")
        if depth > MAX_PAYLOAD_DEPTH:
            raise PayloadLimitError("payload nesting is too deep")
        if isinstance(item, dict):
            if len(item) > MAX_FIELDS_PER_OBJECT:
                raise PayloadLimitError("payload object contains too many fields")
            fields += len(item)
            if fields > MAX_PAYLOAD_FIELDS:
                raise PayloadLimitError("payload contains too many fields")
            for key, child in item.items():
                if not key or len(key) > 64 or not _SAFE_NAME.fullmatch(key):
                    raise UnsafePayloadError("payload field name is invalid")
                if _FORBIDDEN_KEYS.search(key):
                    raise UnsafePayloadError(
                        "payload contains a prohibited control or credential field"
                    )
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > MAX_ARRAY_ITEMS:
                raise PayloadLimitError("payload array contains too many items")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > MAX_STRING_LENGTH:
                raise PayloadLimitError("payload string is too long")
            if any(ord(character) < 32 and character not in "\t\n\r" for character in item):
                raise UnsafePayloadError("payload contains unsupported control characters")
            if _URL_VALUE.search(item):
                raise UnsafePayloadError("payload contains a URL")
            if _CREDENTIAL_VALUE.search(item):
                raise UnsafePayloadError("payload contains credential-like data")
            if _COMMAND_VALUE.search(item):
                raise UnsafePayloadError("payload contains command-like instructions")
        elif isinstance(item, float) and (not math.isfinite(item) or abs(item) > 1e12):
            raise PayloadLimitError("payload number is outside the supported range")
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) > 10**15:
            raise PayloadLimitError("payload integer is outside the supported range")

    visit(value, 0)
    return value


class ExternalEvent(BaseModel):
    """A bounded external event accepted as data and never as instructions."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_type: EventType
    source: EventSource
    occurred_at: AwareDatetime
    external_event_reference: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    payload: dict[str, JsonValue]

    @field_validator("event_type", mode="before")
    @classmethod
    def parse_event_type(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return EventType(value)
        except ValueError as exc:
            raise PydanticCustomError("unsupported_event_type", "unsupported event type") from exc

    @field_validator("source", mode="before")
    @classmethod
    def parse_source(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return EventSource(value)
        except ValueError as exc:
            raise PydanticCustomError("unsupported_source", "unsupported event source") from exc

    @field_validator("occurred_at", mode="before")
    @classmethod
    def parse_occurred_at(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if not value or len(value) > 64:
            raise PydanticCustomError("invalid_timestamp", "invalid event timestamp")
        normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
        try:
            return datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise PydanticCustomError("invalid_timestamp", "invalid event timestamp") from exc

    @field_validator("external_event_reference")
    @classmethod
    def validate_external_reference(cls, value: str | None) -> str | None:
        if value is not None and _CREDENTIAL_VALUE.search(value):
            raise UnsafePayloadError("external reference resembles credential data")
        return value

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """Enforce recursive limits and reject capability-bearing content."""

        return _validate_payload(value)

    @model_validator(mode="after")
    def validate_external_operation(self) -> "ExternalEvent":
        if self.event_type is EventType.GHL_CONTACT_TAG_REQUEST:
            if self.source is not EventSource.INTERNAL:
                raise UnsafePayloadError("GHL mutation requests require the internal event source")
            GHLAddContactTagParameters.model_validate(self.payload)
        return self


class InternalEventMetadata(BaseModel):
    """Server-shaped metadata; clients cannot provide this object."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    external_event_reference: str | None = None


class CanonicalBusinessEvent(BaseModel):
    """Safe canonical representation used only inside the application boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_id: str = Field(min_length=20, max_length=40, pattern=r"^evt_[A-Za-z0-9_-]+$")
    event_type: EventType
    source: EventSource
    occurred_at: AwareDatetime
    received_at: AwareDatetime
    payload: dict[str, JsonValue]
    metadata: InternalEventMetadata

    @field_validator("occurred_at", "received_at")
    @classmethod
    def normalize_internal_datetime(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("canonical datetimes must use UTC")
        return value.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def validate_internal_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return _validate_payload(value)

    @model_validator(mode="after")
    def validate_external_operation(self) -> "CanonicalBusinessEvent":
        if self.event_type is EventType.GHL_CONTACT_TAG_REQUEST:
            if self.source is not EventSource.INTERNAL:
                raise UnsafePayloadError("GHL mutation requests require the internal event source")
            GHLAddContactTagParameters.model_validate(self.payload)
        return self


class EventAcknowledgement(BaseModel):
    """Safe acknowledgement that deliberately excludes event contents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    accepted: bool
    event_id: str
    event_type: EventType
    category: EventCategory
    received_at: AwareDatetime
