"""Strict models for the untrusted business-event boundary."""

import json
import math
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


def _validate_payload(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds the serialized size limit")

    fields = 0
    nodes = 0

    def visit(item: JsonValue, depth: int) -> None:
        nonlocal fields, nodes
        nodes += 1
        if nodes > MAX_PAYLOAD_NODES:
            raise ValueError("payload contains too many values")
        if depth > MAX_PAYLOAD_DEPTH:
            raise ValueError("payload nesting is too deep")
        if isinstance(item, dict):
            if len(item) > MAX_FIELDS_PER_OBJECT:
                raise ValueError("payload object contains too many fields")
            fields += len(item)
            if fields > MAX_PAYLOAD_FIELDS:
                raise ValueError("payload contains too many fields")
            for key, child in item.items():
                if not key or len(key) > 64 or not _SAFE_NAME.fullmatch(key):
                    raise ValueError("payload field name is invalid")
                if _FORBIDDEN_KEYS.search(key):
                    raise ValueError("payload contains a prohibited control or credential field")
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > MAX_ARRAY_ITEMS:
                raise ValueError("payload array contains too many items")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > MAX_STRING_LENGTH:
                raise ValueError("payload string is too long")
            if any(ord(character) < 32 and character not in "\t\n\r" for character in item):
                raise ValueError("payload contains unsupported control characters")
            if _URL_VALUE.search(item):
                raise ValueError("payload contains a URL")
            if _CREDENTIAL_VALUE.search(item):
                raise ValueError("payload contains credential-like data")
            if _COMMAND_VALUE.search(item):
                raise ValueError("payload contains command-like instructions")
        elif isinstance(item, float) and (not math.isfinite(item) or abs(item) > 1e12):
            raise ValueError("payload number is outside the supported range")
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) > 10**15:
            raise ValueError("payload integer is outside the supported range")

    visit(value, 0)
    return value


class BusinessEvent(BaseModel):
    """A bounded event accepted as data and never as instructions."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_type: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    source: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    payload: dict[str, JsonValue]

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """Enforce recursive limits and reject capability-bearing content."""

        return _validate_payload(value)


class EventAcknowledgement(BaseModel):
    """Safe acknowledgement that deliberately excludes event contents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    accepted: bool
    event_type: str
