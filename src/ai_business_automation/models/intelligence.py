"""Strict advisory business-intelligence models."""

import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from pydantic_core import PydanticCustomError

from ai_business_automation.models.taxonomy import EventCategory

MAX_SUMMARY_LENGTH = 500
MAX_REASONS = 5
MAX_REASON_LENGTH = 250
MAX_AI_OUTPUT_BYTES = 4_096

_PROHIBITED_OUTPUT = re.compile(
    r"(?:https?://|ftp://|file://|data:|javascript:|```|\$\(|`[^`]+`|"
    r"(?:^|\s)(?:GET|POST|PUT|PATCH|DELETE)\s+/|"
    r"(?:^|\s)(?:bash|sh|cmd(?:\.exe)?|powershell|pwsh|curl|wget|sudo|rm|"
    r"remove-item|invoke-expression|python|node)\s+|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bsk-[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)


class Priority(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Urgency(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Intent(StrEnum):
    INFORMATION = "INFORMATION"
    PURCHASE = "PURCHASE"
    SUPPORT = "SUPPORT"
    COMPLAINT = "COMPLAINT"
    PAYMENT = "PAYMENT"
    ACCOUNT = "ACCOUNT"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class RecommendedNextStep(StrEnum):
    NO_ACTION = "NO_ACTION"
    REVIEW = "REVIEW"
    CONTACT_HUMAN = "CONTACT_HUMAN"
    REQUEST_INFORMATION = "REQUEST_INFORMATION"
    ESCALATE = "ESCALATE"
    SCHEDULE_CONSULTATION = "SCHEDULE_CONSULTATION"
    NURTURE = "NURTURE"


type Reason = Annotated[str, Field(min_length=1, max_length=MAX_REASON_LENGTH)]


class ProviderAnalysisOutput(BaseModel):
    """Exact structured output accepted from an untrusted AI provider."""

    model_config = ConfigDict(extra="forbid", strict=True)

    priority: Priority
    urgency: Urgency
    intent: Intent
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_LENGTH)
    reasons: list[Reason] = Field(max_length=MAX_REASONS)
    recommended_next_step: RecommendedNextStep

    @field_validator("priority", "urgency", "intent", "recommended_next_step", mode="before")
    @classmethod
    def parse_closed_enum(cls, value: object, info: ValidationInfo) -> object:
        if not isinstance(value, str):
            return value
        enum_by_field: dict[str, type[StrEnum]] = {
            "priority": Priority,
            "urgency": Urgency,
            "intent": Intent,
            "recommended_next_step": RecommendedNextStep,
        }
        field_name = info.field_name
        if field_name is None:
            raise PydanticCustomError("invalid_advisory_enum", "invalid advisory enum")
        enum_type = enum_by_field[field_name]
        try:
            return enum_type(value)
        except ValueError as exc:
            raise PydanticCustomError("invalid_advisory_enum", "invalid advisory enum") from exc

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return _validate_advisory_text(value)

    @field_validator("reasons")
    @classmethod
    def validate_reasons(cls, value: list[str]) -> list[str]:
        return [_validate_advisory_text(reason) for reason in value]


class BusinessIntelligenceResult(ProviderAnalysisOutput):
    """Advisory result with authoritative server-owned identity and category."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    event_id: str = Field(min_length=20, max_length=40, pattern=r"^evt_[A-Za-z0-9_-]+$")
    category: EventCategory


def _validate_advisory_text(value: str) -> str:
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValueError("advisory text contains unsupported control characters")
    if _PROHIBITED_OUTPUT.search(value):
        raise ValueError("advisory text contains prohibited capability-bearing content")
    return value
