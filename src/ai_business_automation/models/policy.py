"""Strict server-authoritative policy decision models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

POLICY_VERSION = "1.0"
DEFAULT_CONFIDENCE_THRESHOLD = 0.85
MAX_POLICY_EVIDENCE = 8


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    DENY = "DENY"


class RecommendedAction(StrEnum):
    NONE = "NONE"
    REVIEW = "REVIEW"
    CONTACT_HUMAN = "CONTACT_HUMAN"
    REQUEST_INFORMATION = "REQUEST_INFORMATION"
    ESCALATE = "ESCALATE"
    SCHEDULE_CONSULTATION = "SCHEDULE_CONSULTATION"
    NURTURE = "NURTURE"
    GHL_ADD_CONTACT_TAG = "GHL_ADD_CONTACT_TAG"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceCode(StrEnum):
    NO_ACTION_RECOMMENDED = "NO_ACTION_RECOMMENDED"
    POLICY_CONDITIONS_SATISFIED = "POLICY_CONDITIONS_SATISFIED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    ELEVATED_PRIORITY = "ELEVATED_PRIORITY"
    HIGH_URGENCY = "HIGH_URGENCY"
    UNKNOWN_INTENT = "UNKNOWN_INTENT"
    RECOMMENDATION_REQUIRES_REVIEW = "RECOMMENDATION_REQUIRES_REVIEW"
    ESCALATION_RECOMMENDED = "ESCALATION_RECOMMENDED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    CATEGORY_MISMATCH = "CATEGORY_MISMATCH"
    MISSING_AI_EVIDENCE = "MISSING_AI_EVIDENCE"
    INVALID_POLICY_VERSION = "INVALID_POLICY_VERSION"
    CONFLICTING_NO_ACTION_SIGNALS = "CONFLICTING_NO_ACTION_SIGNALS"
    EXTERNAL_MUTATION_REQUIRES_APPROVAL = "EXTERNAL_MUTATION_REQUIRES_APPROVAL"


class EvidenceSource(StrEnum):
    AI_ANALYSIS = "AI_ANALYSIS"
    CANONICAL_EVENT = "CANONICAL_EVENT"
    POLICY = "POLICY"


type EvidenceText = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9_.-]+$")]
type EvidenceNumber = Annotated[float, Field(ge=0.0, le=1.0)]


class PolicyEvidence(BaseModel):
    """Bounded explanation derived only from validated trusted fields."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    code: EvidenceCode
    source: EvidenceSource
    value: EvidenceText | EvidenceNumber | None = None


class PolicyDecision(BaseModel):
    """Complete server-owned policy response; it never authorizes execution itself."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    decision: DecisionOutcome
    action: RecommendedAction
    risk: RiskLevel
    policy_version: Annotated[str, Field(pattern=r"^1\.0$")]
    confidence_threshold: float = Field(ge=0.0, le=1.0)
    evidence: list[PolicyEvidence] = Field(min_length=1, max_length=MAX_POLICY_EVIDENCE)
    event_id: str = Field(min_length=20, max_length=40, pattern=r"^evt_[A-Za-z0-9_-]+$")
    generated_at: AwareDatetime

    @field_validator("generated_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("policy timestamp must use UTC")
        return value.astimezone(UTC)
