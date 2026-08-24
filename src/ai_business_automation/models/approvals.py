"""Strict approval, provenance, transition, and audit models."""

import re
import unicodedata
from datetime import UTC
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ai_business_automation.models.policy import (
    DecisionOutcome,
    PolicyEvidence,
    RecommendedAction,
    RiskLevel,
)
from ai_business_automation.models.taxonomy import EventSource, EventType

MAX_REJECTION_REASON_LENGTH = 500
MAX_APPROVAL_EVIDENCE = 8
GENESIS_AUDIT_HASH = "0" * 64

_UNSAFE_REASON = re.compile(
    r"(?:https?://|ftp://|file://|data:|javascript:|```|\$\(|`[^`]+`|"
    r"(?:^|\s)(?:bash|sh|cmd(?:\.exe)?|powershell|pwsh|curl|wget|sudo|rm|"
    r"remove-item|invoke-expression|python|node)\s+|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bsk-[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class AuditEventType(StrEnum):
    APPROVAL_CREATED = "APPROVAL_CREATED"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_TRANSITION_REJECTED = "APPROVAL_TRANSITION_REJECTED"


type ApprovalId = Annotated[
    str, Field(min_length=24, max_length=40, pattern=r"^apr_[A-Za-z0-9_-]+$")
]
type AuditEventId = Annotated[
    str, Field(min_length=24, max_length=40, pattern=r"^aud_[A-Za-z0-9_-]+$")
]
type EventId = Annotated[str, Field(min_length=20, max_length=40, pattern=r"^evt_[A-Za-z0-9_-]+$")]
type ActorId = Annotated[
    str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
]
type Sha256Hex = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
type RejectionReason = Annotated[str, Field(min_length=1, max_length=MAX_REJECTION_REASON_LENGTH)]


class RejectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    reason: RejectionReason

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _validate_rejection_reason(value)


class EmptyApprovalTransitionRequest(BaseModel):
    """Strict empty body used to reject client-selected transition metadata."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class TrustedProvenance(BaseModel):
    """Canonical safe provenance; content-bearing representations remain digest-only."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    event_id: EventId
    event_type: EventType
    source: EventSource
    policy_version: Annotated[str, Field(pattern=r"^1\.0$")]
    decision: DecisionOutcome
    action: RecommendedAction
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[PolicyEvidence] = Field(min_length=1, max_length=MAX_APPROVAL_EVIDENCE)
    canonical_event_sha256: Sha256Hex
    canonical_intelligence_sha256: Sha256Hex


class ApprovalRecord(BaseModel):
    """Internal trusted approval record, including bounded policy evidence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    approval_id: ApprovalId
    event_id: EventId
    event_type: EventType
    source: EventSource
    policy_version: Annotated[str, Field(pattern=r"^1\.0$")]
    decision: DecisionOutcome
    action: RecommendedAction
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[PolicyEvidence] = Field(min_length=1, max_length=MAX_APPROVAL_EVIDENCE)
    status: ApprovalStatus
    created_at: AwareDatetime
    expires_at: AwareDatetime
    decided_at: AwareDatetime | None = None
    approver_id: ActorId | None = None
    rejection_reason: RejectionReason | None = None
    provenance_hash: Sha256Hex

    @field_validator("rejection_reason")
    @classmethod
    def validate_rejection_reason(cls, value: str | None) -> str | None:
        return _validate_rejection_reason(value) if value is not None else None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ApprovalRecord":
        for value in (self.created_at, self.expires_at, self.decided_at):
            if value is not None and value.utcoffset() != UTC.utcoffset(value):
                raise ValueError("approval timestamps must use UTC")
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiry must follow creation")
        if self.status is ApprovalStatus.PENDING:
            if self.decided_at is not None or self.approver_id is not None:
                raise ValueError("pending approval contains terminal metadata")
            if self.rejection_reason is not None:
                raise ValueError("pending approval contains rejection metadata")
        elif self.status is ApprovalStatus.APPROVED:
            if self.decided_at is None or self.approver_id is None:
                raise ValueError("approved record is missing decision metadata")
            if self.rejection_reason is not None:
                raise ValueError("approved record contains rejection metadata")
        elif self.status is ApprovalStatus.REJECTED:
            if self.decided_at is None or self.approver_id is None or self.rejection_reason is None:
                raise ValueError("rejected record is missing decision metadata")
        elif self.decided_at is None or self.approver_id is not None:
            raise ValueError("expired record has invalid terminal metadata")
        return self

    def public(self) -> "ApprovalResponse":
        return ApprovalResponse(
            approval_id=self.approval_id,
            status=self.status,
            event_id=self.event_id,
            decision=self.decision,
            action=self.action,
            risk=self.risk,
            policy_version=self.policy_version,
            created_at=self.created_at,
            expires_at=self.expires_at,
            decided_at=self.decided_at,
            approver_id=self.approver_id,
            provenance_hash=self.provenance_hash,
        )


class ApprovalResponse(BaseModel):
    """Safe public approval metadata without evidence or content-bearing input."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    approval_id: ApprovalId
    status: ApprovalStatus
    event_id: EventId
    decision: DecisionOutcome
    action: RecommendedAction
    risk: RiskLevel
    policy_version: Annotated[str, Field(pattern=r"^1\.0$")]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    decided_at: AwareDatetime | None = None
    approver_id: ActorId | None = None
    provenance_hash: Sha256Hex


class AuditEvent(BaseModel):
    """Append-only application audit event with a deterministic hash link."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    audit_event_id: AuditEventId
    approval_id: ApprovalId
    sequence_number: int = Field(ge=1, le=1_000_000)
    event_type: AuditEventType
    status: ApprovalStatus
    actor_id: ActorId
    occurred_at: AwareDatetime
    previous_event_hash: Sha256Hex
    event_hash: Sha256Hex

    @model_validator(mode="after")
    def validate_timestamp(self) -> "AuditEvent":
        if self.occurred_at.utcoffset() != UTC.utcoffset(self.occurred_at):
            raise ValueError("audit timestamp must use UTC")
        return self


def _validate_rejection_reason(value: str) -> str:
    sanitized = value.strip()
    if not sanitized:
        raise ValueError("rejection reason must not be blank")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("rejection reason contains unsupported control characters")
    if _UNSAFE_REASON.search(sanitized):
        raise ValueError("rejection reason contains prohibited content")
    return sanitized
