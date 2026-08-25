"""Strict append-only external assessment models for UNKNOWN executions."""

import re
import unicodedata
from datetime import UTC
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from ai_business_automation.models.approvals import ActorId, ApprovalId, Sha256Hex
from ai_business_automation.models.executions import ExecutionId, ExecutionStatus

MAX_RECONCILIATION_REASON_LENGTH = 500
_SAFE_REASON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,;:'()_-]*$")
_PROHIBITED_REASON = re.compile(
    r"(?:https?://|ftp://|file://|www\.|\bBearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{10,}|private[ _-]?key|```|\$\(|`|"
    r"(?:^|\s)(?:bash|sh|cmd|powershell|pwsh|curl|wget|sudo|rm|python|node)\s+)",
    re.IGNORECASE,
)


class ReconciliationOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


type AssessmentId = Annotated[
    str, Field(min_length=24, max_length=40, pattern=r"^rcn_[A-Za-z0-9_-]+$")
]
type ReconciliationReason = Annotated[
    str, Field(min_length=1, max_length=MAX_RECONCILIATION_REASON_LENGTH)
]


class ReconciliationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    outcome: ReconciliationOutcome
    reason: ReconciliationReason

    @field_validator("outcome", mode="before")
    @classmethod
    def parse_outcome(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return ReconciliationOutcome(value)
        except ValueError as exc:
            raise PydanticCustomError(
                "unsupported_reconciliation_outcome",
                "unsupported reconciliation outcome",
            ) from exc

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        sanitized = value.strip()
        if (
            not sanitized
            or sanitized != value
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
            or not _SAFE_REASON.fullmatch(sanitized)
            or _PROHIBITED_REASON.search(sanitized)
        ):
            raise ValueError("reconciliation reason contains prohibited content")
        return sanitized


class ReconciliationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    assessment_id: AssessmentId
    execution_id: ExecutionId
    approval_id: ApprovalId
    provenance_hash: Sha256Hex
    policy_version: Annotated[str, Field(pattern=r"^1\.0$")]
    original_execution_integrity_hash: Sha256Hex
    actor_id: ActorId
    occurred_at: AwareDatetime
    declared_outcome: ReconciliationOutcome
    reason: ReconciliationReason
    previous_assessment_hash: Sha256Hex
    assessment_hash: Sha256Hex

    @model_validator(mode="after")
    def validate_timestamp(self) -> "ReconciliationRecord":
        if self.occurred_at.utcoffset() != UTC.utcoffset(self.occurred_at):
            raise ValueError("reconciliation timestamp must use UTC")
        return self

    def public(self) -> "ReconciliationResponse":
        return ReconciliationResponse(
            assessment_id=self.assessment_id,
            execution_id=self.execution_id,
            execution_status=ExecutionStatus.UNKNOWN,
            declared_outcome=self.declared_outcome,
            recorded_at=self.occurred_at,
            actor_id=self.actor_id,
        )


class ReconciliationResponse(BaseModel):
    """Safe assessment result; the execution itself remains permanently UNKNOWN."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    assessment_id: AssessmentId
    execution_id: ExecutionId
    execution_status: Literal[ExecutionStatus.UNKNOWN]
    declared_outcome: ReconciliationOutcome
    recorded_at: AwareDatetime
    actor_id: ActorId
