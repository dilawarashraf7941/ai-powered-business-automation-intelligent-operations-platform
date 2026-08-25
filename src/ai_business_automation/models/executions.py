"""Strict models for one approval-bound contact-tag execution."""

from datetime import UTC
from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from ai_business_automation.models.approvals import ActorId, ApprovalId, EventId


class ExecutionAction(StrEnum):
    ADD_CONTACT_TAG = "ADD_CONTACT_TAG"


class ExecutionStatus(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ExecutionFailureCategory(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    ALREADY_EXECUTED = "ALREADY_EXECUTED"
    PROVIDER_AUTHENTICATION = "PROVIDER_AUTHENTICATION"
    PROVIDER_RATE_LIMIT = "PROVIDER_RATE_LIMIT"
    PROVIDER_BAD_REQUEST = "PROVIDER_BAD_REQUEST"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    PERSISTENCE_ERROR = "PERSISTENCE_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


type ExecutionId = Annotated[
    str, Field(min_length=24, max_length=40, pattern=r"^exe_[A-Za-z0-9_-]+$")
]


class ExecutionRequest(BaseModel):
    """The only client-controlled execution field is a bounded approval reference."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    approval_id: ApprovalId


class ExecutionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    execution_id: ExecutionId
    approval_id: ApprovalId
    event_id: EventId
    action: ExecutionAction
    contact_id: str = Field(min_length=10, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    tag: str = Field(min_length=1, max_length=50)
    status: ExecutionStatus
    created_at: AwareDatetime
    claimed_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    failure_category: ExecutionFailureCategory | None = None
    provenance_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_version: str = Field(pattern=r"^1\.0$")
    actor_id: ActorId

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ExecutionRecord":
        for value in (self.created_at, self.claimed_at, self.completed_at):
            if value is not None and value.utcoffset() != UTC.utcoffset(value):
                raise ValueError("execution timestamps must use UTC")
        terminal = self.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.UNKNOWN,
        }
        if terminal != (self.completed_at is not None):
            raise ValueError("execution completion timestamp does not match status")
        if self.status is ExecutionStatus.SUCCEEDED and self.failure_category is not None:
            raise ValueError("successful execution cannot contain a failure category")
        if (
            self.status in {ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}
            and self.failure_category is None
        ):
            raise ValueError("failed or unknown execution requires a failure category")
        return self

    def public(self) -> "ExecutionResponse":
        return ExecutionResponse(
            execution_id=self.execution_id,
            status=self.status,
            action=self.action,
        )


class ExecutionResponse(BaseModel):
    """Minimal safe response without provider, target, credential, or failure details."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    execution_id: ExecutionId
    status: ExecutionStatus
    action: ExecutionAction
