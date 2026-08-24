"""Strict internal action and execution boundary models."""

from datetime import UTC
from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from ai_business_automation.models.approvals import ActorId, ApprovalId, EventId, Sha256Hex
from ai_business_automation.models.ghl import GHLAddContactTagParameters
from ai_business_automation.models.policy import RecommendedAction, RiskLevel


class ExecutionAction(StrEnum):
    NO_OP = "NO_OP"
    CREATE_INTERNAL_TASK = "CREATE_INTERNAL_TASK"
    UPDATE_INTERNAL_STATUS = "UPDATE_INTERNAL_STATUS"
    REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"
    GENERATE_INTERNAL_NOTE = "GENERATE_INTERNAL_NOTE"
    GHL_ADD_CONTACT_TAG = "GHL_ADD_CONTACT_TAG"


class ExecutionStatus(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    RECONCILED_SUCCEEDED = "RECONCILED_SUCCEEDED"
    RECONCILED_FAILED = "RECONCILED_FAILED"


class ExecutionResultCode(StrEnum):
    COMPLETED = "COMPLETED"
    DEFINITIVE_FAILURE = "DEFINITIVE_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECONCILED = "RECONCILED"


class ExecutionFailureCategory(StrEnum):
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"
    INTERNAL_UNKNOWN = "INTERNAL_UNKNOWN"
    GHL_AUTHENTICATION = "GHL_AUTHENTICATION"
    GHL_AUTHORIZATION = "GHL_AUTHORIZATION"
    GHL_RATE_LIMIT = "GHL_RATE_LIMIT"
    GHL_VALIDATION = "GHL_VALIDATION"
    GHL_NOT_FOUND = "GHL_NOT_FOUND"
    GHL_TIMEOUT = "GHL_TIMEOUT"
    GHL_NETWORK = "GHL_NETWORK"
    GHL_SERVER_ERROR = "GHL_SERVER_ERROR"
    GHL_UNKNOWN = "GHL_UNKNOWN"


class InternalPriority(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class InternalStatus(StrEnum):
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


type ExecutionId = Annotated[
    str, Field(min_length=24, max_length=40, pattern=r"^exe_[A-Za-z0-9_-]+$")
]
type InternalObjectId = Annotated[
    str, Field(min_length=24, max_length=48, pattern=r"^(?:tsk|nte|rev)_[a-f0-9]{24,40}$")
]
type SafeSummary = Annotated[str, Field(min_length=1, max_length=200)]


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
    status: ExecutionStatus
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    result_code: ExecutionResultCode | None = None
    safe_summary: SafeSummary | None = None
    actor_id: ActorId
    failure_category: ExecutionFailureCategory | None = None
    reconciled_at: AwareDatetime | None = None
    reconciler_id: ActorId | None = None
    reconciliation_hash: Sha256Hex | None = None

    def public(self) -> "ExecutionResponse":
        return ExecutionResponse(
            execution_id=self.execution_id,
            approval_id=self.approval_id,
            event_id=self.event_id,
            action=self.action,
            status=self.status,
            started_at=self.started_at,
            completed_at=self.completed_at,
            result_code=self.result_code,
            safe_summary=self.safe_summary,
        )

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ExecutionRecord":
        for value in (self.started_at, self.completed_at):
            if value is not None and value.utcoffset() != UTC.utcoffset(value):
                raise ValueError("execution timestamps must use UTC")
        terminal = self.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.UNKNOWN,
            ExecutionStatus.RECONCILED_SUCCEEDED,
            ExecutionStatus.RECONCILED_FAILED,
        }
        if terminal != (self.completed_at is not None):
            raise ValueError("execution completion timestamp does not match status")
        if terminal != (self.result_code is not None and self.safe_summary is not None):
            raise ValueError("execution result metadata does not match status")
        expected_code = {
            ExecutionStatus.SUCCEEDED: ExecutionResultCode.COMPLETED,
            ExecutionStatus.FAILED: ExecutionResultCode.DEFINITIVE_FAILURE,
            ExecutionStatus.UNKNOWN: ExecutionResultCode.OUTCOME_UNKNOWN,
            ExecutionStatus.RECONCILED_SUCCEEDED: ExecutionResultCode.RECONCILED,
            ExecutionStatus.RECONCILED_FAILED: ExecutionResultCode.RECONCILED,
        }.get(self.status)
        if expected_code is not None and self.result_code is not expected_code:
            raise ValueError("execution result code does not match status")
        reconciled = self.status in {
            ExecutionStatus.RECONCILED_SUCCEEDED,
            ExecutionStatus.RECONCILED_FAILED,
        }
        reconciliation_values = (self.reconciled_at, self.reconciler_id, self.reconciliation_hash)
        if (reconciled and not all(value is not None for value in reconciliation_values)) or (
            not reconciled and any(value is not None for value in reconciliation_values)
        ):
            raise ValueError("execution reconciliation metadata does not match status")
        if self.reconciled_at is not None and self.reconciled_at.utcoffset() != UTC.utcoffset(
            self.reconciled_at
        ):
            raise ValueError("reconciliation timestamp must use UTC")
        return self


class ExecutionResponse(BaseModel):
    """Safe execution metadata without internal effects or actor configuration."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    execution_id: ExecutionId
    approval_id: ApprovalId
    event_id: EventId
    action: ExecutionAction
    status: ExecutionStatus
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    result_code: ExecutionResultCode | None = None
    safe_summary: SafeSummary | None = None


class ActionContext(BaseModel):
    """Trusted server-reconstructed action context."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    execution_id: ExecutionId
    approval_id: ApprovalId
    event_id: EventId
    action: ExecutionAction
    risk: RiskLevel
    started_at: AwareDatetime
    action_parameters: GHLAddContactTagParameters | None = None

    @model_validator(mode="after")
    def validate_action_parameters(self) -> "ActionContext":
        requires_parameters = self.action is ExecutionAction.GHL_ADD_CONTACT_TAG
        if requires_parameters != (self.action_parameters is not None):
            raise ValueError("execution action parameters do not match the action")
        return self


class NoOpInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InternalTaskInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    title: Annotated[str, Field(min_length=1, max_length=200)]
    description: Annotated[str, Field(min_length=1, max_length=1000)]
    priority: InternalPriority


class InternalStatusInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    internal_reference: EventId
    status: InternalStatus


class HumanReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    approval_id: ApprovalId
    event_id: EventId
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class InternalNoteInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    text: Annotated[str, Field(min_length=1, max_length=1000)]


class InternalActionEffect(BaseModel):
    """Bounded local effect persisted atomically with successful completion."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    object_id: InternalObjectId | None = None
    object_type: Annotated[
        str, Field(pattern=r"^(?:NONE|INTERNAL_TASK|INTERNAL_STATUS|HUMAN_REVIEW|INTERNAL_NOTE)$")
    ]
    content: Annotated[str, Field(min_length=1, max_length=1000)]


class ActionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    result_code: Annotated[str, Field(pattern=r"^COMPLETED$")]
    safe_summary: SafeSummary
    effect: InternalActionEffect | None = None


def execution_action_for(recommendation: RecommendedAction) -> ExecutionAction:
    """Closed policy-to-execution mapping; no runtime registration is possible."""

    return {
        RecommendedAction.NONE: ExecutionAction.NO_OP,
        RecommendedAction.REVIEW: ExecutionAction.UPDATE_INTERNAL_STATUS,
        RecommendedAction.CONTACT_HUMAN: ExecutionAction.REQUEST_HUMAN_REVIEW,
        RecommendedAction.REQUEST_INFORMATION: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.ESCALATE: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.SCHEDULE_CONSULTATION: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.NURTURE: ExecutionAction.GENERATE_INTERNAL_NOTE,
        RecommendedAction.GHL_ADD_CONTACT_TAG: ExecutionAction.GHL_ADD_CONTACT_TAG,
    }[recommendation]
