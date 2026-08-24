"""Trusted server-derived authentication and authorization models."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from ai_business_automation.models.approvals import ActorId


class AuthRole(StrEnum):
    READ_ONLY = "READ_ONLY"
    APPROVER = "APPROVER"
    EXECUTOR = "EXECUTOR"
    ADMIN = "ADMIN"


class AuthenticatedActor(BaseModel):
    """Identity created only by successful server-side token verification."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    actor_id: ActorId
    role: AuthRole


class SecurityAuditEventType(StrEnum):
    AUTHENTICATION_SUCCEEDED = "AUTHENTICATION_SUCCEEDED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    APPROVAL_AUTHORIZED = "APPROVAL_AUTHORIZED"
    APPROVAL_REJECTED_BY_AUTHZ = "APPROVAL_REJECTED_BY_AUTHZ"
    ACTION_EXECUTION_AUTHORIZED = "ACTION_EXECUTION_AUTHORIZED"
    ACTION_EXECUTION_REJECTED_BY_AUTHZ = "ACTION_EXECUTION_REJECTED_BY_AUTHZ"
