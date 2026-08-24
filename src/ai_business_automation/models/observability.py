"""Closed, bounded operational visibility models."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class FailureCategory(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    POLICY_FAILURE = "POLICY_FAILURE"
    APPROVAL_FAILURE = "APPROVAL_FAILURE"
    EXECUTION_FAILURE = "EXECUTION_FAILURE"
    GHL_AUTHENTICATION = "GHL_AUTHENTICATION"
    GHL_RATE_LIMIT = "GHL_RATE_LIMIT"
    GHL_BAD_REQUEST = "GHL_BAD_REQUEST"
    GHL_UNAVAILABLE = "GHL_UNAVAILABLE"
    GHL_TIMEOUT = "GHL_TIMEOUT"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"
    AI_FAILURE = "AI_FAILURE"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class MetricName(StrEnum):
    REQUESTS_TOTAL = "requests_total"
    REQUESTS_FAILED = "requests_failed"
    POLICY_DECISIONS_ALLOW = "policy_decisions_allow"
    POLICY_DECISIONS_APPROVAL = "policy_decisions_approval"
    POLICY_DECISIONS_DENY = "policy_decisions_deny"
    APPROVALS_CREATED = "approvals_created"
    APPROVALS_APPROVED = "approvals_approved"
    APPROVALS_REJECTED = "approvals_rejected"
    APPROVALS_EXPIRED = "approvals_expired"
    EXECUTIONS_STARTED = "executions_started"
    EXECUTIONS_SUCCEEDED = "executions_succeeded"
    EXECUTIONS_FAILED = "executions_failed"
    EXECUTIONS_UNKNOWN = "executions_unknown"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"


class ReadinessStatus(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"


class LatencyMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    count: int = Field(ge=0)
    total_ms: int = Field(ge=0)
    minimum_ms: int = Field(ge=0)
    maximum_ms: int = Field(ge=0)


class OperationalMetricSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    requests_total: int = Field(ge=0)
    requests_failed: int = Field(ge=0)
    policy_decisions_allow: int = Field(ge=0)
    policy_decisions_approval: int = Field(ge=0)
    policy_decisions_deny: int = Field(ge=0)
    approvals_created: int = Field(ge=0)
    approvals_approved: int = Field(ge=0)
    approvals_rejected: int = Field(ge=0)
    approvals_expired: int = Field(ge=0)
    executions_started: int = Field(ge=0)
    executions_succeeded: int = Field(ge=0)
    executions_failed: int = Field(ge=0)
    executions_unknown: int = Field(ge=0)
    authentication_success: int = Field(ge=0)
    authentication_failure: int = Field(ge=0)
    request_latency: LatencyMetrics
