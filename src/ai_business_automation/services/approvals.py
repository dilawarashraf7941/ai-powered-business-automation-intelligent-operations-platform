"""Human approval orchestration with no action execution capability."""

import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ai_business_automation.models import (
    POLICY_VERSION,
    ApprovalRecord,
    ApprovalStatus,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    DecisionOutcome,
    RejectionRequest,
)
from ai_business_automation.repositories import ApprovalRepository
from ai_business_automation.services.approval_errors import PolicyValidationError
from ai_business_automation.services.policy import PolicyDecisionService
from ai_business_automation.services.provenance import (
    build_trusted_provenance,
    provenance_hash,
)

_LOGGER = logging.getLogger("ai_business_automation.approvals")


@dataclass(frozen=True, slots=True)
class ApprovalService:
    """Recompute policy, persist trusted approvals, and perform state transitions only."""

    repository: ApprovalRepository
    policy_service: PolicyDecisionService
    ttl_seconds: int
    approver_id: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    approval_id_factory: Callable[[], str] = lambda: f"apr_{secrets.token_urlsafe(18)}"

    def __post_init__(self) -> None:
        if not 60 <= self.ttl_seconds <= 86_400:
            raise ValueError("approval TTL is outside the supported range")

    def create(
        self,
        event: CanonicalBusinessEvent,
        intelligence: BusinessIntelligenceResult,
        actor_id: str | None = None,
    ) -> ApprovalRecord:
        decision = self.policy_service.decide(event, intelligence)
        if (
            decision.decision is not DecisionOutcome.REQUIRE_HUMAN_APPROVAL
            or decision.policy_version != POLICY_VERSION
            or decision.event_id != event.event_id
        ):
            raise PolicyValidationError
        now = _utc(self.clock())
        provenance = build_trusted_provenance(event, intelligence, decision)
        record = ApprovalRecord(
            approval_id=self.approval_id_factory(),
            event_id=event.event_id,
            event_type=event.event_type,
            source=event.source,
            policy_version=decision.policy_version,
            decision=decision.decision,
            action=decision.action,
            risk=decision.risk,
            confidence=intelligence.confidence,
            evidence=decision.evidence,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=self.ttl_seconds),
            provenance_hash=provenance_hash(provenance),
            action_parameters=provenance.action_parameters,
        )
        stored = (
            self.repository.create(record, provenance, now, actor_id)
            if actor_id is not None
            else self.repository.create(record, provenance, now)
        )
        self._log("approval_created", stored, "created")
        return stored

    def get(self, approval_id: str) -> ApprovalRecord:
        record = self.repository.get(approval_id, _utc(self.clock()))
        self._log("approval_read", record, "success")
        return record

    def approve(self, approval_id: str, actor_id: str | None = None) -> ApprovalRecord:
        record = self.repository.transition(
            approval_id,
            ApprovalStatus.APPROVED,
            _utc(self.clock()),
            actor_id or self.approver_id,
        )
        self._log("approval_approved", record, "success")
        return record

    def reject(self, approval_id: str, reason: str, actor_id: str | None = None) -> ApprovalRecord:
        validated_reason = RejectionRequest(reason=reason).reason
        record = self.repository.transition(
            approval_id,
            ApprovalStatus.REJECTED,
            _utc(self.clock()),
            actor_id or self.approver_id,
            rejection_reason=validated_reason,
        )
        self._log("approval_rejected", record, "success")
        return record

    def verify_audit_integrity(self, approval_id: str) -> bool:
        return self.repository.verify_audit_chain(approval_id)

    @staticmethod
    def _log(event_name: str, record: ApprovalRecord, outcome: str) -> None:
        _LOGGER.info(
            event_name,
            extra={
                "approval_id": record.approval_id,
                "event_id": record.event_id,
                "status": record.status.value,
                "decision": record.decision.value,
                "action": record.action.value,
                "risk": record.risk.value,
                "policy_version": record.policy_version,
                "outcome": outcome,
            },
        )


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("server approval clock must use UTC")
    return value.astimezone(UTC)
