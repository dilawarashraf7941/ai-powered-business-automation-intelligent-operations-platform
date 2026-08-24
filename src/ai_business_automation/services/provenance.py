"""Canonical SHA-256 provenance and audit hashing."""

import hashlib
import json

from ai_business_automation.models import (
    ApprovalStatus,
    AuditEventType,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    GHLAddContactTagParameters,
    PolicyDecision,
    RecommendedAction,
    TrustedProvenance,
)
from ai_business_automation.models.approvals import ActorId, ApprovalId, AuditEventId, Sha256Hex
from ai_business_automation.services.canonicalization import canonical_event_bytes


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def chained_audit_hash(payload: object, previous_event_hash: str) -> str:
    """Apply the shared hash-chain primitive to canonical audit data."""

    return sha256_hex(canonical_json_bytes(payload) + previous_event_hash.encode("ascii"))


def build_trusted_provenance(
    event: CanonicalBusinessEvent,
    intelligence: BusinessIntelligenceResult,
    decision: PolicyDecision,
) -> TrustedProvenance:
    """Bind policy fields to digests of full canonical validated inputs."""

    intelligence_bytes = canonical_json_bytes(intelligence.model_dump(mode="json"))
    action_parameters = (
        GHLAddContactTagParameters.model_validate(event.payload)
        if decision.action is RecommendedAction.ADD_CONTACT_TAG
        else None
    )
    return TrustedProvenance(
        event_id=event.event_id,
        event_type=event.event_type,
        source=event.source,
        policy_version=decision.policy_version,
        decision=decision.decision,
        action=decision.action,
        risk=decision.risk,
        confidence=intelligence.confidence,
        evidence=decision.evidence,
        canonical_event_sha256=sha256_hex(canonical_event_bytes(event)),
        canonical_intelligence_sha256=sha256_hex(intelligence_bytes),
        action_parameters=action_parameters,
    )


def provenance_bytes(provenance: TrustedProvenance) -> bytes:
    return canonical_json_bytes(provenance.model_dump(mode="json"))


def provenance_hash(provenance: TrustedProvenance) -> str:
    return sha256_hex(provenance_bytes(provenance))


def audit_event_hash(
    *,
    audit_event_id: AuditEventId,
    approval_id: ApprovalId,
    execution_id: str | None = None,
    event_id: str | None = None,
    failure_category: str | None = None,
    sequence_number: int,
    event_type: AuditEventType,
    status: ApprovalStatus | str,
    actor_id: ActorId,
    occurred_at: str,
    previous_event_hash: Sha256Hex,
) -> str:
    status_value = status.value if isinstance(status, ApprovalStatus) else status
    return chained_audit_hash(
        {
            "actor_id": actor_id,
            "approval_id": approval_id,
            "audit_event_id": audit_event_id,
            "event_type": event_type.value,
            "event_id": event_id,
            "execution_id": execution_id,
            "failure_category": failure_category,
            "occurred_at": occurred_at,
            "sequence_number": sequence_number,
            "status": status_value,
        },
        previous_event_hash,
    )
