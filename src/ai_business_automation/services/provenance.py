"""Canonical SHA-256 provenance and audit hashing."""

import hashlib
import json

from ai_business_automation.models import (
    ApprovalStatus,
    AuditEventType,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    PolicyDecision,
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


def build_trusted_provenance(
    event: CanonicalBusinessEvent,
    intelligence: BusinessIntelligenceResult,
    decision: PolicyDecision,
) -> TrustedProvenance:
    """Bind policy fields to digests of full canonical validated inputs."""

    intelligence_bytes = canonical_json_bytes(intelligence.model_dump(mode="json"))
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
    )


def provenance_bytes(provenance: TrustedProvenance) -> bytes:
    return canonical_json_bytes(provenance.model_dump(mode="json"))


def provenance_hash(provenance: TrustedProvenance) -> str:
    return sha256_hex(provenance_bytes(provenance))


def audit_event_hash(
    *,
    audit_event_id: AuditEventId,
    approval_id: ApprovalId,
    sequence_number: int,
    event_type: AuditEventType,
    status: ApprovalStatus,
    actor_id: ActorId,
    occurred_at: str,
    previous_event_hash: Sha256Hex,
) -> str:
    current = canonical_json_bytes(
        {
            "actor_id": actor_id,
            "approval_id": approval_id,
            "audit_event_id": audit_event_id,
            "event_type": event_type.value,
            "occurred_at": occurred_at,
            "sequence_number": sequence_number,
            "status": status.value,
        }
    )
    return sha256_hex(current + previous_event_hash.encode("ascii"))
