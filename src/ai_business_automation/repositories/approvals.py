"""Parameterized transactional SQLite approval repository."""

import hmac
import json
import secrets
import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from pydantic import ValidationError

from ai_business_automation.models import (
    GENESIS_AUDIT_HASH,
    POLICY_VERSION,
    ApprovalRecord,
    ApprovalStatus,
    AuditEvent,
    AuditEventType,
    DecisionOutcome,
    EventSource,
    EventType,
    EvidenceCode,
    EvidenceSource,
    GHLAddContactTagParameters,
    PolicyEvidence,
    RecommendedAction,
    RiskLevel,
    TrustedProvenance,
)
from ai_business_automation.services.approval_errors import (
    ApprovalConflictError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalInvalidStateError,
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    ProvenanceIntegrityError,
    SchemaCompatibilityError,
)
from ai_business_automation.services.provenance import (
    audit_event_hash,
    canonical_json_bytes,
    provenance_hash,
)

_SYSTEM_ACTOR = "SYSTEM"
_SCHEMA_VERSION = 8
_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 8)
);
INSERT OR IGNORE INTO schema_metadata (singleton, schema_version) VALUES (1, 8);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY CHECK(length(approval_id) BETWEEN 24 AND 40),
    event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 20 AND 40),
    event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 64),
    source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 64),
    policy_version TEXT NOT NULL CHECK(policy_version = '1.0'),
    decision TEXT NOT NULL CHECK(decision = 'REQUIRE_HUMAN_APPROVAL'),
    action TEXT NOT NULL CHECK(action IN (
        'NONE', 'REVIEW', 'CONTACT_HUMAN', 'REQUEST_INFORMATION', 'ESCALATE',
        'SCHEDULE_CONSULTATION', 'NURTURE', 'GHL_ADD_CONTACT_TAG'
    )),
    risk TEXT NOT NULL CHECK(risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    evidence_json TEXT NOT NULL CHECK(length(evidence_json) BETWEEN 2 AND 8192),
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    expires_at TEXT NOT NULL CHECK(length(expires_at) BETWEEN 20 AND 40),
    decided_at TEXT CHECK(decided_at IS NULL OR length(decided_at) BETWEEN 20 AND 40),
    approver_id TEXT CHECK(approver_id IS NULL OR length(approver_id) BETWEEN 1 AND 64),
    rejection_reason TEXT CHECK(
        rejection_reason IS NULL OR length(rejection_reason) BETWEEN 1 AND 500
    ),
    provenance_json TEXT NOT NULL CHECK(length(provenance_json) BETWEEN 2 AND 8192),
    provenance_hash TEXT NOT NULL CHECK(length(provenance_hash) = 64),
    action_parameters_json TEXT CHECK(
        action_parameters_json IS NULL OR length(action_parameters_json) BETWEEN 2 AND 1024
    ),
    audit_event_count INTEGER NOT NULL DEFAULT 0 CHECK(audit_event_count >= 0),
    audit_head_hash TEXT NOT NULL CHECK(length(audit_head_hash) = 64)
);

CREATE TABLE IF NOT EXISTS approval_audit_events (
    audit_event_id TEXT PRIMARY KEY CHECK(length(audit_event_id) BETWEEN 24 AND 40),
    approval_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL CHECK(sequence_number >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN (
        'APPROVAL_CREATED', 'APPROVAL_APPROVED', 'APPROVAL_REJECTED',
        'APPROVAL_EXPIRED', 'APPROVAL_TRANSITION_REJECTED',
        'EXECUTION_CREATED', 'EXECUTION_CLAIMED', 'EXECUTION_SUCCEEDED',
        'EXECUTION_FAILED', 'EXECUTION_UNKNOWN', 'EXECUTION_REJECTED',
        'EXECUTION_RECONCILIATION_REQUESTED', 'EXECUTION_RECONCILED_SUCCEEDED',
        'EXECUTION_RECONCILED_FAILED', 'EXECUTION_RECONCILIATION_REJECTED'
    )),
    execution_id TEXT CHECK(
        execution_id IS NULL OR length(execution_id) BETWEEN 24 AND 40
    ),
    event_id TEXT CHECK(event_id IS NULL OR length(event_id) BETWEEN 20 AND 40),
    failure_category TEXT CHECK(
        failure_category IS NULL OR length(failure_category) BETWEEN 1 AND 64
    ),
    commitment_hash TEXT CHECK(
        commitment_hash IS NULL OR length(commitment_hash) = 64
    ),
    status TEXT NOT NULL CHECK(status IN (
        'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED',
        'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN',
        'RECONCILED_SUCCEEDED', 'RECONCILED_FAILED'
    )),
    actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
    occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
    previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) = 64),
    event_hash TEXT NOT NULL CHECK(length(event_hash) = 64),
    UNIQUE(approval_id, sequence_number),
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_approval_audit_sequence
ON approval_audit_events(approval_id, sequence_number);
"""


@runtime_checkable
class ApprovalRepository(Protocol):
    def initialize(self) -> None: ...

    def create(
        self,
        record: ApprovalRecord,
        provenance: TrustedProvenance,
        occurred_at: datetime,
        actor_id: str | None = None,
    ) -> ApprovalRecord: ...

    def get(self, approval_id: str, now: datetime) -> ApprovalRecord: ...

    def transition(
        self,
        approval_id: str,
        target: ApprovalStatus,
        now: datetime,
        actor_id: str,
        rejection_reason: str | None = None,
    ) -> ApprovalRecord: ...

    def verify_audit_chain(self, approval_id: str) -> bool: ...


class SQLiteApprovalRepository:
    """Open one bounded connection per operation and serialize writers with BEGIN IMMEDIATE."""

    def __init__(
        self,
        database_path: Path,
        *,
        audit_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._database_path = database_path
        self._audit_id_factory = audit_id_factory or _new_audit_id

    def initialize(self) -> None:
        connection = self._connect()
        try:
            _require_compatible_or_empty_schema(connection)
            connection.executescript(_SCHEMA)
        except SchemaCompatibilityError:
            raise
        except sqlite3.Error as exc:
            raise ApprovalPersistenceError from exc
        finally:
            connection.close()

    def create(
        self,
        record: ApprovalRecord,
        provenance: TrustedProvenance,
        occurred_at: datetime,
        actor_id: str | None = None,
    ) -> ApprovalRecord:
        evidence_json = _evidence_json(record.evidence)
        provenance_json = canonical_json_bytes(provenance.model_dump(mode="json")).decode("utf-8")
        action_parameters_json = (
            canonical_json_bytes(record.action_parameters.model_dump(mode="json")).decode("utf-8")
            if record.action_parameters is not None
            else None
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO approvals (
                    approval_id, event_id, event_type, source, policy_version, decision,
                    action, risk, confidence, evidence_json, status, created_at, expires_at,
                    decided_at, approver_id, rejection_reason, provenance_json,
                    provenance_hash, action_parameters_json, audit_event_count, audit_head_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.approval_id,
                    record.event_id,
                    record.event_type.value,
                    record.source.value,
                    record.policy_version,
                    record.decision.value,
                    record.action.value,
                    record.risk.value,
                    record.confidence,
                    evidence_json,
                    record.status.value,
                    _datetime_text(record.created_at),
                    _datetime_text(record.expires_at),
                    None,
                    None,
                    None,
                    provenance_json,
                    record.provenance_hash,
                    action_parameters_json,
                    0,
                    GENESIS_AUDIT_HASH,
                ),
            )
            self._append_audit(
                connection,
                approval_id=record.approval_id,
                event_type=AuditEventType.APPROVAL_CREATED,
                status=ApprovalStatus.PENDING,
                actor_id=actor_id or _SYSTEM_ACTOR,
                occurred_at=occurred_at,
                previous_hash=GENESIS_AUDIT_HASH,
                sequence_number=1,
            )
            connection.commit()
            return record
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ApprovalConflictError from exc
        except sqlite3.Error as exc:
            connection.rollback()
            raise ApprovalPersistenceError from exc
        finally:
            connection.close()

    def get(self, approval_id: str, now: datetime) -> ApprovalRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._required_row(connection, approval_id)
            self._verify_integrity(connection, row)
            if ApprovalStatus(row["status"]) is ApprovalStatus.PENDING and now >= _datetime(
                row["expires_at"]
            ):
                self._expire(connection, row, now)
                row = self._required_row(connection, approval_id)
            connection.commit()
            return _record_from_row(row)
        except ApprovalError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ApprovalPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            connection.rollback()
            raise ProvenanceIntegrityError from exc
        finally:
            connection.close()

    def transition(
        self,
        approval_id: str,
        target: ApprovalStatus,
        now: datetime,
        actor_id: str,
        rejection_reason: str | None = None,
    ) -> ApprovalRecord:
        if target not in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}:
            raise ApprovalInvalidStateError
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._required_row(connection, approval_id)
            self._verify_integrity(connection, row)
            current_status = ApprovalStatus(row["status"])
            if current_status is ApprovalStatus.PENDING and now >= _datetime(row["expires_at"]):
                self._expire(connection, row, now)
                connection.commit()
                raise ApprovalExpiredError
            if current_status is not ApprovalStatus.PENDING:
                self._append_rejected_transition(connection, row, now, actor_id)
                connection.commit()
                raise ApprovalInvalidStateError

            reason = rejection_reason if target is ApprovalStatus.REJECTED else None
            cursor = connection.execute(
                """
                UPDATE approvals
                SET status = ?, decided_at = ?, approver_id = ?, rejection_reason = ?
                WHERE approval_id = ? AND status = 'PENDING'
                """,
                (target.value, _datetime_text(now), actor_id, reason, approval_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise ApprovalConflictError
            self._append_audit(
                connection,
                approval_id=approval_id,
                event_type=(
                    AuditEventType.APPROVAL_APPROVED
                    if target is ApprovalStatus.APPROVED
                    else AuditEventType.APPROVAL_REJECTED
                ),
                status=target,
                actor_id=actor_id,
                occurred_at=now,
                previous_hash=str(row["audit_head_hash"]),
                sequence_number=int(row["audit_event_count"]) + 1,
            )
            connection.commit()
            return _record_from_row(self._read_row(connection, approval_id))
        except ApprovalError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ApprovalPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            connection.rollback()
            raise ProvenanceIntegrityError from exc
        finally:
            connection.close()

    def verify_audit_chain(self, approval_id: str) -> bool:
        connection = self._connect()
        try:
            row = self._required_row(connection, approval_id)
            return self._verify_audit_chain(connection, row)
        except ApprovalNotFoundError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError, ValidationError):
            return False
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=5.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection
        except sqlite3.Error as exc:
            raise ApprovalPersistenceError from exc

    @staticmethod
    def _required_row(connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone(),
        )
        if row is None:
            raise ApprovalNotFoundError
        return row

    @staticmethod
    def _read_row(connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone(),
        )
        if row is None:
            raise ApprovalConflictError
        return row

    def _verify_integrity(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
        if not self._verify_audit_chain(connection, row):
            raise ProvenanceIntegrityError
        provenance = TrustedProvenance.model_validate_json(str(row["provenance_json"]))
        expected_hash = provenance_hash(provenance)
        if not hmac.compare_digest(expected_hash, str(row["provenance_hash"])):
            raise ProvenanceIntegrityError
        record = _record_from_row(row)
        if (
            provenance.event_id != record.event_id
            or provenance.event_type is not record.event_type
            or provenance.source is not record.source
            or provenance.policy_version != record.policy_version
            or provenance.decision is not record.decision
            or provenance.action is not record.action
            or provenance.risk is not record.risk
            or provenance.confidence != record.confidence
            or provenance.evidence != record.evidence
            or provenance.action_parameters != record.action_parameters
            or record.policy_version != POLICY_VERSION
            or record.decision is not DecisionOutcome.REQUIRE_HUMAN_APPROVAL
        ):
            raise ProvenanceIntegrityError

    def _verify_audit_chain(self, connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
        audit_rows = connection.execute(
            """
            SELECT * FROM approval_audit_events
            WHERE approval_id = ? ORDER BY sequence_number ASC
            """,
            (str(row["approval_id"]),),
        ).fetchall()
        if len(audit_rows) != int(row["audit_event_count"]):
            return False
        previous_hash = GENESIS_AUDIT_HASH
        identities: set[str] = set()
        for expected_sequence, audit_row in enumerate(audit_rows, start=1):
            event = _audit_from_row(audit_row)
            if (
                event.sequence_number != expected_sequence
                or event.audit_event_id in identities
                or event.previous_event_hash != previous_hash
            ):
                return False
            expected_hash = audit_event_hash(
                audit_event_id=event.audit_event_id,
                approval_id=event.approval_id,
                execution_id=event.execution_id,
                event_id=event.event_id,
                failure_category=event.failure_category,
                commitment_hash=event.commitment_hash,
                sequence_number=event.sequence_number,
                event_type=event.event_type,
                status=event.status,
                actor_id=event.actor_id,
                occurred_at=_datetime_text(event.occurred_at),
                previous_event_hash=event.previous_event_hash,
            )
            if not hmac.compare_digest(expected_hash, event.event_hash):
                return False
            identities.add(event.audit_event_id)
            previous_hash = event.event_hash
        return hmac.compare_digest(previous_hash, str(row["audit_head_hash"]))

    def _expire(self, connection: sqlite3.Connection, row: sqlite3.Row, now: datetime) -> None:
        cursor = connection.execute(
            """
            UPDATE approvals SET status = 'EXPIRED', decided_at = ?
            WHERE approval_id = ? AND status = 'PENDING'
            """,
            (_datetime_text(now), str(row["approval_id"])),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError
        self._append_audit(
            connection,
            approval_id=str(row["approval_id"]),
            event_type=AuditEventType.APPROVAL_EXPIRED,
            status=ApprovalStatus.EXPIRED,
            actor_id=_SYSTEM_ACTOR,
            occurred_at=now,
            previous_hash=str(row["audit_head_hash"]),
            sequence_number=int(row["audit_event_count"]) + 1,
        )

    def _append_rejected_transition(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        now: datetime,
        actor_id: str,
    ) -> None:
        self._append_audit(
            connection,
            approval_id=str(row["approval_id"]),
            event_type=AuditEventType.APPROVAL_TRANSITION_REJECTED,
            status=ApprovalStatus(row["status"]),
            actor_id=actor_id,
            occurred_at=now,
            previous_hash=str(row["audit_head_hash"]),
            sequence_number=int(row["audit_event_count"]) + 1,
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        approval_id: str,
        event_type: AuditEventType,
        status: ApprovalStatus | str,
        actor_id: str,
        occurred_at: datetime,
        previous_hash: str,
        sequence_number: int,
        execution_id: str | None = None,
        event_id: str | None = None,
        failure_category: str | None = None,
        commitment_hash: str | None = None,
    ) -> None:
        audit_event_id = self._audit_id_factory()
        occurred_text = _datetime_text(occurred_at)
        event_hash = audit_event_hash(
            audit_event_id=audit_event_id,
            approval_id=approval_id,
            execution_id=execution_id,
            event_id=event_id,
            failure_category=failure_category,
            commitment_hash=commitment_hash,
            sequence_number=sequence_number,
            event_type=event_type,
            status=status,
            actor_id=actor_id,
            occurred_at=occurred_text,
            previous_event_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO approval_audit_events (
                audit_event_id, approval_id, sequence_number, event_type,
                execution_id, event_id, failure_category, commitment_hash, status, actor_id,
                occurred_at,
                previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_event_id,
                approval_id,
                sequence_number,
                event_type.value,
                execution_id,
                event_id,
                failure_category,
                commitment_hash,
                status.value if isinstance(status, ApprovalStatus) else status,
                actor_id,
                occurred_text,
                previous_hash,
                event_hash,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE approvals SET audit_event_count = ?, audit_head_hash = ?
            WHERE approval_id = ?
            """,
            (sequence_number, event_hash, approval_id),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError


def _new_audit_id() -> str:
    return f"aud_{secrets.token_urlsafe(18)}"


def _require_compatible_or_empty_schema(connection: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    if not tables:
        return
    if "schema_metadata" not in tables:
        raise SchemaCompatibilityError
    row = connection.execute(
        "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if row is None or int(row[0]) != _SCHEMA_VERSION:
        raise SchemaCompatibilityError


def _datetime_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("stored timestamp is invalid")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _evidence_json(evidence: list[PolicyEvidence]) -> str:
    return canonical_json_bytes([item.model_dump(mode="json") for item in evidence]).decode("utf-8")


def _evidence_from_json(value: object) -> list[PolicyEvidence]:
    if not isinstance(value, str):
        raise ValueError("stored evidence is invalid")
    decoded = json.loads(value)
    if not isinstance(decoded, list):
        raise ValueError("stored evidence is invalid")
    result: list[PolicyEvidence] = []
    for item in decoded:
        if not isinstance(item, dict):
            raise ValueError("stored evidence is invalid")
        raw_value = item.get("value")
        result.append(
            PolicyEvidence(
                code=EvidenceCode(item["code"]),
                source=EvidenceSource(item["source"]),
                value=raw_value,
            )
        )
    return result


def _record_from_row(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=str(row["approval_id"]),
        event_id=str(row["event_id"]),
        event_type=EventType(row["event_type"]),
        source=EventSource(row["source"]),
        policy_version=str(row["policy_version"]),
        decision=DecisionOutcome(row["decision"]),
        action=RecommendedAction(row["action"]),
        risk=RiskLevel(row["risk"]),
        confidence=float(row["confidence"]),
        evidence=_evidence_from_json(row["evidence_json"]),
        status=ApprovalStatus(row["status"]),
        created_at=_datetime(row["created_at"]),
        expires_at=_datetime(row["expires_at"]),
        decided_at=_datetime(row["decided_at"]) if row["decided_at"] is not None else None,
        approver_id=str(row["approver_id"]) if row["approver_id"] is not None else None,
        rejection_reason=(
            str(row["rejection_reason"]) if row["rejection_reason"] is not None else None
        ),
        provenance_hash=str(row["provenance_hash"]),
        action_parameters=(
            GHLAddContactTagParameters.model_validate_json(str(row["action_parameters_json"]))
            if row["action_parameters_json"] is not None
            else None
        ),
    )


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        audit_event_id=str(row["audit_event_id"]),
        approval_id=str(row["approval_id"]),
        execution_id=(str(row["execution_id"]) if row["execution_id"] is not None else None),
        event_id=str(row["event_id"]) if row["event_id"] is not None else None,
        failure_category=(
            str(row["failure_category"]) if row["failure_category"] is not None else None
        ),
        commitment_hash=(
            str(row["commitment_hash"]) if row["commitment_hash"] is not None else None
        ),
        sequence_number=int(row["sequence_number"]),
        event_type=AuditEventType(row["event_type"]),
        status=str(row["status"]),
        actor_id=str(row["actor_id"]),
        occurred_at=_datetime(row["occurred_at"]),
        previous_event_hash=str(row["previous_event_hash"]),
        event_hash=str(row["event_hash"]),
    )
