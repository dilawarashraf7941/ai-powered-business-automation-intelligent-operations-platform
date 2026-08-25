"""Transactional SQLite repository for one single-use contact-tag execution."""

import hmac
import secrets
import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from pydantic import ValidationError

from ai_business_automation.models import (
    POLICY_VERSION,
    ApprovalRecord,
    ApprovalStatus,
    AuditEventType,
    ExecutionAction,
    ExecutionFailureCategory,
    ExecutionRecord,
    ExecutionStatus,
    GHLAddContactTagParameters,
    RecommendedAction,
    ReconciliationOutcome,
    ReconciliationRecord,
)
from ai_business_automation.repositories.approvals import (
    SQLiteApprovalRepository,
    _datetime,
    _datetime_text,
    _record_from_row,
)
from ai_business_automation.services.approval_errors import ProvenanceIntegrityError
from ai_business_automation.services.execution_errors import (
    ActionNotAllowedError,
    ApprovalNotApprovedError,
    ApprovalProvenanceInvalidError,
    ExecutionAlreadyAssessedError,
    ExecutionAlreadyClaimedError,
    ExecutionAlreadyCompletedError,
    ExecutionApprovalExpiredError,
    ExecutionBoundaryError,
    ExecutionConflictError,
    ExecutionIntegrityError,
    ExecutionNotFoundError,
    ExecutionNotReconciliableError,
    ExecutionPersistenceError,
    ReconciliationIntegrityError,
)
from ai_business_automation.services.provenance import canonical_json_bytes, sha256_hex

_EXECUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY CHECK(length(execution_id) BETWEEN 24 AND 40),
    approval_id TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 20 AND 40),
    action TEXT NOT NULL CHECK(action = 'ADD_CONTACT_TAG'),
    contact_id TEXT NOT NULL CHECK(length(contact_id) BETWEEN 10 AND 40),
    tag TEXT NOT NULL CHECK(length(tag) BETWEEN 1 AND 50),
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    claimed_at TEXT NOT NULL CHECK(length(claimed_at) BETWEEN 20 AND 40),
    completed_at TEXT CHECK(completed_at IS NULL OR length(completed_at) BETWEEN 20 AND 40),
    failure_category TEXT CHECK(failure_category IS NULL OR failure_category IN (
        'VALIDATION_ERROR', 'APPROVAL_INVALID', 'APPROVAL_EXPIRED', 'ALREADY_EXECUTED',
        'PROVIDER_AUTHENTICATION', 'PROVIDER_RATE_LIMIT', 'PROVIDER_BAD_REQUEST',
        'PROVIDER_UNAVAILABLE', 'PROVIDER_TIMEOUT', 'PROVIDER_ERROR', 'UNKNOWN_OUTCOME',
        'PERSISTENCE_ERROR', 'INTERNAL_ERROR'
    )),
    provenance_hash TEXT NOT NULL CHECK(length(provenance_hash) = 64),
    policy_version TEXT NOT NULL CHECK(policy_version = '1.0'),
    actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
    action_parameters_hash TEXT NOT NULL CHECK(length(action_parameters_hash) = 64),
    integrity_hash TEXT NOT NULL CHECK(length(integrity_hash) = 64),
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);
"""


@runtime_checkable
class ExecutionRepository(Protocol):
    def initialize(self) -> None: ...

    def claim(
        self, approval_id: str, now: datetime, actor_id: str
    ) -> tuple[ExecutionRecord, ApprovalRecord]: ...

    def complete(
        self,
        execution_id: str,
        target: ExecutionStatus,
        now: datetime,
        failure_category: ExecutionFailureCategory | None,
    ) -> ExecutionRecord: ...

    def get_execution(self, execution_id: str) -> ExecutionRecord: ...

    def reconcile(
        self,
        execution_id: str,
        outcome: ReconciliationOutcome,
        reason: str,
        now: datetime,
        actor_id: str,
    ) -> ReconciliationRecord: ...

    def get_reconciliation(self, execution_id: str) -> ReconciliationRecord: ...

    def verify_integrity(self, execution_id: str) -> bool: ...


class SQLiteExecutionRepository(SQLiteApprovalRepository):
    """Use approval provenance and audit chain as one atomic trust boundary."""

    def __init__(
        self,
        database_path: Path,
        *,
        execution_id_factory: Callable[[], str] | None = None,
        audit_id_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(database_path, audit_id_factory=audit_id_factory)
        self._execution_id_factory = execution_id_factory or _new_execution_id

    def initialize(self) -> None:
        super().initialize()

    def claim(
        self, approval_id: str, now: datetime, actor_id: str
    ) -> tuple[ExecutionRecord, ApprovalRecord]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            approval_row = self._required_row(connection, approval_id)
            if not self._verify_audit_chain(connection, approval_row):
                raise ExecutionIntegrityError
            try:
                self._verify_integrity(connection, approval_row)
            except (
                ProvenanceIntegrityError,
                KeyError,
                TypeError,
                ValueError,
                ValidationError,
            ) as exc:
                raise ApprovalProvenanceInvalidError from exc
            approval = _record_from_row(approval_row)
            if approval.status is ApprovalStatus.EXPIRED or now >= approval.expires_at:
                raise ExecutionApprovalExpiredError
            if approval.status is not ApprovalStatus.APPROVED:
                raise ApprovalNotApprovedError
            if (
                approval.policy_version != POLICY_VERSION
                or approval.action is not RecommendedAction.ADD_CONTACT_TAG
                or approval.action_parameters is None
            ):
                raise ActionNotAllowedError
            trusted_parameters = GHLAddContactTagParameters.model_validate(
                approval.action_parameters
            )
            existing = connection.execute(
                "SELECT status FROM executions WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if existing is not None:
                connection.commit()
                if ExecutionStatus(existing["status"]) is ExecutionStatus.CLAIMED:
                    raise ExecutionAlreadyClaimedError
                raise ExecutionAlreadyCompletedError

            execution_id = self._execution_id_factory()
            timestamp = _datetime_text(now)
            parameters_hash = sha256_hex(
                canonical_json_bytes(trusted_parameters.model_dump(mode="json"))
            )
            integrity_hash = _execution_hash(
                execution_id=execution_id,
                approval_id=approval_id,
                event_id=approval.event_id,
                contact_id=trusted_parameters.contact_id,
                tag=trusted_parameters.tag,
                status=ExecutionStatus.CLAIMED,
                created_at=timestamp,
                claimed_at=timestamp,
                completed_at=None,
                failure_category=None,
                provenance_hash=approval.provenance_hash,
                policy_version=approval.policy_version,
                actor_id=actor_id,
                action_parameters_hash=parameters_hash,
            )
            connection.execute(
                """
                INSERT INTO executions (
                    execution_id, approval_id, event_id, action, contact_id, tag, status,
                    created_at, claimed_at, completed_at, failure_category, provenance_hash,
                    policy_version, actor_id, action_parameters_hash, integrity_hash
                ) VALUES (
                    ?, ?, ?, 'ADD_CONTACT_TAG', ?, ?, 'PENDING', ?, ?, NULL, NULL, ?, ?, ?, ?, ?
                )
                """,
                (
                    execution_id,
                    approval_id,
                    approval.event_id,
                    trusted_parameters.contact_id,
                    trusted_parameters.tag,
                    timestamp,
                    timestamp,
                    approval.provenance_hash,
                    approval.policy_version,
                    actor_id,
                    parameters_hash,
                    integrity_hash,
                ),
            )
            self._append_execution_event(
                connection,
                approval_row,
                execution_id,
                AuditEventType.EXECUTION_AUTHORIZED,
                ExecutionStatus.PENDING,
                now,
                actor_id,
            )
            cursor = connection.execute(
                "UPDATE executions SET status = 'CLAIMED' "
                "WHERE execution_id = ? AND status = 'PENDING'",
                (execution_id,),
            )
            if cursor.rowcount != 1:
                raise ExecutionConflictError
            approval_row = self._required_row(connection, approval_id)
            self._append_execution_event(
                connection,
                approval_row,
                execution_id,
                AuditEventType.EXECUTION_CLAIMED,
                ExecutionStatus.CLAIMED,
                now,
                actor_id,
            )
            connection.commit()
            return _execution_from_row(self._required_execution(connection, execution_id)), approval
        except ExecutionBoundaryError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ExecutionConflictError from exc
        except sqlite3.Error as exc:
            connection.rollback()
            raise ExecutionPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            connection.rollback()
            raise ExecutionIntegrityError from exc
        finally:
            connection.close()

    def complete(
        self,
        execution_id: str,
        target: ExecutionStatus,
        now: datetime,
        failure_category: ExecutionFailureCategory | None,
    ) -> ExecutionRecord:
        if target not in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.UNKNOWN,
        }:
            raise ExecutionConflictError
        if (target is ExecutionStatus.SUCCEEDED) != (failure_category is None):
            raise ExecutionConflictError
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._required_execution(connection, execution_id)
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._verify_execution(connection, row, approval_row)
            if ExecutionStatus(row["status"]) is not ExecutionStatus.CLAIMED:
                raise ExecutionAlreadyCompletedError
            completed_at = _datetime_text(now)
            integrity_hash = _execution_hash_from_row(
                row, status=target, completed_at=completed_at, failure_category=failure_category
            )
            cursor = connection.execute(
                """
                UPDATE executions SET status = ?, completed_at = ?, failure_category = ?,
                    integrity_hash = ? WHERE execution_id = ? AND status = 'CLAIMED'
                """,
                (
                    target.value,
                    completed_at,
                    failure_category.value if failure_category is not None else None,
                    integrity_hash,
                    execution_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ExecutionConflictError
            event_type = {
                ExecutionStatus.SUCCEEDED: AuditEventType.EXECUTION_SUCCEEDED,
                ExecutionStatus.FAILED: AuditEventType.EXECUTION_FAILED,
                ExecutionStatus.UNKNOWN: AuditEventType.EXECUTION_UNKNOWN,
            }[target]
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._append_execution_event(
                connection,
                approval_row,
                execution_id,
                event_type,
                target,
                now,
                str(row["actor_id"]),
                failure_category,
            )
            connection.commit()
            return _execution_from_row(self._required_execution(connection, execution_id))
        except ExecutionBoundaryError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ExecutionPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            connection.rollback()
            raise ExecutionIntegrityError from exc
        finally:
            connection.close()

    def get_execution(self, execution_id: str) -> ExecutionRecord:
        connection = self._connect()
        try:
            row = self._required_execution(connection, execution_id)
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._verify_execution(connection, row, approval_row)
            return _execution_from_row(row)
        except ExecutionBoundaryError:
            raise
        except sqlite3.Error as exc:
            raise ExecutionPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ExecutionIntegrityError from exc
        finally:
            connection.close()

    def reconcile(
        self,
        execution_id: str,
        outcome: ReconciliationOutcome,
        reason: str,
        now: datetime,
        actor_id: str,
    ) -> ReconciliationRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._required_execution(connection, execution_id)
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._verify_execution(connection, row, approval_row)
            if (
                ExecutionStatus(row["status"]) is not ExecutionStatus.UNKNOWN
                or ExecutionAction(row["action"]) is not ExecutionAction.ADD_CONTACT_TAG
            ):
                raise ExecutionNotReconciliableError
            if (
                connection.execute(
                    "SELECT 1 FROM execution_reconciliation_assessments WHERE execution_id = ?",
                    (execution_id,),
                ).fetchone()
                is not None
            ):
                raise ExecutionAlreadyAssessedError
            assessment_id = f"rcn_{secrets.token_urlsafe(18)}"
            occurred_at = _datetime_text(now)
            original_hash = str(row["integrity_hash"])
            previous_hash = "0" * 64
            payload = {
                "actor_id": actor_id,
                "approval_id": row["approval_id"],
                "assessment_id": assessment_id,
                "declared_outcome": outcome.value,
                "execution_id": execution_id,
                "occurred_at": occurred_at,
                "original_execution_integrity_hash": original_hash,
                "policy_version": row["policy_version"],
                "provenance_hash": row["provenance_hash"],
                "reason": reason,
            }
            assessment_hash = sha256_hex(
                canonical_json_bytes(payload) + previous_hash.encode("ascii")
            )
            connection.execute(
                """
                INSERT INTO execution_reconciliation_assessments (
                    assessment_id, execution_id, approval_id, provenance_hash,
                    policy_version, original_execution_integrity_hash, actor_id,
                    occurred_at, declared_outcome, reason, previous_assessment_hash,
                    assessment_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    execution_id,
                    row["approval_id"],
                    row["provenance_hash"],
                    row["policy_version"],
                    original_hash,
                    actor_id,
                    occurred_at,
                    outcome.value,
                    reason,
                    previous_hash,
                    assessment_hash,
                ),
            )
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._append_audit(
                connection,
                approval_id=str(row["approval_id"]),
                event_type=AuditEventType.RECONCILIATION_RECORDED,
                status=ExecutionStatus.UNKNOWN.value,
                actor_id=actor_id,
                occurred_at=now,
                previous_hash=str(approval_row["audit_head_hash"]),
                sequence_number=int(approval_row["audit_event_count"]) + 1,
                execution_id=execution_id,
                event_id=str(row["event_id"]),
                commitment_hash=assessment_hash,
            )
            connection.commit()
            return self.get_reconciliation(execution_id)
        except ExecutionBoundaryError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ExecutionAlreadyAssessedError from exc
        except sqlite3.Error as exc:
            connection.rollback()
            raise ExecutionPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            connection.rollback()
            raise ReconciliationIntegrityError from exc
        finally:
            connection.close()

    def get_reconciliation(self, execution_id: str) -> ReconciliationRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM execution_reconciliation_assessments WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            if row is None:
                raise ExecutionNotFoundError
            record = _reconciliation_from_row(row)
            payload = {
                "actor_id": record.actor_id,
                "approval_id": record.approval_id,
                "assessment_id": record.assessment_id,
                "declared_outcome": record.declared_outcome.value,
                "execution_id": record.execution_id,
                "occurred_at": _datetime_text(record.occurred_at),
                "original_execution_integrity_hash": (record.original_execution_integrity_hash),
                "policy_version": record.policy_version,
                "provenance_hash": record.provenance_hash,
                "reason": record.reason,
            }
            expected = sha256_hex(
                canonical_json_bytes(payload) + record.previous_assessment_hash.encode("ascii")
            )
            execution = self._required_execution(connection, execution_id)
            if (
                not hmac.compare_digest(expected, record.assessment_hash)
                or record.previous_assessment_hash != "0" * 64
                or ExecutionStatus(execution["status"]) is not ExecutionStatus.UNKNOWN
                or execution["integrity_hash"] != record.original_execution_integrity_hash
                or execution["provenance_hash"] != record.provenance_hash
            ):
                raise ReconciliationIntegrityError
            return record
        except ExecutionBoundaryError:
            raise
        except sqlite3.Error as exc:
            raise ExecutionPersistenceError from exc
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ReconciliationIntegrityError from exc
        finally:
            connection.close()

    def verify_integrity(self, execution_id: str) -> bool:
        try:
            self.get_execution(execution_id)
        except ExecutionBoundaryError:
            return False
        return True

    @staticmethod
    def _required_execution(connection: sqlite3.Connection, execution_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone(),
        )
        if row is None:
            raise ExecutionNotFoundError
        return row

    def _verify_execution(
        self, connection: sqlite3.Connection, row: sqlite3.Row, approval_row: sqlite3.Row
    ) -> None:
        if not self._verify_audit_chain(connection, approval_row):
            raise ExecutionIntegrityError
        try:
            self._verify_integrity(connection, approval_row)
        except ProvenanceIntegrityError as exc:
            raise ApprovalProvenanceInvalidError from exc
        approval = _record_from_row(approval_row)
        record = _execution_from_row(row)
        expected = _execution_hash_from_row(row)
        parameters_hash = sha256_hex(
            canonical_json_bytes({"contact_id": record.contact_id, "tag": record.tag})
        )
        if (
            not hmac.compare_digest(expected, str(row["integrity_hash"]))
            or not hmac.compare_digest(parameters_hash, str(row["action_parameters_hash"]))
            or approval.action_parameters is None
            or approval.action_parameters.contact_id != record.contact_id
            or approval.action_parameters.tag != record.tag
            or approval.provenance_hash != record.provenance_hash
            or approval.policy_version != record.policy_version
            or approval.action is not RecommendedAction.ADD_CONTACT_TAG
        ):
            raise ExecutionIntegrityError

    def _append_execution_event(
        self,
        connection: sqlite3.Connection,
        approval_row: sqlite3.Row,
        execution_id: str,
        event_type: AuditEventType,
        status: ExecutionStatus,
        now: datetime,
        actor_id: str,
        failure_category: ExecutionFailureCategory | None = None,
    ) -> None:
        self._append_audit(
            connection,
            approval_id=str(approval_row["approval_id"]),
            event_type=event_type,
            status=status.value,
            actor_id=actor_id,
            occurred_at=now,
            previous_hash=str(approval_row["audit_head_hash"]),
            sequence_number=int(approval_row["audit_event_count"]) + 1,
            execution_id=execution_id,
            event_id=str(approval_row["event_id"]),
            failure_category=(failure_category.value if failure_category is not None else None),
        )


def _new_execution_id() -> str:
    return f"exe_{secrets.token_urlsafe(18)}"


def _execution_hash(
    *,
    execution_id: str,
    approval_id: str,
    event_id: str,
    contact_id: str,
    tag: str,
    status: ExecutionStatus,
    created_at: str,
    claimed_at: str,
    completed_at: str | None,
    failure_category: ExecutionFailureCategory | None,
    provenance_hash: str,
    policy_version: str,
    actor_id: str,
    action_parameters_hash: str,
) -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "action": ExecutionAction.ADD_CONTACT_TAG.value,
                "action_parameters_hash": action_parameters_hash,
                "actor_id": actor_id,
                "approval_id": approval_id,
                "claimed_at": claimed_at,
                "completed_at": completed_at,
                "contact_id": contact_id,
                "created_at": created_at,
                "event_id": event_id,
                "execution_id": execution_id,
                "failure_category": failure_category.value
                if failure_category is not None
                else None,
                "policy_version": policy_version,
                "provenance_hash": provenance_hash,
                "status": status.value,
                "tag": tag,
            }
        )
    )


def _execution_hash_from_row(
    row: sqlite3.Row,
    *,
    status: ExecutionStatus | None = None,
    completed_at: str | None = None,
    failure_category: ExecutionFailureCategory | None = None,
) -> str:
    active_status = status or ExecutionStatus(row["status"])
    active_failure = (
        failure_category
        if status is not None
        else ExecutionFailureCategory(row["failure_category"])
        if row["failure_category"] is not None
        else None
    )
    return _execution_hash(
        execution_id=str(row["execution_id"]),
        approval_id=str(row["approval_id"]),
        event_id=str(row["event_id"]),
        contact_id=str(row["contact_id"]),
        tag=str(row["tag"]),
        status=active_status,
        created_at=str(row["created_at"]),
        claimed_at=str(row["claimed_at"]),
        completed_at=completed_at
        if status is not None
        else (str(row["completed_at"]) if row["completed_at"] is not None else None),
        failure_category=active_failure,
        provenance_hash=str(row["provenance_hash"]),
        policy_version=str(row["policy_version"]),
        actor_id=str(row["actor_id"]),
        action_parameters_hash=str(row["action_parameters_hash"]),
    )


def _execution_from_row(row: sqlite3.Row) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=str(row["execution_id"]),
        approval_id=str(row["approval_id"]),
        event_id=str(row["event_id"]),
        action=ExecutionAction(row["action"]),
        contact_id=str(row["contact_id"]),
        tag=str(row["tag"]),
        status=ExecutionStatus(row["status"]),
        created_at=_datetime(row["created_at"]),
        claimed_at=_datetime(row["claimed_at"]),
        completed_at=_datetime(row["completed_at"]) if row["completed_at"] is not None else None,
        failure_category=(
            ExecutionFailureCategory(row["failure_category"])
            if row["failure_category"] is not None
            else None
        ),
        provenance_hash=str(row["provenance_hash"]),
        policy_version=str(row["policy_version"]),
        actor_id=str(row["actor_id"]),
    )


def _reconciliation_from_row(row: sqlite3.Row) -> ReconciliationRecord:
    return ReconciliationRecord(
        assessment_id=str(row["assessment_id"]),
        execution_id=str(row["execution_id"]),
        approval_id=str(row["approval_id"]),
        provenance_hash=str(row["provenance_hash"]),
        policy_version=str(row["policy_version"]),
        original_execution_integrity_hash=str(row["original_execution_integrity_hash"]),
        actor_id=str(row["actor_id"]),
        occurred_at=_datetime(row["occurred_at"]),
        declared_outcome=ReconciliationOutcome(row["declared_outcome"]),
        reason=str(row["reason"]),
        previous_assessment_hash=str(row["previous_assessment_hash"]),
        assessment_hash=str(row["assessment_hash"]),
    )
