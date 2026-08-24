"""Transactional SQLite repository for single-use internal executions."""

import hmac
import secrets
import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from pydantic import ValidationError

from ai_business_automation.models import (
    ActionOutcome,
    ApprovalRecord,
    ApprovalStatus,
    AuditEventType,
    ExecutionAction,
    ExecutionRecord,
    ExecutionResultCode,
    ExecutionStatus,
    execution_action_for,
)
from ai_business_automation.repositories.approvals import (
    SQLiteApprovalRepository,
    _datetime,
    _datetime_text,
    _record_from_row,
)
from ai_business_automation.services.approval_errors import ProvenanceIntegrityError
from ai_business_automation.services.execution_errors import (
    ApprovalNotApprovedError,
    ApprovalProvenanceInvalidError,
    ExecutionAlreadyClaimedError,
    ExecutionAlreadyCompletedError,
    ExecutionApprovalExpiredError,
    ExecutionBoundaryError,
    ExecutionConflictError,
    ExecutionIntegrityError,
    ExecutionNotFoundError,
    ExecutionPersistenceError,
)
from ai_business_automation.services.provenance import canonical_json_bytes, sha256_hex

_EXECUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY CHECK(length(execution_id) BETWEEN 24 AND 40),
    approval_id TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 20 AND 40),
    action TEXT NOT NULL CHECK(action IN (
        'NO_OP', 'CREATE_INTERNAL_TASK', 'UPDATE_INTERNAL_STATUS',
        'REQUEST_HUMAN_REVIEW', 'GENERATE_INTERNAL_NOTE'
    )),
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
    started_at TEXT NOT NULL CHECK(length(started_at) BETWEEN 20 AND 40),
    completed_at TEXT CHECK(completed_at IS NULL OR length(completed_at) BETWEEN 20 AND 40),
    result_code TEXT CHECK(result_code IN ('COMPLETED', 'DEFINITIVE_FAILURE', 'OUTCOME_UNKNOWN')),
    safe_summary TEXT CHECK(safe_summary IS NULL OR length(safe_summary) BETWEEN 1 AND 200),
    actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
    effect_hash TEXT CHECK(effect_hash IS NULL OR length(effect_hash) = 64),
    integrity_hash TEXT NOT NULL CHECK(length(integrity_hash) = 64),
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS internal_action_effects (
    execution_id TEXT PRIMARY KEY,
    object_id TEXT UNIQUE CHECK(object_id IS NULL OR length(object_id) BETWEEN 24 AND 48),
    object_type TEXT NOT NULL CHECK(object_type IN (
        'NONE', 'INTERNAL_TASK', 'INTERNAL_STATUS', 'HUMAN_REVIEW', 'INTERNAL_NOTE'
    )),
    content TEXT NOT NULL CHECK(length(content) BETWEEN 1 AND 1000),
    created_at TEXT NOT NULL CHECK(length(created_at) BETWEEN 20 AND 40),
    FOREIGN KEY(execution_id) REFERENCES executions(execution_id) ON DELETE RESTRICT
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
        safe_summary: str,
        outcome: ActionOutcome | None = None,
    ) -> ExecutionRecord: ...

    def get_execution(self, execution_id: str) -> ExecutionRecord: ...

    def verify_integrity(self, execution_id: str) -> bool: ...


class SQLiteExecutionRepository(SQLiteApprovalRepository):
    """Use the approval database and hash chain as one transactional trust boundary."""

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
        connection = self._connect()
        try:
            connection.executescript(_EXECUTION_SCHEMA)
        except sqlite3.Error as exc:
            raise ExecutionPersistenceError from exc
        finally:
            connection.close()

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
                self._append_execution_rejected(connection, approval_row, now, actor_id)
                connection.commit()
                raise ApprovalProvenanceInvalidError from exc

            approval = _record_from_row(approval_row)
            if approval.status is ApprovalStatus.EXPIRED:
                self._append_execution_rejected(connection, approval_row, now, actor_id)
                connection.commit()
                raise ExecutionApprovalExpiredError
            if approval.status is not ApprovalStatus.APPROVED:
                self._append_execution_rejected(connection, approval_row, now, actor_id)
                connection.commit()
                raise ApprovalNotApprovedError
            if now >= approval.expires_at:
                self._append_execution_rejected(connection, approval_row, now, actor_id)
                connection.commit()
                raise ExecutionApprovalExpiredError

            existing = connection.execute(
                "SELECT * FROM executions WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if existing is not None:
                connection.commit()
                status = ExecutionStatus(existing["status"])
                if status is ExecutionStatus.CLAIMED:
                    raise ExecutionAlreadyClaimedError
                raise ExecutionAlreadyCompletedError

            execution_id = self._execution_id_factory()
            action = execution_action_for(approval.action)
            started_at = _datetime_text(now)
            claimed_hash = _execution_hash(
                execution_id=execution_id,
                approval_id=approval_id,
                event_id=approval.event_id,
                action=action,
                status=ExecutionStatus.CLAIMED,
                started_at=started_at,
                completed_at=None,
                result_code=None,
                safe_summary=None,
                actor_id=actor_id,
            )
            connection.execute(
                """
                INSERT INTO executions (
                    execution_id, approval_id, event_id, action, status, started_at,
                    completed_at, result_code, safe_summary, actor_id, effect_hash,
                    integrity_hash
                ) VALUES (?, ?, ?, ?, 'PENDING', ?, NULL, NULL, NULL, ?, NULL, ?)
                """,
                (
                    execution_id,
                    approval_id,
                    approval.event_id,
                    action.value,
                    started_at,
                    actor_id,
                    claimed_hash,
                ),
            )
            self._append_execution_event(
                connection,
                approval_row,
                execution_id,
                approval.event_id,
                AuditEventType.EXECUTION_CREATED,
                ExecutionStatus.PENDING,
                now,
                actor_id,
            )
            cursor = connection.execute(
                """
                UPDATE executions SET status = 'CLAIMED'
                WHERE execution_id = ? AND status = 'PENDING'
                """,
                (execution_id,),
            )
            if cursor.rowcount != 1:
                raise ExecutionConflictError
            approval_row = self._required_row(connection, approval_id)
            self._append_execution_event(
                connection,
                approval_row,
                execution_id,
                approval.event_id,
                AuditEventType.EXECUTION_CLAIMED,
                ExecutionStatus.CLAIMED,
                now,
                actor_id,
            )
            connection.commit()
            record = self._required_execution(connection, execution_id)
            return _execution_from_row(record), approval
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
        safe_summary: str,
        outcome: ActionOutcome | None = None,
    ) -> ExecutionRecord:
        if target not in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.UNKNOWN,
        }:
            raise ExecutionConflictError
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._required_execution(connection, execution_id)
            approval_row = self._required_row(connection, str(row["approval_id"]))
            self._verify_execution(connection, row, approval_row)
            current = ExecutionStatus(row["status"])
            if current is not ExecutionStatus.CLAIMED:
                if current in {
                    ExecutionStatus.SUCCEEDED,
                    ExecutionStatus.FAILED,
                    ExecutionStatus.UNKNOWN,
                }:
                    raise ExecutionAlreadyCompletedError
                raise ExecutionConflictError

            result_code = {
                ExecutionStatus.SUCCEEDED: ExecutionResultCode.COMPLETED,
                ExecutionStatus.FAILED: ExecutionResultCode.DEFINITIVE_FAILURE,
                ExecutionStatus.UNKNOWN: ExecutionResultCode.OUTCOME_UNKNOWN,
            }[target]
            if target is ExecutionStatus.SUCCEEDED:
                if outcome is None:
                    raise ExecutionConflictError
                connection.execute(
                    """
                    INSERT INTO internal_action_effects (
                        execution_id, object_id, object_type, content, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        outcome.effect.object_id,
                        outcome.effect.object_type,
                        outcome.effect.content,
                        _datetime_text(now),
                    ),
                )
                effect_hash = sha256_hex(
                    canonical_json_bytes(outcome.effect.model_dump(mode="json"))
                )
            elif outcome is not None:
                raise ExecutionConflictError
            else:
                effect_hash = None

            completed_text = _datetime_text(now)
            integrity_hash = _execution_hash(
                execution_id=execution_id,
                approval_id=str(row["approval_id"]),
                event_id=str(row["event_id"]),
                action=ExecutionAction(row["action"]),
                status=target,
                started_at=str(row["started_at"]),
                completed_at=completed_text,
                result_code=result_code,
                safe_summary=safe_summary,
                actor_id=str(row["actor_id"]),
                effect_hash=effect_hash,
            )
            cursor = connection.execute(
                """
                UPDATE executions
                SET status = ?, completed_at = ?, result_code = ?, safe_summary = ?,
                    effect_hash = ?, integrity_hash = ?
                WHERE execution_id = ? AND status = 'CLAIMED'
                """,
                (
                    target.value,
                    completed_text,
                    result_code.value,
                    safe_summary,
                    effect_hash,
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
                str(row["event_id"]),
                event_type,
                target,
                now,
                str(row["actor_id"]),
            )
            connection.commit()
            return _execution_from_row(self._required_execution(connection, execution_id))
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
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        approval_row: sqlite3.Row,
    ) -> None:
        if not self._verify_audit_chain(connection, approval_row):
            raise ExecutionIntegrityError
        try:
            self._verify_integrity(connection, approval_row)
        except ProvenanceIntegrityError as exc:
            raise ApprovalProvenanceInvalidError from exc
        approval = _record_from_row(approval_row)
        record = _execution_from_row(row)
        expected_hash = _execution_hash(
            execution_id=record.execution_id,
            approval_id=record.approval_id,
            event_id=record.event_id,
            action=record.action,
            status=record.status,
            started_at=_datetime_text(record.started_at),
            completed_at=(
                _datetime_text(record.completed_at) if record.completed_at is not None else None
            ),
            result_code=record.result_code,
            safe_summary=record.safe_summary,
            actor_id=record.actor_id,
            effect_hash=str(row["effect_hash"]) if row["effect_hash"] is not None else None,
        )
        effect_row = connection.execute(
            """
            SELECT object_id, object_type, content FROM internal_action_effects
            WHERE execution_id = ?
            """,
            (record.execution_id,),
        ).fetchone()
        effect_valid = _effect_is_valid(record, row, effect_row)
        if (
            not hmac.compare_digest(expected_hash, str(row["integrity_hash"]))
            or not effect_valid
            or record.approval_id != approval.approval_id
            or record.event_id != approval.event_id
            or record.action is not execution_action_for(approval.action)
        ):
            raise ExecutionIntegrityError

    def _append_execution_rejected(
        self,
        connection: sqlite3.Connection,
        approval_row: sqlite3.Row,
        now: datetime,
        actor_id: str,
    ) -> None:
        self._append_execution_event(
            connection,
            approval_row,
            None,
            str(approval_row["event_id"]),
            AuditEventType.EXECUTION_REJECTED,
            str(approval_row["status"]),
            now,
            actor_id,
        )

    def _append_execution_event(
        self,
        connection: sqlite3.Connection,
        approval_row: sqlite3.Row,
        execution_id: str | None,
        event_id: str,
        event_type: AuditEventType,
        status: ExecutionStatus | str,
        now: datetime,
        actor_id: str,
    ) -> None:
        self._append_audit(
            connection,
            approval_id=str(approval_row["approval_id"]),
            event_type=event_type,
            status=status.value if isinstance(status, ExecutionStatus) else status,
            actor_id=actor_id,
            occurred_at=now,
            previous_hash=str(approval_row["audit_head_hash"]),
            sequence_number=int(approval_row["audit_event_count"]) + 1,
            execution_id=execution_id,
            event_id=event_id,
        )


def _new_execution_id() -> str:
    return f"exe_{secrets.token_urlsafe(18)}"


def _execution_hash(
    *,
    execution_id: str,
    approval_id: str,
    event_id: str,
    action: ExecutionAction,
    status: ExecutionStatus,
    started_at: str,
    completed_at: str | None,
    result_code: ExecutionResultCode | None,
    safe_summary: str | None,
    actor_id: str,
    effect_hash: str | None = None,
) -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "action": action.value,
                "actor_id": actor_id,
                "approval_id": approval_id,
                "completed_at": completed_at,
                "event_id": event_id,
                "effect_hash": effect_hash,
                "execution_id": execution_id,
                "result_code": result_code.value if result_code is not None else None,
                "safe_summary": safe_summary,
                "started_at": started_at,
                "status": status.value,
            }
        )
    )


def _execution_from_row(row: sqlite3.Row) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=str(row["execution_id"]),
        approval_id=str(row["approval_id"]),
        event_id=str(row["event_id"]),
        action=ExecutionAction(row["action"]),
        status=ExecutionStatus(row["status"]),
        started_at=_datetime(row["started_at"]),
        completed_at=_datetime(row["completed_at"]) if row["completed_at"] is not None else None,
        result_code=(
            ExecutionResultCode(row["result_code"]) if row["result_code"] is not None else None
        ),
        safe_summary=str(row["safe_summary"]) if row["safe_summary"] is not None else None,
        actor_id=str(row["actor_id"]),
    )


def _effect_is_valid(
    record: ExecutionRecord,
    execution_row: sqlite3.Row,
    effect_row: sqlite3.Row | None,
) -> bool:
    stored_hash = execution_row["effect_hash"]
    if record.status is not ExecutionStatus.SUCCEEDED:
        return effect_row is None and stored_hash is None
    if effect_row is None or not isinstance(stored_hash, str):
        return False
    calculated = sha256_hex(
        canonical_json_bytes(
            {
                "content": str(effect_row["content"]),
                "object_id": (
                    str(effect_row["object_id"]) if effect_row["object_id"] is not None else None
                ),
                "object_type": str(effect_row["object_type"]),
            }
        )
    )
    return hmac.compare_digest(calculated, stored_hash)
