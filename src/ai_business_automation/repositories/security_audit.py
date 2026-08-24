"""Persistent tamper-evident authentication and authorization audit chain."""

import hmac
import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from ai_business_automation.models import AuthenticatedActor, SecurityAuditEventType
from ai_business_automation.repositories.approvals import SQLiteApprovalRepository
from ai_business_automation.services.approval_errors import ApprovalPersistenceError
from ai_business_automation.services.provenance import chained_audit_hash

_GENESIS = "0" * 64
_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_audit_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    event_count INTEGER NOT NULL CHECK(event_count >= 0),
    head_hash TEXT NOT NULL CHECK(length(head_hash) = 64)
);
INSERT OR IGNORE INTO security_audit_state
VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000');
CREATE TABLE IF NOT EXISTS security_audit_events (
    audit_event_id TEXT PRIMARY KEY CHECK(length(audit_event_id) BETWEEN 24 AND 40),
    sequence_number INTEGER NOT NULL UNIQUE,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'AUTHENTICATION_SUCCEEDED', 'AUTHENTICATION_FAILED',
        'APPROVAL_AUTHORIZED', 'APPROVAL_REJECTED_BY_AUTHZ',
        'ACTION_EXECUTION_AUTHORIZED', 'ACTION_EXECUTION_REJECTED_BY_AUTHZ'
    )),
    actor_id TEXT CHECK(actor_id IS NULL OR length(actor_id) BETWEEN 1 AND 64),
    role TEXT CHECK(role IS NULL OR role IN ('READ_ONLY', 'APPROVER', 'EXECUTOR', 'ADMIN')),
    request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 20 AND 40),
    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'failure', 'authorized', 'rejected')),
    occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
    previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) = 64),
    event_hash TEXT NOT NULL CHECK(length(event_hash) = 64)
);
"""


class SecurityAuditRepository:
    """Append security decisions without storing credential material."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialized = False
        self._initialization_lock = threading.Lock()

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._initialization_lock:
            if self._initialized:
                return
            SQLiteApprovalRepository(self._database_path).initialize()
            connection = sqlite3.connect(self._database_path)
            try:
                connection.executescript(_SCHEMA)
            finally:
                connection.close()
            self._initialized = True

    def append(
        self,
        event_type: SecurityAuditEventType,
        *,
        request_id: str,
        operation: str,
        outcome: str,
        actor: AuthenticatedActor | None = None,
    ) -> None:
        self._initialize()
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT event_count, head_hash FROM security_audit_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("security audit state is unavailable")
            sequence = int(row[0]) + 1
            previous = str(row[1])
            audit_event_id = f"aud_{secrets.token_urlsafe(18)}"
            occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            payload = {
                "actor_id": actor.actor_id if actor is not None else None,
                "audit_event_id": audit_event_id,
                "event_type": event_type.value,
                "occurred_at": occurred_at,
                "operation": operation,
                "outcome": outcome,
                "request_id": request_id,
                "role": actor.role.value if actor is not None else None,
                "sequence_number": sequence,
            }
            event_hash = chained_audit_hash(payload, previous)
            connection.execute(
                "INSERT INTO security_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    audit_event_id,
                    sequence,
                    event_type.value,
                    payload["actor_id"],
                    payload["role"],
                    request_id,
                    operation,
                    outcome,
                    occurred_at,
                    previous,
                    event_hash,
                ),
            )
            connection.execute(
                "UPDATE security_audit_state SET event_count = ?, head_hash = ? "
                "WHERE singleton = 1",
                (sequence, event_hash),
            )
            connection.commit()
        finally:
            connection.close()

    def is_ready(self) -> bool:
        """Verify bounded local schema access without exposing failure details."""

        try:
            self._initialize()
            connection = sqlite3.connect(self._database_path, timeout=1.0)
            try:
                approval_schema = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'approvals'"
                ).fetchone()
                audit_state = connection.execute(
                    "SELECT event_count, head_hash FROM security_audit_state WHERE singleton = 1"
                ).fetchone()
                return (
                    approval_schema is not None
                    and audit_state is not None
                    and isinstance(audit_state[0], int)
                    and audit_state[0] >= 0
                    and isinstance(audit_state[1], str)
                    and len(audit_state[1]) == 64
                )
            finally:
                connection.close()
        except (OSError, sqlite3.Error, ApprovalPersistenceError):
            return False

    def close(self) -> None:
        """Release repository lifecycle state after operation-scoped connections close."""

        with self._initialization_lock:
            self._initialized = False

    def verify(self) -> bool:
        self._initialize()
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT * FROM security_audit_events ORDER BY sequence_number"
            ).fetchall()
            previous = _GENESIS
            for sequence, row in enumerate(rows, start=1):
                payload = {
                    "actor_id": row["actor_id"],
                    "audit_event_id": row["audit_event_id"],
                    "event_type": row["event_type"],
                    "occurred_at": row["occurred_at"],
                    "operation": row["operation"],
                    "outcome": row["outcome"],
                    "request_id": row["request_id"],
                    "role": row["role"],
                    "sequence_number": sequence,
                }
                expected = chained_audit_hash(payload, previous)
                if (
                    row["sequence_number"] != sequence
                    or not hmac.compare_digest(previous, row["previous_event_hash"])
                    or not hmac.compare_digest(expected, row["event_hash"])
                ):
                    return False
                previous = row["event_hash"]
            state = connection.execute(
                "SELECT event_count, head_hash FROM security_audit_state WHERE singleton = 1"
            ).fetchone()
            return (
                state is not None
                and state[0] == len(rows)
                and hmac.compare_digest(previous, state[1])
            )
        finally:
            connection.close()
