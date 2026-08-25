"""Fail-closed SQLite schema detection and history-preserving migration."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from ai_business_automation.services.approval_errors import (
    ApprovalPersistenceError,
    SchemaCompatibilityError,
)

ACTIVE_SCHEMA_VERSION = 9
_GENESIS_HASH = "0" * 64


class DatabaseFamily(StrEnum):
    EMPTY = "EMPTY"
    MAIN_V8 = "MAIN_V8"
    VERIFIED_UNVERSIONED = "VERIFIED_UNVERSIONED"
    ACTIVE_V9 = "ACTIVE_V9"


@dataclass(frozen=True, slots=True)
class MigrationResult:
    family: DatabaseFamily
    migrated: bool
    backup_path: Path | None
    source_commitment: str | None


_APPROVAL_COLUMNS = (
    "approval_id",
    "event_id",
    "event_type",
    "source",
    "policy_version",
    "decision",
    "action",
    "risk",
    "confidence",
    "evidence_json",
    "status",
    "created_at",
    "expires_at",
    "decided_at",
    "approver_id",
    "rejection_reason",
    "provenance_json",
    "provenance_hash",
    "action_parameters_json",
    "audit_event_count",
    "audit_head_hash",
)
_MAIN_AUDIT_COLUMNS = (
    "audit_event_id",
    "approval_id",
    "sequence_number",
    "event_type",
    "execution_id",
    "event_id",
    "failure_category",
    "commitment_hash",
    "status",
    "actor_id",
    "occurred_at",
    "previous_event_hash",
    "event_hash",
)
_VERIFIED_AUDIT_COLUMNS = tuple(
    column for column in _MAIN_AUDIT_COLUMNS if column != "commitment_hash"
)
_MAIN_EXECUTION_COLUMNS = (
    "execution_id",
    "approval_id",
    "event_id",
    "action",
    "status",
    "started_at",
    "completed_at",
    "result_code",
    "safe_summary",
    "actor_id",
    "failure_category",
    "action_parameters_hash",
    "effect_hash",
    "reconciled_at",
    "reconciler_id",
    "reconciliation_reason",
    "original_execution_hash",
    "reconciliation_hash",
    "integrity_hash",
)
_VERIFIED_EXECUTION_COLUMNS = (
    "execution_id",
    "approval_id",
    "event_id",
    "action",
    "contact_id",
    "tag",
    "status",
    "created_at",
    "claimed_at",
    "completed_at",
    "failure_category",
    "provenance_hash",
    "policy_version",
    "actor_id",
    "action_parameters_hash",
    "integrity_hash",
)
_INTERNAL_EFFECT_COLUMNS = (
    "execution_id",
    "object_id",
    "object_type",
    "content",
    "created_at",
)
_SECURITY_STATE_COLUMNS = ("singleton", "event_count", "head_hash")
_SECURITY_EVENT_COLUMNS = (
    "audit_event_id",
    "sequence_number",
    "event_type",
    "actor_id",
    "role",
    "request_id",
    "operation",
    "outcome",
    "occurred_at",
    "previous_event_hash",
    "event_hash",
)
_ACTIVE_EXECUTION_COLUMNS = _VERIFIED_EXECUTION_COLUMNS

_ACTIVE_DDL = (
    """
    CREATE TABLE schema_metadata (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        schema_version INTEGER NOT NULL CHECK(schema_version = 9)
    )
    """,
    "INSERT INTO schema_metadata VALUES (1, 9)",
    """
    CREATE TABLE migration_history (
        migration_id TEXT PRIMARY KEY CHECK(length(migration_id) BETWEEN 24 AND 40),
        source_family TEXT NOT NULL CHECK(source_family IN (
            'EMPTY', 'MAIN_V8', 'VERIFIED_UNVERSIONED'
        )),
        target_version INTEGER NOT NULL CHECK(target_version = 9),
        source_commitment TEXT CHECK(source_commitment IS NULL OR length(source_commitment) = 64),
        backup_filename TEXT CHECK(
            backup_filename IS NULL OR length(backup_filename) BETWEEN 1 AND 255
        ),
        completed_at TEXT NOT NULL CHECK(length(completed_at) BETWEEN 20 AND 40)
    )
    """,
    """
    CREATE TABLE approvals (
        approval_id TEXT PRIMARY KEY CHECK(length(approval_id) BETWEEN 24 AND 40),
        event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 20 AND 40),
        event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 64),
        source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 64),
        policy_version TEXT NOT NULL CHECK(policy_version = '1.0'),
        decision TEXT NOT NULL CHECK(decision = 'REQUIRE_HUMAN_APPROVAL'),
        action TEXT NOT NULL CHECK(action IN (
            'NONE', 'REVIEW', 'CONTACT_HUMAN', 'REQUEST_INFORMATION', 'ESCALATE',
            'SCHEDULE_CONSULTATION', 'NURTURE', 'ADD_CONTACT_TAG'
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
    )
    """,
    """
    CREATE TABLE approval_audit_events (
        audit_event_id TEXT PRIMARY KEY CHECK(length(audit_event_id) BETWEEN 24 AND 40),
        approval_id TEXT NOT NULL,
        sequence_number INTEGER NOT NULL CHECK(sequence_number >= 1),
        event_type TEXT NOT NULL CHECK(event_type IN (
            'APPROVAL_CREATED', 'APPROVAL_APPROVED', 'APPROVAL_REJECTED',
            'APPROVAL_EXPIRED', 'APPROVAL_TRANSITION_REJECTED',
            'EXECUTION_AUTHORIZED', 'EXECUTION_CLAIMED', 'EXECUTION_SUCCEEDED',
            'EXECUTION_FAILED', 'EXECUTION_UNKNOWN', 'RECONCILIATION_RECORDED'
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
            'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN'
        )),
        actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
        occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
        previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) = 64),
        event_hash TEXT NOT NULL CHECK(length(event_hash) = 64),
        UNIQUE(approval_id, sequence_number),
        FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
    )
    """,
    """
    CREATE INDEX idx_v9_approval_audit_sequence
    ON approval_audit_events(approval_id, sequence_number)
    """,
    """
    CREATE TABLE executions (
        execution_id TEXT PRIMARY KEY CHECK(length(execution_id) BETWEEN 24 AND 40),
        approval_id TEXT NOT NULL UNIQUE,
        event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 20 AND 40),
        action TEXT NOT NULL CHECK(action = 'ADD_CONTACT_TAG'),
        contact_id TEXT NOT NULL CHECK(length(contact_id) BETWEEN 10 AND 40),
        tag TEXT NOT NULL CHECK(length(tag) BETWEEN 1 AND 50),
        status TEXT NOT NULL CHECK(status IN (
            'PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN'
        )),
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
    )
    """,
    """
    CREATE TABLE execution_reconciliation_assessments (
        assessment_id TEXT PRIMARY KEY CHECK(length(assessment_id) BETWEEN 24 AND 40),
        execution_id TEXT NOT NULL UNIQUE,
        approval_id TEXT NOT NULL,
        provenance_hash TEXT NOT NULL CHECK(length(provenance_hash) = 64),
        policy_version TEXT NOT NULL CHECK(policy_version = '1.0'),
        original_execution_integrity_hash TEXT NOT NULL CHECK(
            length(original_execution_integrity_hash) = 64
        ),
        actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
        occurred_at TEXT NOT NULL CHECK(length(occurred_at) BETWEEN 20 AND 40),
        declared_outcome TEXT NOT NULL CHECK(declared_outcome IN ('SUCCEEDED', 'FAILED')),
        reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
        previous_assessment_hash TEXT NOT NULL CHECK(length(previous_assessment_hash) = 64),
        assessment_hash TEXT NOT NULL CHECK(length(assessment_hash) = 64),
        FOREIGN KEY(execution_id) REFERENCES executions(execution_id) ON DELETE RESTRICT,
        FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TRIGGER execution_reconciliation_assessments_deny_update
    BEFORE UPDATE ON execution_reconciliation_assessments
    BEGIN SELECT RAISE(ABORT, 'immutable history'); END
    """,
    """
    CREATE TRIGGER execution_reconciliation_assessments_deny_delete
    BEFORE DELETE ON execution_reconciliation_assessments
    BEGIN SELECT RAISE(ABORT, 'immutable history'); END
    """,
)


def ensure_active_schema(
    database_path: Path,
    *,
    fault_hook: Callable[[str], None] | None = None,
) -> MigrationResult:
    """Detect and transactionally initialize or archive a known database family."""

    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(database_path)
    backup_path: Path | None = None
    try:
        family = _detect_family(connection)
        if family is DatabaseFamily.ACTIVE_V9:
            _verify_active_schema(connection)
            return MigrationResult(family, False, None, None)
        source_tables = _source_tables(connection, family)
        source_commitment = (
            _database_commitment(connection, source_tables) if source_tables else None
        )
        if family is not DatabaseFamily.EMPTY:
            _verify_source_integrity(connection, family)
            backup_path = _create_backup(connection, database_path)
        if fault_hook is not None:
            fault_hook("after_backup")

        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN EXCLUSIVE")
        try:
            if family is not DatabaseFamily.EMPTY:
                prefix = (
                    "legacy_main_v8"
                    if family is DatabaseFamily.MAIN_V8
                    else "legacy_verified_unversioned"
                )
                for table in source_tables:
                    connection.execute(f'ALTER TABLE "{table}" RENAME TO "{prefix}_{table}"')
                if fault_hook is not None:
                    fault_hook("after_archive")
                _protect_legacy_tables(connection, prefix, source_tables)
            _create_active_schema(connection)
            _record_migration(connection, family, source_commitment, backup_path)
            if family is not DatabaseFamily.EMPTY:
                archive_prefix = (
                    "legacy_main_v8"
                    if family is DatabaseFamily.MAIN_V8
                    else "legacy_verified_unversioned"
                )
                archived = tuple(f"{archive_prefix}_{table}" for table in source_tables)
                if _database_commitment(connection, archived) != source_commitment:
                    raise SchemaCompatibilityError
            _verify_active_schema(connection)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise SchemaCompatibilityError
            if fault_hook is not None:
                fault_hook("before_commit")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")
        return MigrationResult(family, True, backup_path, source_commitment)
    except SchemaCompatibilityError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SchemaCompatibilityError from exc
    finally:
        connection.close()


def _connect(database_path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(database_path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error as exc:
        raise ApprovalPersistenceError from exc


def _detect_family(connection: sqlite3.Connection) -> DatabaseFamily:
    tables = _table_names(connection)
    if not tables:
        return DatabaseFamily.EMPTY
    if "schema_metadata" in tables:
        if _columns(connection, "schema_metadata") != ("singleton", "schema_version"):
            raise SchemaCompatibilityError
        row = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise SchemaCompatibilityError
        version = int(row[0])
        if version == ACTIVE_SCHEMA_VERSION:
            return DatabaseFamily.ACTIVE_V9
        if version == 8:
            _validate_source_shape(connection, DatabaseFamily.MAIN_V8)
            return DatabaseFamily.MAIN_V8
        raise SchemaCompatibilityError
    _validate_source_shape(connection, DatabaseFamily.VERIFIED_UNVERSIONED)
    return DatabaseFamily.VERIFIED_UNVERSIONED


def _validate_source_shape(connection: sqlite3.Connection, family: DatabaseFamily) -> None:
    tables = _table_names(connection)
    allowed = {"approvals", "approval_audit_events"}
    required = set(allowed)
    if family is DatabaseFamily.MAIN_V8:
        allowed.add("schema_metadata")
    optional_groups = (
        {"executions", "internal_action_effects"}
        if family is DatabaseFamily.MAIN_V8
        else {"executions"},
        {"security_audit_state", "security_audit_events"},
    )
    for group in optional_groups:
        present = group & tables
        if present and present != group:
            raise SchemaCompatibilityError
        allowed.update(group)
    if not required.issubset(tables) or not tables.issubset(allowed):
        raise SchemaCompatibilityError
    _require_columns(connection, "approvals", _APPROVAL_COLUMNS)
    _require_columns(
        connection,
        "approval_audit_events",
        _MAIN_AUDIT_COLUMNS if family is DatabaseFamily.MAIN_V8 else _VERIFIED_AUDIT_COLUMNS,
    )
    if "executions" in tables:
        _require_columns(
            connection,
            "executions",
            _MAIN_EXECUTION_COLUMNS
            if family is DatabaseFamily.MAIN_V8
            else _VERIFIED_EXECUTION_COLUMNS,
        )
    if "internal_action_effects" in tables:
        _require_columns(connection, "internal_action_effects", _INTERNAL_EFFECT_COLUMNS)
    if "security_audit_state" in tables:
        _require_columns(connection, "security_audit_state", _SECURITY_STATE_COLUMNS)
        _require_columns(connection, "security_audit_events", _SECURITY_EVENT_COLUMNS)
    if family is DatabaseFamily.MAIN_V8:
        _require_sql_tokens(
            connection,
            "approvals",
            ("GHL_ADD_CONTACT_TAG", "ACTION IN", "PROVENANCE_HASH"),
        )
        _require_sql_tokens(
            connection,
            "approval_audit_events",
            ("COMMITMENT_HASH", "EXECUTION_RECONCILIATION_REQUESTED", "ON DELETE RESTRICT"),
        )
        if "executions" in tables:
            _require_sql_tokens(
                connection,
                "executions",
                ("GHL_ADD_CONTACT_TAG", "RECONCILED_SUCCEEDED", "INTEGRITY_HASH"),
            )
    else:
        _require_sql_tokens(
            connection,
            "approvals",
            ("ADD_CONTACT_TAG", "ACTION IN", "PROVENANCE_HASH"),
        )
        _require_sql_tokens(
            connection,
            "approval_audit_events",
            ("EXECUTION_AUTHORIZED", "ON DELETE RESTRICT"),
        )
        if "executions" in tables:
            _require_sql_tokens(
                connection,
                "executions",
                ("ACTION = 'ADD_CONTACT_TAG'", "PROVENANCE_HASH", "INTEGRITY_HASH"),
            )


def _verify_source_integrity(connection: sqlite3.Connection, family: DatabaseFamily) -> None:
    _verify_approval_integrity(connection, family)
    if "executions" in _table_names(connection):
        if family is DatabaseFamily.MAIN_V8:
            _verify_main_execution_integrity(connection)
        else:
            _verify_verified_execution_integrity(connection)
    if "security_audit_events" in _table_names(connection):
        _verify_security_audit(connection)
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SchemaCompatibilityError


def _verify_approval_integrity(connection: sqlite3.Connection, family: DatabaseFamily) -> None:
    approvals = connection.execute("SELECT * FROM approvals ORDER BY approval_id").fetchall()
    for approval in approvals:
        provenance = json.loads(str(approval["provenance_json"]))
        if not isinstance(provenance, dict):
            raise SchemaCompatibilityError
        expected_provenance = _sha256(_canonical(provenance))
        if not hmac.compare_digest(expected_provenance, str(approval["provenance_hash"])):
            raise SchemaCompatibilityError
        parameters = (
            json.loads(str(approval["action_parameters_json"]))
            if approval["action_parameters_json"] is not None
            else None
        )
        bindings = {
            "event_id": approval["event_id"],
            "event_type": approval["event_type"],
            "source": approval["source"],
            "policy_version": approval["policy_version"],
            "decision": approval["decision"],
            "action": approval["action"],
            "risk": approval["risk"],
            "confidence": approval["confidence"],
            "evidence": json.loads(str(approval["evidence_json"])),
            "action_parameters": parameters,
        }
        if any(provenance.get(key) != value for key, value in bindings.items()):
            raise SchemaCompatibilityError
        events = connection.execute(
            "SELECT * FROM approval_audit_events WHERE approval_id = ? ORDER BY sequence_number",
            (approval["approval_id"],),
        ).fetchall()
        if len(events) != int(approval["audit_event_count"]):
            raise SchemaCompatibilityError
        previous = _GENESIS_HASH
        for sequence, event in enumerate(events, start=1):
            if (
                int(event["sequence_number"]) != sequence
                or event["previous_event_hash"] != previous
            ):
                raise SchemaCompatibilityError
            payload = {
                "actor_id": event["actor_id"],
                "approval_id": event["approval_id"],
                "audit_event_id": event["audit_event_id"],
                "event_type": event["event_type"],
                "event_id": event["event_id"],
                "execution_id": event["execution_id"],
                "failure_category": event["failure_category"],
            }
            if family is DatabaseFamily.MAIN_V8:
                payload["commitment_hash"] = event["commitment_hash"]
            payload.update(
                {
                    "occurred_at": event["occurred_at"],
                    "sequence_number": sequence,
                    "status": event["status"],
                }
            )
            expected = _chained_hash(payload, previous)
            if not hmac.compare_digest(expected, str(event["event_hash"])):
                raise SchemaCompatibilityError
            previous = str(event["event_hash"])
        if not hmac.compare_digest(previous, str(approval["audit_head_hash"])):
            raise SchemaCompatibilityError


def _verify_main_execution_integrity(connection: sqlite3.Connection) -> None:
    approvals = {
        str(row["approval_id"]): row
        for row in connection.execute("SELECT * FROM approvals").fetchall()
    }
    effects = {
        str(row["execution_id"]): row
        for row in connection.execute("SELECT * FROM internal_action_effects").fetchall()
    }
    executions = connection.execute("SELECT * FROM executions ORDER BY execution_id").fetchall()
    for row in executions:
        approval = approvals.get(str(row["approval_id"]))
        if approval is None or row["event_id"] != approval["event_id"]:
            raise SchemaCompatibilityError
        expected_action = {
            "NONE": "NO_OP",
            "REVIEW": "UPDATE_INTERNAL_STATUS",
            "CONTACT_HUMAN": "REQUEST_HUMAN_REVIEW",
            "REQUEST_INFORMATION": "CREATE_INTERNAL_TASK",
            "ESCALATE": "CREATE_INTERNAL_TASK",
            "SCHEDULE_CONSULTATION": "CREATE_INTERNAL_TASK",
            "NURTURE": "GENERATE_INTERNAL_NOTE",
            "GHL_ADD_CONTACT_TAG": "GHL_ADD_CONTACT_TAG",
        }.get(str(approval["action"]))
        if row["action"] != expected_action:
            raise SchemaCompatibilityError
        payload = _main_execution_payload(row)
        if not hmac.compare_digest(_sha256(_canonical(payload)), str(row["integrity_hash"])):
            raise SchemaCompatibilityError
        expected_parameters = (
            _sha256(_canonical(json.loads(str(approval["action_parameters_json"]))))
            if approval["action_parameters_json"] is not None
            else None
        )
        if row["action_parameters_hash"] != expected_parameters:
            raise SchemaCompatibilityError
        effect = effects.get(str(row["execution_id"]))
        if row["status"] == "SUCCEEDED":
            if effect is None:
                if row["effect_hash"] != _sha256(_canonical(None)):
                    raise SchemaCompatibilityError
            else:
                effect_payload = {
                    "content": effect["content"],
                    "object_id": effect["object_id"],
                    "object_type": effect["object_type"],
                }
                if row["effect_hash"] != _sha256(_canonical(effect_payload)):
                    raise SchemaCompatibilityError
        elif effect is not None or row["effect_hash"] is not None:
            raise SchemaCompatibilityError
        _verify_main_reconciliation(row, approval)
    if set(effects) - {str(row["execution_id"]) for row in executions}:
        raise SchemaCompatibilityError


def _verify_main_reconciliation(row: sqlite3.Row, approval: sqlite3.Row) -> None:
    fields = (
        row["reconciled_at"],
        row["reconciler_id"],
        row["reconciliation_reason"],
        row["original_execution_hash"],
        row["reconciliation_hash"],
    )
    reconciled = row["status"] in {"RECONCILED_SUCCEEDED", "RECONCILED_FAILED"}
    if not reconciled:
        if any(value is not None for value in fields):
            raise SchemaCompatibilityError
        return
    if (
        not all(isinstance(value, str) for value in fields)
        or row["action"] != "GHL_ADD_CONTACT_TAG"
    ):
        raise SchemaCompatibilityError
    outcome = "SUCCEEDED" if row["status"] == "RECONCILED_SUCCEEDED" else "FAILED"
    commitment = {
        "action": row["action"],
        "approval_id": row["approval_id"],
        "event_id": row["event_id"],
        "execution_id": row["execution_id"],
        "original_execution_hash": row["original_execution_hash"],
        "original_status": "UNKNOWN",
        "outcome": outcome,
        "policy_version": approval["policy_version"],
        "reason": row["reconciliation_reason"],
        "reconciled_at": row["reconciled_at"],
        "reconciler_id": row["reconciler_id"],
    }
    if not hmac.compare_digest(_sha256(_canonical(commitment)), str(row["reconciliation_hash"])):
        raise SchemaCompatibilityError


def _main_execution_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "action": row["action"],
        "actor_id": row["actor_id"],
        "approval_id": row["approval_id"],
        "completed_at": row["completed_at"],
        "event_id": row["event_id"],
        "effect_hash": row["effect_hash"],
        "failure_category": row["failure_category"],
        "action_parameters_hash": row["action_parameters_hash"],
        "reconciled_at": row["reconciled_at"],
        "reconciler_id": row["reconciler_id"],
        "reconciliation_reason": row["reconciliation_reason"],
        "original_execution_hash": row["original_execution_hash"],
        "reconciliation_hash": row["reconciliation_hash"],
        "execution_id": row["execution_id"],
        "result_code": row["result_code"],
        "safe_summary": row["safe_summary"],
        "started_at": row["started_at"],
        "status": row["status"],
    }


def _verify_verified_execution_integrity(connection: sqlite3.Connection) -> None:
    approvals = {
        str(row["approval_id"]): row
        for row in connection.execute("SELECT * FROM approvals").fetchall()
    }
    for row in connection.execute("SELECT * FROM executions ORDER BY execution_id").fetchall():
        approval = approvals.get(str(row["approval_id"]))
        if approval is None:
            raise SchemaCompatibilityError
        payload = {
            "action": "ADD_CONTACT_TAG",
            "action_parameters_hash": row["action_parameters_hash"],
            "actor_id": row["actor_id"],
            "approval_id": row["approval_id"],
            "claimed_at": row["claimed_at"],
            "completed_at": row["completed_at"],
            "contact_id": row["contact_id"],
            "created_at": row["created_at"],
            "event_id": row["event_id"],
            "execution_id": row["execution_id"],
            "failure_category": row["failure_category"],
            "policy_version": row["policy_version"],
            "provenance_hash": row["provenance_hash"],
            "status": row["status"],
            "tag": row["tag"],
        }
        parameters = {"contact_id": row["contact_id"], "tag": row["tag"]}
        approval_parameters = json.loads(str(approval["action_parameters_json"]))
        if (
            not hmac.compare_digest(_sha256(_canonical(payload)), str(row["integrity_hash"]))
            or not hmac.compare_digest(
                _sha256(_canonical(parameters)), str(row["action_parameters_hash"])
            )
            or row["provenance_hash"] != approval["provenance_hash"]
            or row["policy_version"] != approval["policy_version"]
            or row["event_id"] != approval["event_id"]
            or approval["action"] != "ADD_CONTACT_TAG"
            or parameters != approval_parameters
        ):
            raise SchemaCompatibilityError


def _verify_security_audit(connection: sqlite3.Connection) -> None:
    state = connection.execute(
        "SELECT event_count, head_hash FROM security_audit_state WHERE singleton = 1"
    ).fetchone()
    if state is None:
        raise SchemaCompatibilityError
    previous = _GENESIS_HASH
    events = connection.execute(
        "SELECT * FROM security_audit_events ORDER BY sequence_number"
    ).fetchall()
    for sequence, event in enumerate(events, start=1):
        payload = {
            "actor_id": event["actor_id"],
            "audit_event_id": event["audit_event_id"],
            "event_type": event["event_type"],
            "occurred_at": event["occurred_at"],
            "operation": event["operation"],
            "outcome": event["outcome"],
            "request_id": event["request_id"],
            "role": event["role"],
            "sequence_number": sequence,
        }
        if (
            int(event["sequence_number"]) != sequence
            or event["previous_event_hash"] != previous
            or not hmac.compare_digest(_chained_hash(payload, previous), str(event["event_hash"]))
        ):
            raise SchemaCompatibilityError
        previous = str(event["event_hash"])
    if int(state["event_count"]) != len(events) or not hmac.compare_digest(
        previous, str(state["head_hash"])
    ):
        raise SchemaCompatibilityError


def _create_backup(connection: sqlite3.Connection, database_path: Path) -> Path:
    suffix = secrets.token_hex(8)
    backup_path = database_path.with_name(f"{database_path.name}.pre-v9-{suffix}.bak")
    backup = sqlite3.connect(backup_path)
    try:
        connection.backup(backup)
    finally:
        backup.close()
    return backup_path


def _create_active_schema(connection: sqlite3.Connection) -> None:
    for statement in _ACTIVE_DDL:
        connection.execute(statement)


def _record_migration(
    connection: sqlite3.Connection,
    family: DatabaseFamily,
    source_commitment: str | None,
    backup_path: Path | None,
) -> None:
    connection.execute(
        "INSERT INTO migration_history VALUES (?, ?, 9, ?, ?, ?)",
        (
            f"mig_{secrets.token_urlsafe(18)}",
            family.value,
            source_commitment,
            backup_path.name if backup_path is not None else None,
            datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        ),
    )


def _protect_legacy_tables(
    connection: sqlite3.Connection, prefix: str, source_tables: Iterable[str]
) -> None:
    for source_table in source_tables:
        table = f"{prefix}_{source_table}"
        for operation in ("insert", "update", "delete"):
            connection.execute(_immutable_trigger(table, operation))


def _immutable_trigger(table: str, operation: str) -> str:
    return (
        f'CREATE TRIGGER "{table}_deny_{operation}" BEFORE {operation.upper()} ON "{table}" '
        "BEGIN SELECT RAISE(ABORT, 'immutable history'); END"
    )


def _verify_active_schema(connection: sqlite3.Connection) -> None:
    required = {
        "schema_metadata",
        "migration_history",
        "approvals",
        "approval_audit_events",
        "executions",
        "execution_reconciliation_assessments",
    }
    tables = _table_names(connection)
    if not required.issubset(tables):
        raise SchemaCompatibilityError
    row = connection.execute(
        "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if row is None or int(row[0]) != ACTIVE_SCHEMA_VERSION:
        raise SchemaCompatibilityError
    _require_columns(connection, "approvals", _APPROVAL_COLUMNS)
    _require_columns(connection, "approval_audit_events", _MAIN_AUDIT_COLUMNS)
    _require_columns(connection, "executions", _ACTIVE_EXECUTION_COLUMNS)
    _require_columns(
        connection,
        "execution_reconciliation_assessments",
        (
            "assessment_id",
            "execution_id",
            "approval_id",
            "provenance_hash",
            "policy_version",
            "original_execution_integrity_hash",
            "actor_id",
            "occurred_at",
            "declared_outcome",
            "reason",
            "previous_assessment_hash",
            "assessment_hash",
        ),
    )
    _require_sql_tokens(
        connection,
        "executions",
        ("ACTION = 'ADD_CONTACT_TAG'", "PROVENANCE_HASH", "INTEGRITY_HASH"),
    )
    trigger_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
    }
    if not {
        "execution_reconciliation_assessments_deny_update",
        "execution_reconciliation_assessments_deny_delete",
    }.issubset(trigger_names):
        raise SchemaCompatibilityError


def _source_tables(connection: sqlite3.Connection, family: DatabaseFamily) -> tuple[str, ...]:
    if family in {DatabaseFamily.EMPTY, DatabaseFamily.ACTIVE_V9}:
        return ()
    return tuple(sorted(_table_names(connection)))


def _database_commitment(connection: sqlite3.Connection, tables: Iterable[str]) -> str:
    content: list[dict[str, Any]] = []
    for table in sorted(tables):
        rows = _commitment_rows(connection, table)
        content.append(
            {
                "columns": list(_columns(connection, table)),
                "rows": [[_json_value(value) for value in row] for row in rows],
                "table": table.split("_", 3)[-1] if table.startswith("legacy_") else table,
            }
        )
    return _sha256(_canonical(content))


def _commitment_rows(connection: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    queries = {
        "approval_audit_events": "SELECT * FROM approval_audit_events ORDER BY rowid",
        "approvals": "SELECT * FROM approvals ORDER BY rowid",
        "executions": "SELECT * FROM executions ORDER BY rowid",
        "internal_action_effects": "SELECT * FROM internal_action_effects ORDER BY rowid",
        "schema_metadata": "SELECT * FROM schema_metadata ORDER BY rowid",
        "security_audit_events": "SELECT * FROM security_audit_events ORDER BY rowid",
        "security_audit_state": "SELECT * FROM security_audit_state ORDER BY rowid",
        "legacy_main_v8_approval_audit_events": (
            "SELECT * FROM legacy_main_v8_approval_audit_events ORDER BY rowid"
        ),
        "legacy_main_v8_approvals": "SELECT * FROM legacy_main_v8_approvals ORDER BY rowid",
        "legacy_main_v8_executions": "SELECT * FROM legacy_main_v8_executions ORDER BY rowid",
        "legacy_main_v8_internal_action_effects": (
            "SELECT * FROM legacy_main_v8_internal_action_effects ORDER BY rowid"
        ),
        "legacy_main_v8_schema_metadata": (
            "SELECT * FROM legacy_main_v8_schema_metadata ORDER BY rowid"
        ),
        "legacy_main_v8_security_audit_events": (
            "SELECT * FROM legacy_main_v8_security_audit_events ORDER BY rowid"
        ),
        "legacy_main_v8_security_audit_state": (
            "SELECT * FROM legacy_main_v8_security_audit_state ORDER BY rowid"
        ),
        "legacy_verified_unversioned_approval_audit_events": (
            "SELECT * FROM legacy_verified_unversioned_approval_audit_events ORDER BY rowid"
        ),
        "legacy_verified_unversioned_approvals": (
            "SELECT * FROM legacy_verified_unversioned_approvals ORDER BY rowid"
        ),
        "legacy_verified_unversioned_executions": (
            "SELECT * FROM legacy_verified_unversioned_executions ORDER BY rowid"
        ),
        "legacy_verified_unversioned_security_audit_events": (
            "SELECT * FROM legacy_verified_unversioned_security_audit_events ORDER BY rowid"
        ),
        "legacy_verified_unversioned_security_audit_state": (
            "SELECT * FROM legacy_verified_unversioned_security_audit_state ORDER BY rowid"
        ),
    }
    query = queries.get(table)
    if query is None:
        raise SchemaCompatibilityError
    return connection.execute(query).fetchall()


def _json_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_sha256": _sha256(value)}
    if value is None or isinstance(value, str | int | float):
        return value
    raise SchemaCompatibilityError


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")'))


def _require_columns(connection: sqlite3.Connection, table: str, expected: tuple[str, ...]) -> None:
    if _columns(connection, table) != expected:
        raise SchemaCompatibilityError


def _require_sql_tokens(
    connection: sqlite3.Connection, table: str, tokens: tuple[str, ...]
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        raise SchemaCompatibilityError
    normalized = " ".join(str(row[0]).upper().split())
    if any(token.upper() not in normalized for token in tokens):
        raise SchemaCompatibilityError


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _chained_hash(payload: object, previous: str) -> str:
    return _sha256(_canonical(payload) + previous.encode("ascii"))
