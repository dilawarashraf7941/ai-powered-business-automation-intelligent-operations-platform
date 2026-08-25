"""Schema-9 migration, immutable legacy history, and assessment-ledger tests."""

import hashlib
import json
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ai_business_automation.repositories import SQLiteApprovalRepository, migrations
from ai_business_automation.repositories.migrations import (
    ACTIVE_SCHEMA_VERSION,
    DatabaseFamily,
    ensure_active_schema,
)
from ai_business_automation.services.approval_errors import (
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    SchemaCompatibilityError,
)

NOW = "2026-08-25T00:00:00Z"
GENESIS = "0" * 64

_MAIN_SCHEMA = """
CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 8)
);
INSERT INTO schema_metadata VALUES (1, 8);
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, event_type TEXT NOT NULL,
    source TEXT NOT NULL, policy_version TEXT NOT NULL, decision TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('NONE', 'REVIEW', 'GHL_ADD_CONTACT_TAG')),
    risk TEXT NOT NULL, confidence REAL NOT NULL, evidence_json TEXT NOT NULL,
    status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    decided_at TEXT, approver_id TEXT, rejection_reason TEXT, provenance_json TEXT NOT NULL,
    provenance_hash TEXT NOT NULL, action_parameters_json TEXT,
    audit_event_count INTEGER NOT NULL, audit_head_hash TEXT NOT NULL
);
CREATE TABLE approval_audit_events (
    audit_event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL, event_type TEXT NOT NULL CHECK(event_type IN (
        'APPROVAL_CREATED', 'APPROVAL_APPROVED', 'EXECUTION_CREATED',
        'EXECUTION_CLAIMED', 'EXECUTION_UNKNOWN', 'EXECUTION_RECONCILIATION_REQUESTED',
        'EXECUTION_RECONCILED_SUCCEEDED'
    )), execution_id TEXT, event_id TEXT, failure_category TEXT, commitment_hash TEXT,
    status TEXT NOT NULL, actor_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
    UNIQUE(approval_id, sequence_number),
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);
CREATE TABLE executions (
    execution_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL UNIQUE, event_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('NO_OP', 'UPDATE_INTERNAL_STATUS',
        'GHL_ADD_CONTACT_TAG')), status TEXT NOT NULL CHECK(status IN (
        'PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'UNKNOWN',
        'RECONCILED_SUCCEEDED', 'RECONCILED_FAILED'
    )), started_at TEXT NOT NULL, completed_at TEXT, result_code TEXT, safe_summary TEXT,
    actor_id TEXT NOT NULL, failure_category TEXT, action_parameters_hash TEXT,
    effect_hash TEXT, reconciled_at TEXT, reconciler_id TEXT,
    reconciliation_reason TEXT, original_execution_hash TEXT,
    reconciliation_hash TEXT, integrity_hash TEXT NOT NULL,
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);
CREATE TABLE internal_action_effects (
    execution_id TEXT PRIMARY KEY, object_id TEXT UNIQUE, object_type TEXT NOT NULL,
    content TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES executions(execution_id) ON DELETE RESTRICT
);
"""

_VERIFIED_SCHEMA = """
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, event_type TEXT NOT NULL,
    source TEXT NOT NULL, policy_version TEXT NOT NULL, decision TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('NONE', 'REVIEW', 'ADD_CONTACT_TAG')),
    risk TEXT NOT NULL, confidence REAL NOT NULL, evidence_json TEXT NOT NULL,
    status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    decided_at TEXT, approver_id TEXT, rejection_reason TEXT, provenance_json TEXT NOT NULL,
    provenance_hash TEXT NOT NULL, action_parameters_json TEXT,
    audit_event_count INTEGER NOT NULL, audit_head_hash TEXT NOT NULL
);
CREATE TABLE approval_audit_events (
    audit_event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL, event_type TEXT NOT NULL CHECK(event_type IN (
        'APPROVAL_CREATED', 'APPROVAL_APPROVED', 'EXECUTION_AUTHORIZED',
        'EXECUTION_CLAIMED', 'EXECUTION_UNKNOWN'
    )), execution_id TEXT, event_id TEXT, failure_category TEXT,
    status TEXT NOT NULL, actor_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
    UNIQUE(approval_id, sequence_number),
    FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
);
"""


@pytest.fixture
def migration_tmp_path() -> Iterator[Path]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = root / f"migration-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _chain(payload: object, previous: str) -> str:
    return _hash(_canonical(payload) + previous.encode("ascii"))


def _provenance(action: str, event_id: str, parameters: object) -> dict[str, object]:
    return {
        "event_id": event_id,
        "event_type": "GHL_CONTACT_TAG_REQUEST" if "CONTACT_TAG" in action else "CUSTOMER_REQUEST",
        "source": "INTERNAL" if "CONTACT_TAG" in action else "API",
        "policy_version": "1.0",
        "decision": "REQUIRE_HUMAN_APPROVAL",
        "action": action,
        "risk": "MEDIUM",
        "confidence": 0.91,
        "evidence": [{"code": "POLICY_CONDITIONS_SATISFIED", "source": "POLICY", "value": None}],
        "canonical_event_sha256": "1" * 64,
        "canonical_intelligence_sha256": "2" * 64,
        "action_parameters": parameters,
    }


def _insert_approval(
    connection: sqlite3.Connection,
    *,
    family: DatabaseFamily,
    approval_id: str,
    event_id: str,
    action: str,
    parameters: object,
    approved: bool = True,
) -> tuple[str, str]:
    provenance = _provenance(action, event_id, parameters)
    evidence = provenance["evidence"]
    provenance_text = _canonical(provenance).decode()
    parameters_text = _canonical(parameters).decode() if parameters is not None else None
    events: list[dict[str, object]] = []
    previous = GENESIS
    event_names = ["APPROVAL_CREATED", "APPROVAL_APPROVED"] if approved else ["APPROVAL_CREATED"]
    for sequence, event_type in enumerate(event_names, start=1):
        event = {
            "audit_event_id": f"aud_{_hash(f'{approval_id}:{sequence}'.encode())[:21]}",
            "approval_id": approval_id,
            "sequence_number": sequence,
            "event_type": event_type,
            "execution_id": None,
            "event_id": None,
            "failure_category": None,
            "commitment_hash": None,
            "status": "APPROVED" if sequence == 2 else "PENDING",
            "actor_id": "fixture-actor",
            "occurred_at": NOW,
            "previous_event_hash": previous,
        }
        payload = {
            "actor_id": event["actor_id"],
            "approval_id": approval_id,
            "audit_event_id": event["audit_event_id"],
            "event_type": event_type,
            "event_id": None,
            "execution_id": None,
            "failure_category": None,
        }
        if family is DatabaseFamily.MAIN_V8:
            payload["commitment_hash"] = None
        payload.update(
            {
                "occurred_at": NOW,
                "sequence_number": sequence,
                "status": event["status"],
            }
        )
        previous = _chain(payload, previous)
        event["event_hash"] = previous
        events.append(event)
    connection.execute(
        "INSERT INTO approvals VALUES (?, ?, ?, ?, '1.0', 'REQUIRE_HUMAN_APPROVAL', "
        "?, 'MEDIUM', 0.91, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
        (
            approval_id,
            event_id,
            provenance["event_type"],
            provenance["source"],
            action,
            _canonical(evidence).decode(),
            "APPROVED" if approved else "PENDING",
            NOW,
            "2026-08-26T00:00:00Z",
            NOW if approved else None,
            "fixture-actor" if approved else None,
            provenance_text,
            _hash(provenance_text.encode()),
            parameters_text,
            len(events),
            previous,
        ),
    )
    for event in events:
        values = (
            event["audit_event_id"],
            event["approval_id"],
            event["sequence_number"],
            event["event_type"],
            event["execution_id"],
            event["event_id"],
            event["failure_category"],
        )
        tail = (
            event["status"],
            event["actor_id"],
            event["occurred_at"],
            event["previous_event_hash"],
            event["event_hash"],
        )
        if family is DatabaseFamily.MAIN_V8:
            connection.execute(
                "INSERT INTO approval_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*values, event["commitment_hash"], *tail),
            )
        else:
            connection.execute(
                "INSERT INTO approval_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values + tail,
            )
    return provenance_text, previous


def _append_main_event(
    connection: sqlite3.Connection,
    approval_id: str,
    event_type: str,
    status: str,
    sequence: int,
    previous: str,
    execution_id: str,
    commitment: str | None = None,
) -> str:
    audit_id = f"aud_{_hash(f'{approval_id}:{sequence}'.encode())[:21]}"
    payload = {
        "actor_id": "fixture-executor",
        "approval_id": approval_id,
        "audit_event_id": audit_id,
        "event_type": event_type,
        "event_id": "evt_reconciled_history",
        "execution_id": execution_id,
        "failure_category": "GHL_TIMEOUT" if status == "UNKNOWN" else None,
        "commitment_hash": commitment,
        "occurred_at": NOW,
        "sequence_number": sequence,
        "status": status,
    }
    event_hash = _chain(payload, previous)
    connection.execute(
        "INSERT INTO approval_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            audit_id,
            approval_id,
            sequence,
            event_type,
            execution_id,
            "evt_reconciled_history",
            payload["failure_category"],
            commitment,
            status,
            "fixture-executor",
            NOW,
            previous,
            event_hash,
        ),
    )
    return event_hash


def _insert_reconciled_execution(connection: sqlite3.Connection, approval_id: str) -> None:
    execution_id = "exe_reconciled_history_01"
    parameters = {"contact_id": "contact_123456", "tags": ["qualified"]}
    parameters_hash = _hash(_canonical(parameters))
    original_hash = "3" * 64
    reconciliation = {
        "action": "GHL_ADD_CONTACT_TAG",
        "approval_id": approval_id,
        "event_id": "evt_reconciled_history",
        "execution_id": execution_id,
        "original_execution_hash": original_hash,
        "original_status": "UNKNOWN",
        "outcome": "SUCCEEDED",
        "policy_version": "1.0",
        "reason": "Verified in the provider console.",
        "reconciled_at": NOW,
        "reconciler_id": "fixture-reconciler",
    }
    reconciliation_hash = _hash(_canonical(reconciliation))
    row = {
        "action": "GHL_ADD_CONTACT_TAG",
        "actor_id": "fixture-executor",
        "approval_id": approval_id,
        "completed_at": NOW,
        "event_id": "evt_reconciled_history",
        "effect_hash": None,
        "failure_category": "GHL_TIMEOUT",
        "action_parameters_hash": parameters_hash,
        "reconciled_at": NOW,
        "reconciler_id": "fixture-reconciler",
        "reconciliation_reason": "Verified in the provider console.",
        "original_execution_hash": original_hash,
        "reconciliation_hash": reconciliation_hash,
        "execution_id": execution_id,
        "result_code": "RECONCILED",
        "safe_summary": "Execution externally reconciled as succeeded.",
        "started_at": NOW,
        "status": "RECONCILED_SUCCEEDED",
    }
    connection.execute(
        "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            execution_id,
            approval_id,
            row["event_id"],
            row["action"],
            row["status"],
            row["started_at"],
            row["completed_at"],
            row["result_code"],
            row["safe_summary"],
            row["actor_id"],
            row["failure_category"],
            row["action_parameters_hash"],
            row["effect_hash"],
            row["reconciled_at"],
            row["reconciler_id"],
            row["reconciliation_reason"],
            row["original_execution_hash"],
            row["reconciliation_hash"],
            _hash(_canonical(row)),
        ),
    )
    approval = connection.execute(
        "SELECT audit_event_count, audit_head_hash FROM approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    assert approval is not None
    previous = str(approval[1])
    sequence = int(approval[0])
    for event_type, status, commitment in (
        ("EXECUTION_CREATED", "PENDING", None),
        ("EXECUTION_CLAIMED", "CLAIMED", None),
        ("EXECUTION_UNKNOWN", "UNKNOWN", None),
        ("EXECUTION_RECONCILIATION_REQUESTED", "UNKNOWN", reconciliation_hash),
        ("EXECUTION_RECONCILED_SUCCEEDED", "RECONCILED_SUCCEEDED", reconciliation_hash),
    ):
        sequence += 1
        previous = _append_main_event(
            connection,
            approval_id,
            event_type,
            status,
            sequence,
            previous,
            execution_id,
            commitment,
        )
    connection.execute(
        "UPDATE approvals SET audit_event_count = ?, audit_head_hash = ? WHERE approval_id = ?",
        (sequence, previous, approval_id),
    )


def _main_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_MAIN_SCHEMA)
        _insert_approval(
            connection,
            family=DatabaseFamily.MAIN_V8,
            approval_id="apr_multi_tag_history_001",
            event_id="evt_multi_tag_history_01",
            action="GHL_ADD_CONTACT_TAG",
            parameters={"contact_id": "contact_123456", "tags": ["one", "two"]},
        )
        _insert_approval(
            connection,
            family=DatabaseFamily.MAIN_V8,
            approval_id="apr_non_contact_history_1",
            event_id="evt_non_contact_history1",
            action="REVIEW",
            parameters=None,
        )
        _insert_approval(
            connection,
            family=DatabaseFamily.MAIN_V8,
            approval_id="apr_reconciled_history_1",
            event_id="evt_reconciled_history",
            action="GHL_ADD_CONTACT_TAG",
            parameters={"contact_id": "contact_123456", "tags": ["qualified"]},
        )
        _insert_reconciled_execution(connection, "apr_reconciled_history_1")
        connection.commit()
    finally:
        connection.close()


def _verified_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_VERIFIED_SCHEMA)
        _insert_approval(
            connection,
            family=DatabaseFamily.VERIFIED_UNVERSIONED,
            approval_id="apr_verified_history_001",
            event_id="evt_verified_history_01",
            action="ADD_CONTACT_TAG",
            parameters={"contact_id": "contact_123456", "tag": "qualified"},
        )
        connection.commit()
    finally:
        connection.close()


def _add_verified_execution(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE executions (
                execution_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL UNIQUE,
                event_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action = 'ADD_CONTACT_TAG'),
                contact_id TEXT NOT NULL, tag TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL,
                claimed_at TEXT NOT NULL, completed_at TEXT,
                failure_category TEXT, provenance_hash TEXT NOT NULL,
                policy_version TEXT NOT NULL, actor_id TEXT NOT NULL,
                action_parameters_hash TEXT NOT NULL, integrity_hash TEXT NOT NULL,
                FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE RESTRICT
            )
            """
        )
        approval = connection.execute(
            "SELECT * FROM approvals WHERE approval_id = 'apr_verified_history_001'"
        ).fetchone()
        assert approval is not None
        parameters = {"contact_id": "contact_123456", "tag": "qualified"}
        row = {
            "action": "ADD_CONTACT_TAG",
            "action_parameters_hash": _hash(_canonical(parameters)),
            "actor_id": "fixture-executor",
            "approval_id": "apr_verified_history_001",
            "claimed_at": NOW,
            "completed_at": NOW,
            "contact_id": "contact_123456",
            "created_at": NOW,
            "event_id": "evt_verified_history_01",
            "execution_id": "exe_verified_history_001",
            "failure_category": None,
            "policy_version": "1.0",
            "provenance_hash": str(approval[17]),
            "status": "SUCCEEDED",
            "tag": "qualified",
        }
        connection.execute(
            "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["execution_id"],
                row["approval_id"],
                row["event_id"],
                row["action"],
                row["contact_id"],
                row["tag"],
                row["status"],
                row["created_at"],
                row["claimed_at"],
                row["completed_at"],
                row["failure_category"],
                row["provenance_hash"],
                row["policy_version"],
                row["actor_id"],
                row["action_parameters_hash"],
                _hash(_canonical(row)),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _add_security_audit(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE security_audit_state (
                singleton INTEGER PRIMARY KEY,
                event_count INTEGER NOT NULL,
                head_hash TEXT NOT NULL
            );
            CREATE TABLE security_audit_events (
                audit_event_id TEXT PRIMARY KEY,
                sequence_number INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                previous_event_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            """
        )
        payload = {
            "actor_id": "fixture-admin",
            "audit_event_id": "sec_fixture_history_00001",
            "event_type": "AUTHORIZATION_SUCCEEDED",
            "occurred_at": NOW,
            "operation": "execute_action",
            "outcome": "success",
            "request_id": "req_fixture_history_00001",
            "role": "ADMIN",
            "sequence_number": 1,
        }
        event_hash = _chain(payload, GENESIS)
        connection.execute("INSERT INTO security_audit_state VALUES (1, 1, ?)", (event_hash,))
        connection.execute(
            "INSERT INTO security_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                payload["audit_event_id"],
                1,
                payload["event_type"],
                payload["actor_id"],
                payload["role"],
                payload["request_id"],
                payload["operation"],
                payload["outcome"],
                payload["occurred_at"],
                GENESIS,
                event_hash,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _add_main_succeeded_effect(path: Path) -> tuple[str, str]:
    connection = sqlite3.connect(path)
    try:
        approval_id = "apr_succeeded_history_001"
        _insert_approval(
            connection,
            family=DatabaseFamily.MAIN_V8,
            approval_id=approval_id,
            event_id="evt_succeeded_history_01",
            action="GHL_ADD_CONTACT_TAG",
            parameters={"contact_id": "contact_123456", "tags": ["qualified"]},
        )
        execution_id = "exe_succeeded_history_001"
        parameters_hash = _hash(_canonical({"contact_id": "contact_123456", "tags": ["qualified"]}))
        effect = {
            "content": "qualified",
            "object_id": "contact_123456",
            "object_type": "GHL_CONTACT_TAG",
        }
        effect_hash = _hash(_canonical(effect))
        row = {
            "action": "GHL_ADD_CONTACT_TAG",
            "actor_id": "fixture-executor",
            "approval_id": approval_id,
            "completed_at": NOW,
            "event_id": "evt_succeeded_history_01",
            "effect_hash": effect_hash,
            "failure_category": None,
            "action_parameters_hash": parameters_hash,
            "reconciled_at": None,
            "reconciler_id": None,
            "reconciliation_reason": None,
            "original_execution_hash": None,
            "reconciliation_hash": None,
            "execution_id": execution_id,
            "result_code": "TAG_ADDED",
            "safe_summary": "Contact tag added.",
            "started_at": NOW,
            "status": "SUCCEEDED",
        }
        connection.execute(
            "INSERT INTO executions VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                execution_id,
                approval_id,
                row["event_id"],
                row["action"],
                row["status"],
                row["started_at"],
                row["completed_at"],
                row["result_code"],
                row["safe_summary"],
                row["actor_id"],
                row["failure_category"],
                row["action_parameters_hash"],
                row["effect_hash"],
                None,
                None,
                None,
                None,
                None,
                _hash(_canonical(row)),
            ),
        )
        connection.execute(
            "INSERT INTO internal_action_effects VALUES (?, ?, ?, ?, ?)",
            (execution_id, effect["object_id"], effect["object_type"], effect["content"], NOW),
        )
        connection.commit()
        return approval_id, execution_id
    finally:
        connection.close()


def _refresh_main_execution_integrity(connection: sqlite3.Connection, execution_id: str) -> None:
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
    ).fetchone()
    assert row is not None
    connection.execute(
        "UPDATE executions SET integrity_hash = ? WHERE execution_id = ?",
        (_hash(_canonical(migrations._main_execution_payload(row))), execution_id),
    )


def _tables(path: Path) -> set[str]:
    connection = sqlite3.connect(path)
    try:
        return {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        connection.close()


def test_empty_database_initializes_and_is_idempotent(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "empty.sqlite3"
    first = ensure_active_schema(database)
    second = ensure_active_schema(database)
    assert first.family is DatabaseFamily.EMPTY and first.migrated
    assert second.family is DatabaseFamily.ACTIVE_V9 and not second.migrated
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT schema_version FROM schema_metadata").fetchone() == (
            ACTIVE_SCHEMA_VERSION,
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT count(*) FROM migration_history").fetchone() == (1,)
    finally:
        connection.close()


def test_main_v8_is_backed_up_and_archived_without_reinterpretation(
    migration_tmp_path: Path,
) -> None:
    database = migration_tmp_path / "main.sqlite3"
    _main_database(database)
    result = ensure_active_schema(database)
    assert result.family is DatabaseFamily.MAIN_V8 and result.migrated
    assert result.backup_path is not None and result.backup_path.is_file()
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM legacy_main_v8_approvals").fetchone() == (
            3,
        )
        assert connection.execute(
            "SELECT action_parameters_json FROM legacy_main_v8_approvals "
            "WHERE approval_id = 'apr_multi_tag_history_001'"
        ).fetchone() == ('{"contact_id":"contact_123456","tags":["one","two"]}',)
        assert connection.execute("SELECT status FROM legacy_main_v8_executions").fetchone() == (
            "RECONCILED_SUCCEEDED",
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable history"):
            connection.execute("UPDATE legacy_main_v8_approvals SET status = 'PENDING'")
    finally:
        connection.close()
    with pytest.raises(ApprovalNotFoundError):
        SQLiteApprovalRepository(database).get(
            "apr_multi_tag_history_001", datetime(2026, 8, 25, tzinfo=UTC)
        )


def test_verified_unversioned_is_archived_and_versioned(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "verified.sqlite3"
    _verified_database(database)
    result = ensure_active_schema(database)
    assert result.family is DatabaseFamily.VERIFIED_UNVERSIONED
    assert result.backup_path is not None and result.backup_path.exists()
    connection = sqlite3.connect(database)
    try:
        assert (
            connection.execute(
                "SELECT provenance_hash FROM legacy_verified_unversioned_approvals"
            ).fetchone()
            is not None
        )
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (0,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


@pytest.mark.parametrize("tamper", ["audit", "provenance"])
def test_tampered_source_fails_closed_without_archival(
    migration_tmp_path: Path, tamper: str
) -> None:
    database = migration_tmp_path / f"tampered-{tamper}.sqlite3"
    _verified_database(database)
    connection = sqlite3.connect(database)
    try:
        if tamper == "audit":
            connection.execute("UPDATE approval_audit_events SET event_hash = ?", ("f" * 64,))
        else:
            connection.execute("UPDATE approvals SET provenance_hash = ?", ("f" * 64,))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)
    assert "approvals" in _tables(database)
    assert not any(name.startswith("legacy_") for name in _tables(database))


def test_unknown_and_partial_schemas_fail_closed(migration_tmp_path: Path) -> None:
    unknown = migration_tmp_path / "unknown.sqlite3"
    partial = migration_tmp_path / "partial.sqlite3"
    for database, statement in (
        (unknown, "CREATE TABLE unrelated (value TEXT)"),
        (partial, "CREATE TABLE approvals (approval_id TEXT PRIMARY KEY)"),
    ):
        connection = sqlite3.connect(database)
        try:
            connection.execute(statement)
        finally:
            connection.close()
        with pytest.raises(SchemaCompatibilityError):
            ensure_active_schema(database)
        assert "schema_metadata" not in _tables(database)


@pytest.mark.parametrize(
    "schema",
    [
        "CREATE TABLE schema_metadata (unexpected INTEGER)",
        "CREATE TABLE schema_metadata (singleton INTEGER, schema_version INTEGER)",
        "CREATE TABLE schema_metadata (singleton INTEGER, schema_version INTEGER); "
        "INSERT INTO schema_metadata VALUES (1, 7)",
    ],
    ids=["metadata-columns", "metadata-row", "unsupported-version"],
)
def test_unrecognized_schema_metadata_fails_closed(migration_tmp_path: Path, schema: str) -> None:
    database = migration_tmp_path / f"metadata-{secrets.token_hex(4)}.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


@pytest.mark.parametrize("damage", ["columns", "constraints"])
def test_lookalike_unversioned_schema_fails_closed(migration_tmp_path: Path, damage: str) -> None:
    database = migration_tmp_path / f"lookalike-{damage}.sqlite3"
    if damage == "columns":
        schema = _VERIFIED_SCHEMA.replace(
            "audit_head_hash TEXT NOT NULL", "audit_head_hash TEXT NOT NULL, unexpected TEXT"
        )
    else:
        schema = _VERIFIED_SCHEMA.replace(
            "CHECK(action IN ('NONE', 'REVIEW', 'ADD_CONTACT_TAG'))",
            "CHECK(action IN ('NONE', 'REVIEW'))",
        )
    connection = sqlite3.connect(database)
    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


@pytest.mark.parametrize("stage", ["after_archive", "before_commit"])
def test_interrupted_migration_rolls_back_and_can_resume(
    migration_tmp_path: Path, stage: str
) -> None:
    database = migration_tmp_path / f"interrupted-{stage}.sqlite3"
    _verified_database(database)

    def interrupt(active_stage: str) -> None:
        if active_stage == stage:
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        ensure_active_schema(database, fault_hook=interrupt)
    assert "approvals" in _tables(database)
    assert "schema_metadata" not in _tables(database)
    assert not any(name.startswith("legacy_") for name in _tables(database))
    assert list(migration_tmp_path.glob("*.pre-v9-*.bak"))
    resumed = ensure_active_schema(database)
    assert resumed.family is DatabaseFamily.VERIFIED_UNVERSIONED
    assert ensure_active_schema(database).family is DatabaseFamily.ACTIVE_V9


def test_verified_execution_and_security_history_are_preserved(
    migration_tmp_path: Path,
) -> None:
    database = migration_tmp_path / "verified-complete.sqlite3"
    _verified_database(database)
    _add_verified_execution(database)
    _add_security_audit(database)

    result = ensure_active_schema(database)

    assert result.family is DatabaseFamily.VERIFIED_UNVERSIONED
    connection = sqlite3.connect(database)
    try:
        execution = connection.execute(
            "SELECT status, contact_id, tag FROM legacy_verified_unversioned_executions"
        ).fetchone()
        security_event = connection.execute(
            "SELECT operation, outcome FROM legacy_verified_unversioned_security_audit_events"
        ).fetchone()
        assert execution == ("SUCCEEDED", "contact_123456", "qualified")
        assert security_event == ("execute_action", "success")
        assert connection.execute("SELECT count(*) FROM executions").fetchone() == (0,)
        with pytest.raises(sqlite3.IntegrityError, match="immutable history"):
            connection.execute("DELETE FROM legacy_verified_unversioned_executions")
    finally:
        connection.close()


def test_main_successful_effect_is_validated_and_preserved(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "main-effect.sqlite3"
    _main_database(database)
    approval_id, execution_id = _add_main_succeeded_effect(database)

    ensure_active_schema(database)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT status FROM legacy_main_v8_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone() == ("SUCCEEDED",)
        assert connection.execute(
            "SELECT content FROM legacy_main_v8_internal_action_effects WHERE execution_id = ?",
            (execution_id,),
        ).fetchone() == ("qualified",)
        assert connection.execute(
            "SELECT count(*) FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        ("UPDATE approvals SET event_type = 'TAMPERED'", ()),
        ("UPDATE approvals SET audit_event_count = audit_event_count + 1", ()),
        (
            "UPDATE approval_audit_events SET previous_event_hash = ? WHERE sequence_number = 2",
            ("f" * 64,),
        ),
        ("UPDATE approvals SET audit_head_hash = ?", ("f" * 64,)),
    ],
    ids=["binding", "event-count", "event-order", "audit-head"],
)
def test_approval_integrity_corruption_fails_closed(
    migration_tmp_path: Path, statement: str, parameters: tuple[str, ...]
) -> None:
    database = migration_tmp_path / f"approval-corruption-{secrets.token_hex(4)}.sqlite3"
    _verified_database(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute(statement, parameters)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "approvals" in _tables(database)
    assert not any(name.startswith("legacy_") for name in _tables(database))


def test_non_object_provenance_fails_closed(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "non-object-provenance.sqlite3"
    _verified_database(database)
    provenance = _canonical([]).decode()
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE approvals SET provenance_json = ?, provenance_hash = ?",
            (provenance, _hash(provenance.encode())),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


@pytest.mark.parametrize(
    ("case", "statement"),
    [
        ("execution-integrity", "UPDATE executions SET integrity_hash = ?"),
        ("execution-provenance", "UPDATE executions SET provenance_hash = ?"),
        ("security-event", "UPDATE security_audit_events SET event_hash = ?"),
        ("security-state", "UPDATE security_audit_state SET head_hash = ?"),
    ],
)
def test_execution_and_security_corruption_fails_closed(
    migration_tmp_path: Path, case: str, statement: str
) -> None:
    database = migration_tmp_path / f"history-corruption-{case}.sqlite3"
    _verified_database(database)
    _add_verified_execution(database)
    _add_security_audit(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute(statement, ("f" * 64,))
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "executions" in _tables(database)
    assert not any(name.startswith("legacy_") for name in _tables(database))


def test_tampered_main_effect_fails_closed(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "tampered-main-effect.sqlite3"
    _main_database(database)
    _add_main_succeeded_effect(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("UPDATE internal_action_effects SET content = 'tampered'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "internal_action_effects" in _tables(database)


@pytest.mark.parametrize(
    "damage",
    [
        "event-binding",
        "action-binding",
        "execution-integrity",
        "parameter-binding",
        "missing-effect",
        "effect-on-failure",
        "unexpected-reconciliation",
        "incomplete-reconciliation",
        "reconciliation-hash",
        "orphan-effect",
    ],
)
def test_main_execution_corruption_fails_closed(migration_tmp_path: Path, damage: str) -> None:
    database = migration_tmp_path / f"main-execution-{damage}.sqlite3"
    _main_database(database)
    _approval_id, succeeded_id = _add_main_succeeded_effect(database)
    connection = sqlite3.connect(database)
    try:
        if damage == "event-binding":
            connection.execute(
                "UPDATE executions SET event_id = 'evt_wrong_history_0001' WHERE execution_id = ?",
                (succeeded_id,),
            )
        elif damage == "action-binding":
            connection.execute(
                "UPDATE executions SET action = 'UPDATE_INTERNAL_STATUS' WHERE execution_id = ?",
                (succeeded_id,),
            )
        elif damage == "execution-integrity":
            connection.execute(
                "UPDATE executions SET integrity_hash = ? WHERE execution_id = ?",
                ("f" * 64, succeeded_id),
            )
        elif damage == "parameter-binding":
            connection.execute(
                "UPDATE executions SET action_parameters_hash = ? WHERE execution_id = ?",
                ("f" * 64, succeeded_id),
            )
            _refresh_main_execution_integrity(connection, succeeded_id)
        elif damage == "missing-effect":
            connection.execute(
                "DELETE FROM internal_action_effects WHERE execution_id = ?", (succeeded_id,)
            )
        elif damage == "effect-on-failure":
            connection.execute(
                "UPDATE executions SET status = 'FAILED' WHERE execution_id = ?",
                (succeeded_id,),
            )
            _refresh_main_execution_integrity(connection, succeeded_id)
        elif damage == "unexpected-reconciliation":
            connection.execute(
                "UPDATE executions SET reconciler_id = 'unexpected' WHERE execution_id = ?",
                (succeeded_id,),
            )
            _refresh_main_execution_integrity(connection, succeeded_id)
        elif damage == "incomplete-reconciliation":
            connection.execute(
                "UPDATE executions SET reconciler_id = NULL "
                "WHERE execution_id = 'exe_reconciled_history_01'"
            )
            _refresh_main_execution_integrity(connection, "exe_reconciled_history_01")
        elif damage == "reconciliation-hash":
            connection.execute(
                "UPDATE executions SET reconciliation_hash = ? "
                "WHERE execution_id = 'exe_reconciled_history_01'",
                ("f" * 64,),
            )
            _refresh_main_execution_integrity(connection, "exe_reconciled_history_01")
        else:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "INSERT INTO internal_action_effects VALUES (?, ?, ?, ?, ?)",
                (
                    "exe_orphan_history_00001",
                    "orphan-object",
                    "INTERNAL_NOTE",
                    "orphan",
                    NOW,
                ),
            )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "executions" in _tables(database)
    assert not any(name.startswith("legacy_") for name in _tables(database))


def test_verified_execution_without_approval_fails_closed(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "verified-orphan-execution.sqlite3"
    _verified_database(database)
    _add_verified_execution(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DELETE FROM approval_audit_events")
        connection.execute("DELETE FROM approvals")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


def test_security_audit_without_state_fails_closed(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "security-without-state.sqlite3"
    _verified_database(database)
    _add_security_audit(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("DELETE FROM security_audit_state")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


def test_source_foreign_key_corruption_fails_closed(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "orphan-audit.sqlite3"
    _verified_database(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "INSERT INTO approval_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "aud_orphan_history_000001",
                "apr_missing_history_0001",
                1,
                "APPROVAL_CREATED",
                None,
                None,
                None,
                "PENDING",
                "fixture-actor",
                NOW,
                GENESIS,
                "f" * 64,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "approval_audit_events" in _tables(database)


def test_backup_failure_keeps_source_database_intact(
    migration_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = migration_tmp_path / "backup-failure.sqlite3"
    _verified_database(database)

    def fail_backup(_connection: sqlite3.Connection, _path: Path) -> Path:
        raise OSError("simulated backup failure")

    monkeypatch.setattr(migrations, "_create_backup", fail_backup)
    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    assert "approvals" in _tables(database)
    assert "schema_metadata" not in _tables(database)
    assert list(migration_tmp_path.glob("*.bak")) == []


def test_archive_commitment_mismatch_rolls_back_without_data_loss(
    migration_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = migration_tmp_path / "commitment-mismatch.sqlite3"
    _verified_database(database)
    original_commitment = migrations._database_commitment
    calls = 0

    def mismatched_commitment(connection: sqlite3.Connection, tables: Iterator[str]) -> str:
        nonlocal calls
        calls += 1
        commitment = original_commitment(connection, tables)
        return "f" * 64 if calls == 2 else commitment

    monkeypatch.setattr(migrations, "_database_commitment", mismatched_commitment)
    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (1,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()
    assert not any(name.startswith("legacy_") for name in _tables(database))


@pytest.mark.parametrize("damage", ["required-table", "immutable-trigger"])
def test_damaged_active_schema_is_rejected(migration_tmp_path: Path, damage: str) -> None:
    database = migration_tmp_path / f"active-{damage}.sqlite3"
    ensure_active_schema(database)
    connection = sqlite3.connect(database)
    try:
        if damage == "required-table":
            connection.execute("DROP TABLE migration_history")
        else:
            connection.execute("DROP TRIGGER execution_reconciliation_assessments_deny_update")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


def test_partial_security_audit_schema_is_rejected(migration_tmp_path: Path) -> None:
    database = migration_tmp_path / "partial-security.sqlite3"
    _verified_database(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE security_audit_state "
            "(singleton INTEGER, event_count INTEGER, head_hash TEXT)"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SchemaCompatibilityError):
        ensure_active_schema(database)


def test_invalid_database_target_reports_persistence_error(migration_tmp_path: Path) -> None:
    database_directory = migration_tmp_path / "not-a-database.sqlite3"
    database_directory.mkdir()

    with pytest.raises(ApprovalPersistenceError):
        ensure_active_schema(database_directory)
