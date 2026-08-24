"""Phase 8 execution reconciliation and operational reliability tests."""

import ast
import logging
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ai_business_automation.api.routes import (
    get_execution_service,
    get_reconciliation_service,
)
from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    BusinessIntelligenceResult,
    EventCategory,
    EventSource,
    EventType,
    ExecutionAction,
    ExecutionFailureCategory,
    ExecutionRecord,
    ExecutionResultCode,
    ExecutionStatus,
    ExternalEvent,
    GHLAddContactTagParameters,
    Intent,
    Priority,
    RecommendedNextStep,
    ReconciliationOutcome,
    ReconciliationRequest,
    Urgency,
)
from ai_business_automation.providers import (
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
)
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.repositories.executions import (
    _execution_hash,
    _reconciliation_hash,
)
from ai_business_automation.services import reconciliation_factory
from ai_business_automation.services.actions import ActionRegistry
from ai_business_automation.services.approval_errors import SchemaCompatibilityError
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.execution_errors import (
    ExecutionAlreadyReconciledError,
    ExecutionIntegrityError,
    ExecutionNotReconciliableError,
    ReconciliationApprovalIntegrityError,
    ReconciliationNotAuthorizedError,
)
from ai_business_automation.services.executions import ExecutionService
from ai_business_automation.services.normalization import EventNormalizer
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService
from ai_business_automation.services.reconciliation import ReconciliationService

NOW = datetime(2026, 8, 24, 15, 0, tzinfo=UTC)
EVENT_ID = "evt_phase8_reconcile_id"
REASON = "Externally verified through approved operational procedure."


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


class OutcomeProvider:
    def __init__(self, error: GHLProviderError | None = None) -> None:
        self.error = error
        self.calls = 0

    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        del parameters
        self.calls += 1
        if self.error is not None:
            raise self.error


@pytest.fixture
def phase8_tmp_path() -> Iterator[Path]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = root / f"phase8-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def services(
    database: Path,
    provider: OutcomeProvider,
) -> tuple[ApprovalService, ExecutionService, ReconciliationService, SQLiteExecutionRepository]:
    clock = Clock()
    repository = SQLiteExecutionRepository(database)
    repository.initialize()
    approvals = ApprovalService(
        repository,
        PolicyDecisionService(DeterministicPolicyEngine(), clock=clock),
        1_800,
        "development-approver",
        clock,
    )
    executions = ExecutionService(
        repository,
        ActionRegistry(provider),
        "development-approver",
        clock,
    )
    reconciliation = ReconciliationService(repository, "development-reconciler", clock)
    return approvals, executions, reconciliation, repository


def approved_ghl(approvals: ApprovalService) -> str:
    event = EventNormalizer(clock=lambda: NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.GHL_CONTACT_TAG_REQUEST,
            source=EventSource.INTERNAL,
            occurred_at=NOW - timedelta(minutes=1),
            payload={"contact_id": "contact_123456", "tags": ["qualified-lead"]},
        )
    )
    intelligence = BusinessIntelligenceResult(
        event_id=EVENT_ID,
        category=EventCategory.INTERNAL,
        priority=Priority.LOW,
        urgency=Urgency.LOW,
        intent=Intent.INTERNAL,
        confidence=0.95,
        summary="An approved external mutation requires operator review.",
        reasons=["The operation is allowlisted but externally mutating."],
        recommended_next_step=RecommendedNextStep.REVIEW,
    )
    created = approvals.create(event, intelligence)
    return approvals.approve(created.approval_id).approval_id


def unknown_execution(
    database: Path,
) -> tuple[
    ApprovalService,
    ExecutionService,
    ReconciliationService,
    SQLiteExecutionRepository,
    OutcomeProvider,
    str,
]:
    provider = OutcomeProvider(
        GHLProviderError(GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN)
    )
    approvals, executions, reconciliation, repository = services(database, provider)
    result = executions.execute(approved_ghl(approvals))
    assert result.status is ExecutionStatus.UNKNOWN
    return approvals, executions, reconciliation, repository, provider, result.execution_id


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (ReconciliationOutcome.SUCCEEDED, ExecutionStatus.RECONCILED_SUCCEEDED),
        (ReconciliationOutcome.FAILED, ExecutionStatus.RECONCILED_FAILED),
    ],
)
def test_unknown_execution_reconciles_without_provider_replay(
    phase8_tmp_path: Path,
    outcome: ReconciliationOutcome,
    expected: ExecutionStatus,
) -> None:
    database = phase8_tmp_path / f"{outcome.value}.sqlite3"
    approvals, _executions, reconciliation, repository, provider, execution_id = unknown_execution(
        database
    )
    before = provider.calls
    result = reconciliation.reconcile(
        execution_id, ReconciliationRequest(outcome=outcome, reason=REASON)
    )
    assert result.status is expected
    assert result.result_code == "RECONCILED"
    assert result.reconciler_id == "development-reconciler"
    assert provider.calls == before == 1
    assert repository.verify_integrity(execution_id)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM executions").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (1,)
        stored = connection.execute(
            "SELECT reconciliation_reason, original_execution_hash, reconciliation_hash "
            "FROM executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        assert stored is not None and stored[0] == REASON
        assert len(stored[1]) == len(stored[2]) == 64
    finally:
        connection.close()
    assert result.reconciler_id == "development-reconciler"


def test_reconciliation_response_and_status_hide_reason_and_provider_data(
    phase8_tmp_path: Path,
) -> None:
    database = phase8_tmp_path / "api.sqlite3"
    _approvals, executions, reconciliation, _repository, provider, execution_id = unknown_execution(
        database
    )
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_execution_service] = lambda: executions
    app.dependency_overrides[get_reconciliation_service] = lambda: reconciliation
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/actions/executions/{execution_id}/reconcile",
            json={"outcome": "SUCCEEDED", "reason": REASON},
            headers={"X-Request-ID": "phase8-correlation"},
        )
        assert response.status_code == 200
        assert 20 <= len(response.headers["X-Request-ID"]) <= 40
        assert set(response.json()) == {
            "execution_id",
            "status",
            "result_code",
            "reconciled_at",
            "reconciler_id",
        }
        assert REASON not in response.text
        status_response = client.get(f"/api/v1/actions/executions/{execution_id}")
        assert status_response.json()["status"] == "RECONCILED_SUCCEEDED"
        assert "reconciliation" not in status_response.text.lower()
        duplicate = client.post(
            f"/api/v1/actions/executions/{execution_id}/reconcile",
            json={"outcome": "SUCCEEDED", "reason": REASON},
        )
        assert duplicate.status_code == 409
        assert duplicate.json()["error"]["code"] == "EXECUTION_ALREADY_RECONCILED"
        invalid = client.post(
            f"/api/v1/actions/executions/{execution_id}/reconcile",
            json={"outcome": "FAILED", "reason": REASON, "actor_id": "client"},
        )
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == "RECONCILIATION_VALIDATION_ERROR"
    assert provider.calls == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"outcome": "UNKNOWN", "reason": REASON},
        {"outcome": "PENDING", "reason": REASON},
        {"outcome": "RECONCILED_SUCCEEDED", "reason": REASON},
        {"outcome": "SUCCEEDED", "reason": ""},
        {"outcome": "SUCCEEDED", "reason": "x" * 501},
        {"outcome": "SUCCEEDED", "reason": "See https://example.com"},
        {"outcome": "SUCCEEDED", "reason": "Bearer abcdefghijklmnop"},
        {"outcome": "SUCCEEDED", "reason": "run powershell now"},
    ],
)
def test_invalid_reconciliation_inputs_are_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ReconciliationRequest.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    [
        "actor_id",
        "approval_id",
        "event_id",
        "action",
        "contact_id",
        "tags",
        "provider",
        "api_key",
        "status",
        "timestamp",
        "provenance_hash",
        "execution_id",
    ],
)
def test_client_cannot_supply_trusted_reconciliation_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        ReconciliationRequest.model_validate(
            {"outcome": "SUCCEEDED", "reason": REASON, field: "client-controlled"}
        )


@pytest.mark.parametrize("terminal", ["succeeded", "failed"])
def test_definitive_terminal_executions_are_not_reconciliable(
    phase8_tmp_path: Path, terminal: str
) -> None:
    error = (
        None
        if terminal == "succeeded"
        else GHLProviderError(GHLFailureCategory.VALIDATION, GHLOutcomeCertainty.DEFINITIVE)
    )
    approvals, executions, reconciliation, _repository = services(
        phase8_tmp_path / f"{terminal}.sqlite3", OutcomeProvider(error)
    )
    result = executions.execute(approved_ghl(approvals))
    with pytest.raises(ExecutionNotReconciliableError):
        reconciliation.reconcile(
            result.execution_id,
            ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
        )


def test_claimed_and_pending_executions_are_not_reconciliable(phase8_tmp_path: Path) -> None:
    for requested_status in (ExecutionStatus.CLAIMED, ExecutionStatus.PENDING):
        database = phase8_tmp_path / f"{requested_status.value}.sqlite3"
        approvals, _executions, reconciliation, repository = services(database, OutcomeProvider())
        claimed, _approval = repository.claim(approved_ghl(approvals), NOW, "development-approver")
        if requested_status is ExecutionStatus.PENDING:
            connection = sqlite3.connect(database)
            try:
                parameters_hash = connection.execute(
                    "SELECT action_parameters_hash FROM executions WHERE execution_id = ?",
                    (claimed.execution_id,),
                ).fetchone()[0]
            finally:
                connection.close()
            pending_hash = _execution_hash(
                execution_id=claimed.execution_id,
                approval_id=claimed.approval_id,
                event_id=claimed.event_id,
                action=claimed.action,
                status=ExecutionStatus.PENDING,
                started_at=claimed.started_at.isoformat().replace("+00:00", "Z"),
                completed_at=None,
                result_code=None,
                safe_summary=None,
                actor_id=claimed.actor_id,
                action_parameters_hash=parameters_hash,
            )
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE executions SET status = 'PENDING', integrity_hash = ? "
                    "WHERE execution_id = ?",
                    (pending_hash, claimed.execution_id),
                )
                connection.commit()
            finally:
                connection.close()
        with pytest.raises(ExecutionNotReconciliableError):
            reconciliation.reconcile(
                claimed.execution_id,
                ReconciliationRequest(outcome=ReconciliationOutcome.FAILED, reason=REASON),
            )


def test_duplicate_and_concurrent_reconciliation_allow_one_transition(
    phase8_tmp_path: Path,
) -> None:
    created = unknown_execution(phase8_tmp_path / "concurrent.sqlite3")
    _approvals, _executions, reconciliation, _repository, provider, execution_id = created
    request = ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON)

    def attempt() -> str:
        try:
            return reconciliation.reconcile(execution_id, request).status.value
        except ExecutionAlreadyReconciledError:
            return "ALREADY"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(results) == ["ALREADY", "RECONCILED_SUCCEEDED"]
    assert provider.calls == 1
    with pytest.raises(ExecutionAlreadyReconciledError):
        reconciliation.reconcile(execution_id, request)


@pytest.mark.parametrize(
    ("table", "column", "value", "expected_error"),
    [
        ("executions", "event_id", "evt_tampered_phase8_id", ExecutionIntegrityError),
        ("executions", "integrity_hash", "f" * 64, ExecutionIntegrityError),
        ("approvals", "provenance_hash", "f" * 64, ReconciliationApprovalIntegrityError),
        ("approval_audit_events", "event_hash", "f" * 64, ExecutionIntegrityError),
    ],
)
def test_integrity_tampering_blocks_reconciliation(
    phase8_tmp_path: Path,
    table: str,
    column: str,
    value: str,
    expected_error: type[Exception],
) -> None:
    database = phase8_tmp_path / f"tamper-{table}-{column}.sqlite3"
    created = unknown_execution(database)
    _approvals, _executions, reconciliation, _repository, provider, execution_id = created
    connection = sqlite3.connect(database)
    try:
        key = "execution_id" if table == "executions" else "approval_id"
        key_value = execution_id
        if key == "approval_id":
            key_value = connection.execute(
                "SELECT approval_id FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()[0]
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE {key} = ?",  # noqa: S608
            (value, key_value),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(expected_error):
        reconciliation.reconcile(
            execution_id,
            ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
        )
    assert provider.calls == 1


def test_reconciliation_commitment_is_deterministic_and_tamper_evident(
    phase8_tmp_path: Path,
) -> None:
    values = {
        "execution_id": "exe_abcdefghijklmnopqrstuvwxyz",
        "approval_id": "apr_abcdefghijklmnopqrstuvwxyz",
        "event_id": "evt_abcdefghijklmnopqrst",
        "action": ExecutionAction.GHL_ADD_CONTACT_TAG,
        "original_status": ExecutionStatus.UNKNOWN,
        "outcome": ReconciliationOutcome.SUCCEEDED,
        "reason": REASON,
        "policy_version": "1.0",
        "original_execution_hash": "a" * 64,
        "reconciler_id": "development-reconciler",
        "reconciled_at": "2026-08-24T15:00:00Z",
    }
    assert _reconciliation_hash(**values) == _reconciliation_hash(**values)  # type: ignore[arg-type]

    database = phase8_tmp_path / "commitment.sqlite3"
    created = unknown_execution(database)
    _approvals, _executions, reconciliation, repository, _provider, execution_id = created
    reconciliation.reconcile(
        execution_id,
        ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
    )
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE executions SET reconciliation_hash = ? WHERE execution_id = ?",
            ("b" * 64, execution_id),
        )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_integrity(execution_id)


def test_reconciliation_audit_events_are_hash_chained(phase8_tmp_path: Path) -> None:
    database = phase8_tmp_path / "audit.sqlite3"
    created = unknown_execution(database)
    _approvals, _executions, reconciliation, repository, _provider, execution_id = created
    result = reconciliation.reconcile(
        execution_id,
        ReconciliationRequest(outcome=ReconciliationOutcome.FAILED, reason=REASON),
    )
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT event_type, commitment_hash FROM approval_audit_events "
            "ORDER BY sequence_number DESC LIMIT 2"
        ).fetchall()
        approval_id = connection.execute(
            "SELECT approval_id FROM executions WHERE execution_id = ?", (execution_id,)
        ).fetchone()[0]
    finally:
        connection.close()
    assert [row[0] for row in reversed(rows)] == [
        "EXECUTION_RECONCILIATION_REQUESTED",
        "EXECUTION_RECONCILED_FAILED",
    ]
    assert rows[0][1] == rows[1][1]
    assert repository.verify_audit_chain(approval_id)
    assert result.status is ExecutionStatus.RECONCILED_FAILED


def test_reason_is_not_logged(phase8_tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    created = unknown_execution(phase8_tmp_path / "logs.sqlite3")
    _approvals, _executions, reconciliation, _repository, _provider, execution_id = created
    with caplog.at_level(logging.INFO):
        reconciliation.reconcile(
            execution_id,
            ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
        )
    assert REASON not in caplog.text
    assert "qualified-lead" not in caplog.text


def test_reconciler_identity_is_server_owned_and_bounded(phase8_tmp_path: Path) -> None:
    settings = Settings(environment=Environment.TEST, reconciler_id="operations-reconciler")
    assert settings.reconciler_id == "operations-reconciler"
    repository = SQLiteExecutionRepository(phase8_tmp_path / "actor.sqlite3")
    repository.initialize()
    with pytest.raises(ReconciliationNotAuthorizedError):
        ReconciliationService(repository, "invalid actor")


def test_schema_is_versioned_idempotent_and_legacy_schema_fails_closed(
    phase8_tmp_path: Path,
) -> None:
    fresh = phase8_tmp_path / "fresh.sqlite3"
    repository = SQLiteExecutionRepository(fresh)
    repository.initialize()
    repository.initialize()
    connection = sqlite3.connect(fresh)
    try:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (8,)
    finally:
        connection.close()

    legacy = phase8_tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(legacy)
    try:
        connection.execute("CREATE TABLE approvals (approval_id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(SchemaCompatibilityError):
        SQLiteExecutionRepository(legacy).initialize()
    connection = sqlite3.connect(legacy)
    try:
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name = 'schema_metadata'"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_reconciliation_modules_have_no_network_or_provider_capability() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "ai_business_automation"
    paths = [
        root / "services" / "reconciliation.py",
        root / "services" / "reconciliation_factory.py",
    ]
    forbidden = {"httpx", "requests", "urllib", "socket", "openai", "subprocess", "providers"}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            (node.module or "").split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert imports.isdisjoint(forbidden)
        source = path.read_text(encoding="utf-8")
        for prohibited in ("GHLClient", "GHLProvider", ".post(", ".get(", "retry", "poll"):
            assert prohibited not in source


def test_reconciliation_database_contains_no_provider_material(phase8_tmp_path: Path) -> None:
    database = phase8_tmp_path / "privacy.sqlite3"
    created = unknown_execution(database)
    _approvals, _executions, reconciliation, _repository, _provider, execution_id = created
    reconciliation.reconcile(
        execution_id,
        ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
    )
    contents = database.read_bytes()
    for prohibited in (b"Authorization", b"Bearer ", b"provider response", b"api-key-marker"):
        assert prohibited not in contents


def test_reconciliation_lifecycle_model_rejects_inconsistent_metadata() -> None:
    base: dict[str, object] = {
        "execution_id": "exe_abcdefghijklmnopqrstuvwxyz",
        "approval_id": "apr_abcdefghijklmnopqrstuvwxyz",
        "event_id": "evt_abcdefghijklmnopqrst",
        "action": ExecutionAction.GHL_ADD_CONTACT_TAG,
        "status": ExecutionStatus.RECONCILED_SUCCEEDED,
        "started_at": NOW,
        "completed_at": NOW,
        "result_code": ExecutionResultCode.RECONCILED,
        "safe_summary": "Externally reconciled.",
        "actor_id": "development-approver",
        "failure_category": ExecutionFailureCategory.GHL_TIMEOUT,
        "reconciled_at": NOW,
        "reconciler_id": "development-reconciler",
        "reconciliation_hash": "a" * 64,
    }
    with pytest.raises(ValidationError):
        ExecutionRecord.model_validate({**base, "reconciliation_hash": None})
    with pytest.raises(ValidationError):
        ExecutionRecord.model_validate(
            {**base, "reconciled_at": NOW.astimezone(timezone(timedelta(hours=1)))}
        )
    with pytest.raises(ValidationError):
        ExecutionRecord.model_validate(
            {
                **base,
                "status": ExecutionStatus.UNKNOWN,
                "result_code": ExecutionResultCode.OUTCOME_UNKNOWN,
            }
        )


def test_non_utc_reconciliation_clock_fails_closed(phase8_tmp_path: Path) -> None:
    repository = SQLiteExecutionRepository(phase8_tmp_path / "clock.sqlite3")
    repository.initialize()
    service = ReconciliationService(
        repository,
        "development-reconciler",
        clock=lambda: datetime(2026, 8, 24, 15, 0),
    )
    with pytest.raises(ValueError):
        service.reconcile(
            "exe_abcdefghijklmnopqrstuvwxyz",
            ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=REASON),
        )


def test_reconciliation_factory_uses_server_configuration(
    phase8_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = (phase8_tmp_path / "factory.sqlite3").as_posix()
    settings = Settings(
        environment=Environment.TEST,
        reconciler_id="factory-reconciler",
    ).model_copy(update={"approval_database_path": database})
    reconciliation_factory.get_reconciliation_service.cache_clear()
    monkeypatch.setattr(reconciliation_factory, "get_settings", lambda: settings)
    service = reconciliation_factory.get_reconciliation_service()
    assert service.reconciler_id == "factory-reconciler"
    reconciliation_factory.get_reconciliation_service.cache_clear()


def test_incompatible_version_and_partially_versioned_schema_fail_closed(
    phase8_tmp_path: Path,
) -> None:
    wrong_version = phase8_tmp_path / "version7.sqlite3"
    connection = sqlite3.connect(wrong_version)
    try:
        connection.execute(
            "CREATE TABLE schema_metadata (singleton INTEGER PRIMARY KEY, schema_version INTEGER)"
        )
        connection.execute("INSERT INTO schema_metadata VALUES (1, 7)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(SchemaCompatibilityError):
        SQLiteExecutionRepository(wrong_version).initialize()

    partial = phase8_tmp_path / "partial.sqlite3"
    connection = sqlite3.connect(partial)
    try:
        connection.execute(
            "CREATE TABLE schema_metadata (singleton INTEGER PRIMARY KEY, schema_version INTEGER)"
        )
        connection.execute("INSERT INTO schema_metadata VALUES (1, 8)")
        connection.execute("CREATE TABLE executions (execution_id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(SchemaCompatibilityError):
        SQLiteExecutionRepository(partial).initialize()
