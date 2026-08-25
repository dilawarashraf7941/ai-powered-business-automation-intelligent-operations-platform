"""Phase 8 immutable UNKNOWN assessment and authorization tests."""

import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_business_automation.api.routes import get_reconciliation_service
from ai_business_automation.config import Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    AuthRole,
    ExecutionRecord,
    ExecutionStatus,
    ReconciliationOutcome,
    ReconciliationRequest,
)
from ai_business_automation.providers import (
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
)
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.repositories.migrations import ACTIVE_SCHEMA_VERSION
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.execution_errors import (
    ExecutionAlreadyAssessedError,
    ExecutionNotReconciliableError,
    ReconciliationIntegrityError,
)
from ai_business_automation.services.reconciliation import ReconciliationService
from tests.auth_helpers import auth_settings, authenticated_client
from tests.test_phase6 import (
    NOW,
    Clock,
    RecordingProvider,
    action_request,
    approved_boundary,
)


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


def _unknown_boundary(
    database: Path,
) -> tuple[
    ApprovalService,
    SQLiteExecutionRepository,
    ExecutionRecord,
    ReconciliationService,
    RecordingProvider,
]:
    provider = RecordingProvider(
        GHLProviderError(GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN)
    )
    approvals, executions, repository, approval_id = approved_boundary(database, provider)
    execution = executions.execute(action_request(approval_id), "authenticated-executor")
    service = ReconciliationService(
        repository, "server-reconciler", Clock(NOW + timedelta(minutes=1))
    )
    return approvals, repository, execution, service, provider


def _request(
    outcome: ReconciliationOutcome = ReconciliationOutcome.SUCCEEDED,
) -> ReconciliationRequest:
    return ReconciliationRequest(
        outcome=outcome,
        reason="Verified through an authorized external review.",
    )


def test_reconciliation_input_is_strict_and_bounded() -> None:
    for reason in (
        "",
        " leading",
        "https://untrusted.invalid",
        "Bearer credentialmaterial",
        "x" * 501,
    ):
        with pytest.raises(ValidationError):
            ReconciliationRequest(outcome=ReconciliationOutcome.SUCCEEDED, reason=reason)
    with pytest.raises(ValidationError):
        ReconciliationRequest.model_validate(
            {"outcome": "UNKNOWN", "reason": "Valid bounded reason."}
        )
    with pytest.raises(ValidationError):
        ReconciliationRequest.model_validate(
            {
                "outcome": "SUCCEEDED",
                "reason": "Valid bounded reason.",
                "actor_id": "client-selected",
            }
        )


def test_assessment_preserves_unknown_and_never_calls_provider_again(
    phase8_tmp_path: Path,
) -> None:
    _approvals, repository, execution, service, provider = _unknown_boundary(
        phase8_tmp_path / "unknown.sqlite3"
    )
    before = repository.get_execution(execution.execution_id)
    result = service.reconcile(execution.execution_id, _request(), "authenticated-executor")
    after = repository.get_execution(execution.execution_id)
    assert before == after
    assert after.status is ExecutionStatus.UNKNOWN
    assert result.execution_status is ExecutionStatus.UNKNOWN
    assert result.actor_id == "authenticated-executor"
    assert len(provider.calls) == 1


def test_only_unknown_execution_can_be_assessed(phase8_tmp_path: Path) -> None:
    provider = RecordingProvider()
    _approvals, executions, repository, approval_id = approved_boundary(
        phase8_tmp_path / "succeeded.sqlite3", provider
    )
    execution = executions.execute(action_request(approval_id))
    service = ReconciliationService(repository, "server-reconciler", Clock())
    with pytest.raises(ExecutionNotReconciliableError):
        service.reconcile(execution.execution_id, _request())
    assert len(provider.calls) == 1


def test_second_or_concurrent_assessment_is_rejected(phase8_tmp_path: Path) -> None:
    _approvals, _repository, execution, service, _provider = _unknown_boundary(
        phase8_tmp_path / "single-assessment.sqlite3"
    )

    def assess() -> str:
        try:
            return service.reconcile(execution.execution_id, _request()).assessment_id
        except ExecutionAlreadyAssessedError:
            return "DUPLICATE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: assess(), range(2)))
    assert results.count("DUPLICATE") == 1
    assert sum(result.startswith("rcn_") for result in results) == 1


def test_assessment_integrity_and_immutability_are_enforced(
    phase8_tmp_path: Path,
) -> None:
    database = phase8_tmp_path / "integrity.sqlite3"
    _approvals, repository, execution, service, _provider = _unknown_boundary(database)
    service.reconcile(execution.execution_id, _request())
    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable history"):
            connection.execute(
                "UPDATE execution_reconciliation_assessments SET actor_id = 'tampered'"
            )
        connection.execute("DROP TRIGGER execution_reconciliation_assessments_deny_update")
        connection.execute(
            "UPDATE execution_reconciliation_assessments SET assessment_hash = ?",
            ("f" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ReconciliationIntegrityError):
        repository.get_reconciliation(execution.execution_id)


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (AuthRole.READ_ONLY, 403),
        (AuthRole.APPROVER, 403),
        (AuthRole.EXECUTOR, 200),
        (AuthRole.ADMIN, 200),
    ],
)
def test_assessment_endpoint_requires_executor_or_admin(
    phase8_tmp_path: Path, role: AuthRole, expected: int
) -> None:
    database = phase8_tmp_path / f"auth-{role.value}.sqlite3"
    _approvals, _repository, execution, service, provider = _unknown_boundary(database)
    app = create_app(auth_settings(auth_role_1=role, approval_database_path=str(database)))
    app.dependency_overrides[get_reconciliation_service] = lambda: service
    with authenticated_client(app) as client:
        response = client.post(
            f"/api/v1/actions/executions/{execution.execution_id}/reconcile",
            json={
                "outcome": "SUCCEEDED",
                "reason": "Verified through an authorized external review.",
            },
        )
    assert response.status_code == expected
    assert len(provider.calls) == 1
    if expected == 200:
        assert response.json()["execution_status"] == "UNKNOWN"
        assert response.json()["actor_id"] == "test-admin"


def test_client_cannot_inject_assessment_actor(phase8_tmp_path: Path) -> None:
    database = phase8_tmp_path / "actor.sqlite3"
    _approvals, _repository, execution, service, _provider = _unknown_boundary(database)
    app = create_app(auth_settings(approval_database_path=str(database)))
    app.dependency_overrides[get_reconciliation_service] = lambda: service
    with authenticated_client(app) as client:
        response = client.post(
            f"/api/v1/actions/executions/{execution.execution_id}/reconcile",
            json={
                "outcome": "SUCCEEDED",
                "reason": "Verified through an authorized external review.",
                "actor_id": "client-selected",
            },
        )
    assert response.status_code == 422


def test_schema_version_and_server_reconciler_configuration(
    phase8_tmp_path: Path,
) -> None:
    database = phase8_tmp_path / "schema.sqlite3"
    _unknown_boundary(database)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT schema_version FROM schema_metadata").fetchone() == (
            ACTIVE_SCHEMA_VERSION,
        )
    finally:
        connection.close()
    assert Settings(reconciler_id="operations-reconciler").reconciler_id == (
        "operations-reconciler"
    )
