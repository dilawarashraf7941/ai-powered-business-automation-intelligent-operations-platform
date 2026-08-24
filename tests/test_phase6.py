"""Phase 6 controlled internal action execution and security tests."""

import json
import secrets
import shutil
import socket
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ai_business_automation.api.routes import get_execution_service
from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    ActionContext,
    ActionOutcome,
    ApprovalStatus,
    AuditEventType,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    EventCategory,
    EventSource,
    EventType,
    ExecutionAction,
    ExecutionRecord,
    ExecutionRequest,
    ExecutionResultCode,
    ExecutionStatus,
    ExternalEvent,
    HumanReviewInput,
    Intent,
    InternalActionEffect,
    InternalNoteInput,
    InternalPriority,
    InternalStatus,
    InternalStatusInput,
    InternalTaskInput,
    Priority,
    RecommendedAction,
    RecommendedNextStep,
    RiskLevel,
    Urgency,
    execution_action_for,
)
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.services.actions import (
    ActionRegistry,
    DefinitiveActionFailure,
    UnknownActionOutcome,
)
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.execution_errors import (
    ApprovalNotApprovedError,
    ApprovalProvenanceInvalidError,
    ExecutionAlreadyClaimedError,
    ExecutionAlreadyCompletedError,
    ExecutionApprovalExpiredError,
    ExecutionConflictError,
    ExecutionIntegrityError,
    ExecutionNotFoundError,
)
from ai_business_automation.services.executions import ExecutionService
from ai_business_automation.services.normalization import EventNormalizer
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService

FIXED_NOW = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)
EVENT_ID = "evt_phase6_fixed_identity"


@dataclass
class MutableClock:
    value: datetime = FIXED_NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


@pytest.fixture
def phase6_tmp_path() -> Iterator[Path]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = root / f"phase6-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def execution_boundary(
    phase6_tmp_path: Path,
) -> tuple[ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock]:
    database = phase6_tmp_path / "executions.sqlite3"
    clock = MutableClock()
    repository = SQLiteExecutionRepository(database)
    repository.initialize()
    policy = PolicyDecisionService(DeterministicPolicyEngine(), clock=clock)
    approvals = ApprovalService(
        repository=repository,
        policy_service=policy,
        ttl_seconds=1_800,
        approver_id="development-approver",
        clock=clock,
    )
    executions = ExecutionService(
        repository=repository,
        registry=ActionRegistry(),
        actor_id="development-approver",
        clock=clock,
    )
    return approvals, executions, repository, database, clock


def canonical_event() -> CanonicalBusinessEvent:
    return EventNormalizer(clock=lambda: FIXED_NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.CUSTOMER_REQUEST,
            source=EventSource.API,
            occurred_at=FIXED_NOW - timedelta(minutes=1),
            payload={"request_type": "internal-review"},
        )
    )


def intelligence(
    recommendation: RecommendedNextStep = RecommendedNextStep.CONTACT_HUMAN,
) -> BusinessIntelligenceResult:
    return BusinessIntelligenceResult(
        event_id=EVENT_ID,
        category=EventCategory.CUSTOMER,
        priority=Priority.LOW,
        urgency=Urgency.LOW,
        intent=Intent.SUPPORT,
        confidence=0.95,
        summary="A bounded internal follow-up is recommended.",
        reasons=["The recommendation requires human review."],
        recommended_next_step=recommendation,
    )


def approved_id(approvals: ApprovalService) -> str:
    created = approvals.create(canonical_event(), intelligence())
    return approvals.approve(created.approval_id).approval_id


def test_approved_approval_executes_once_with_server_owned_identity(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, repository, database, _clock = execution_boundary
    approval_id = approved_id(approvals)
    result = executions.execute(approval_id)
    assert result.execution_id.startswith("exe_")
    assert result.approval_id == approval_id
    assert result.event_id == EVENT_ID
    assert result.action is ExecutionAction.REQUEST_HUMAN_REVIEW
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.result_code is ExecutionResultCode.COMPLETED
    assert result.completed_at is not None
    assert result.actor_id == "development-approver"
    assert repository.verify_integrity(result.execution_id)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM internal_action_effects").fetchone() == (1,)
    finally:
        connection.close()


def test_internal_execution_makes_no_network_connection(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approvals, executions, _repository, _database, _clock = execution_boundary

    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("controlled internal execution attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    assert executions.execute(approved_id(approvals)).status is ExecutionStatus.SUCCEEDED


def test_execution_storage_excludes_payload_ai_and_credentials(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, _repository, database, _clock = execution_boundary
    payload_marker = "raw-payload-phase6-marker"
    ai_marker = "raw-ai-response-phase6-marker"
    credential_marker = "secret-credential-phase6-marker"
    event = EventNormalizer(clock=lambda: FIXED_NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.CUSTOMER_REQUEST,
            source=EventSource.API,
            occurred_at=FIXED_NOW - timedelta(minutes=1),
            payload={"safe_field": payload_marker},
        )
    )
    analysis = intelligence().model_copy(
        update={"summary": ai_marker, "reasons": [credential_marker]}
    )
    approval = approvals.approve(approvals.create(event, analysis).approval_id)
    executions.execute(approval.approval_id)
    connection = sqlite3.connect(database)
    try:
        serialized = "\n".join(
            str(value)
            for table in ("executions", "internal_action_effects")
            for row in connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
            for value in row
        )
    finally:
        connection.close()
    assert payload_marker not in serialized
    assert ai_marker not in serialized
    assert credential_marker not in serialized


@pytest.mark.parametrize(
    "terminal",
    [ApprovalStatus.PENDING, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED],
)
def test_unapproved_terminal_states_cannot_execute(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
    terminal: ApprovalStatus,
) -> None:
    approvals, executions, _repository, database, clock = execution_boundary
    created = approvals.create(canonical_event(), intelligence())
    if terminal is ApprovalStatus.REJECTED:
        approvals.reject(created.approval_id, "Internal execution was not authorized.")
    elif terminal is ApprovalStatus.EXPIRED:
        clock.advance(1_801)
        approvals.get(created.approval_id)
    expected_error = (
        ExecutionApprovalExpiredError
        if terminal is ApprovalStatus.EXPIRED
        else ApprovalNotApprovedError
    )
    with pytest.raises(expected_error):
        executions.execute(created.approval_id)
    assert _execution_count(database) == 0
    assert _audit_types(database)[-1] == AuditEventType.EXECUTION_REJECTED.value


def test_approved_but_ttl_expired_cannot_execute(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, _repository, database, clock = execution_boundary
    approval_id = approved_id(approvals)
    clock.advance(1_801)
    with pytest.raises(ExecutionApprovalExpiredError):
        executions.execute(approval_id)
    assert _execution_count(database) == 0


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("provenance_hash", "f" * 64),
        ("policy_version", "9.9"),
        ("event_id", "evt_tampered_event_value"),
        ("action", "ESCALATE"),
    ],
)
def test_tampered_approval_provenance_prevents_handler_invocation(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
    column: str,
    value: str,
) -> None:
    approvals, executions, _repository, database, _clock = execution_boundary
    approval_id = approved_id(approvals)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        allowed_column = {
            "provenance_hash": "provenance_hash",
            "policy_version": "policy_version",
            "event_id": "event_id",
            "action": "action",
        }[column]
        connection.execute(
            f"UPDATE approvals SET {allowed_column} = ? WHERE approval_id = ?",  # noqa: S608
            (value, approval_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ApprovalProvenanceInvalidError):
        executions.execute(approval_id)
    assert _execution_count(database) == 0
    assert _audit_types(database)[-1] == AuditEventType.EXECUTION_REJECTED.value


def test_execution_request_structurally_rejects_all_authoritative_fields() -> None:
    valid = "apr_abcdefghijklmnopqrstuvwxyz"
    assert ExecutionRequest(approval_id=valid).approval_id == valid
    for field in (
        "execution_id",
        "action",
        "url",
        "method",
        "headers",
        "body",
        "credentials",
        "command",
        "module",
        "callable",
        "provider",
        "retry_policy",
        "timeout",
        "actor_id",
    ):
        with pytest.raises(ValidationError):
            ExecutionRequest.model_validate({"approval_id": valid, field: "client-controlled"})


def test_action_taxonomy_and_mapping_are_closed() -> None:
    assert set(ExecutionAction) == {
        ExecutionAction.NO_OP,
        ExecutionAction.CREATE_INTERNAL_TASK,
        ExecutionAction.UPDATE_INTERNAL_STATUS,
        ExecutionAction.REQUEST_HUMAN_REVIEW,
        ExecutionAction.GENERATE_INTERNAL_NOTE,
    }
    expected = {
        RecommendedAction.NONE: ExecutionAction.NO_OP,
        RecommendedAction.REVIEW: ExecutionAction.UPDATE_INTERNAL_STATUS,
        RecommendedAction.CONTACT_HUMAN: ExecutionAction.REQUEST_HUMAN_REVIEW,
        RecommendedAction.REQUEST_INFORMATION: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.ESCALATE: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.SCHEDULE_CONSULTATION: ExecutionAction.CREATE_INTERNAL_TASK,
        RecommendedAction.NURTURE: ExecutionAction.GENERATE_INTERNAL_NOTE,
    }
    assert {action: execution_action_for(action) for action in RecommendedAction} == expected
    with pytest.raises(ValueError):
        ExecutionAction("ARBITRARY_HTTP")


def test_static_registry_executes_every_bounded_internal_handler() -> None:
    registry = ActionRegistry()
    assert registry.actions == frozenset(ExecutionAction)
    for action in ExecutionAction:
        context = ActionContext(
            execution_id="exe_abcdefghijklmnopqrstuvwxyz",
            approval_id="apr_abcdefghijklmnopqrstuvwxyz",
            event_id="evt_abcdefghijklmnopqrst",
            action=action,
            risk=RiskLevel.HIGH,
            started_at=FIXED_NOW,
        )
        outcome = registry.execute(context)
        assert outcome.result_code == "COMPLETED"
        assert 1 <= len(outcome.safe_summary) <= 200
        assert 1 <= len(outcome.effect.content) <= 1000
    for risk, expected in (
        (RiskLevel.LOW, "LOW"),
        (RiskLevel.MEDIUM, "MEDIUM"),
    ):
        task = registry.execute(
            ActionContext(
                execution_id="exe_abcdefghijklmnopqrstuvwxyz",
                approval_id="apr_abcdefghijklmnopqrstuvwxyz",
                event_id="evt_abcdefghijklmnopqrst",
                action=ExecutionAction.CREATE_INTERNAL_TASK,
                risk=risk,
                started_at=FIXED_NOW,
            )
        )
        assert task.effect.content.endswith(expected)


def test_bounded_action_input_and_output_models_reject_oversized_content() -> None:
    with pytest.raises(ValidationError):
        InternalTaskInput(title="x" * 201, description="valid", priority=InternalPriority.LOW)
    with pytest.raises(ValidationError):
        InternalTaskInput(title="valid", description="x" * 1001, priority=InternalPriority.LOW)
    with pytest.raises(ValidationError):
        InternalNoteInput(text="x" * 1001)
    with pytest.raises(ValidationError):
        HumanReviewInput(
            approval_id="apr_abcdefghijklmnopqrstuvwxyz",
            event_id="evt_abcdefghijklmnopqrst",
            reason="x" * 501,
        )
    with pytest.raises(ValidationError):
        InternalActionEffect(object_type="INTERNAL_NOTE", content="x" * 1001)
    assert (
        InternalStatusInput(
            internal_reference="evt_abcdefghijklmnopqrst",
            status=InternalStatus.REVIEW_REQUIRED,
        ).status
        is InternalStatus.REVIEW_REQUIRED
    )


def test_execution_is_single_use_and_success_cannot_replay(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, _repository, database, _clock = execution_boundary
    approval_id = approved_id(approvals)
    first = executions.execute(approval_id)
    with pytest.raises(ExecutionAlreadyCompletedError):
        executions.execute(approval_id)
    assert _execution_count(database) == 1
    assert executions.get(first.execution_id) == first


def test_atomic_claim_allows_only_one_concurrent_request(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, _executions, repository, database, clock = execution_boundary
    approval_id = approved_id(approvals)
    barrier = Barrier(2)

    def claim() -> ExecutionRecord | type[Exception]:
        barrier.wait()
        try:
            return repository.claim(approval_id, clock.value, "development-approver")[0]
        except Exception as exc:
            return type(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in [pool.submit(claim), pool.submit(claim)]]
    assert sum(isinstance(result, ExecutionRecord) for result in results) == 1
    assert any(result is ExecutionAlreadyClaimedError for result in results)
    assert _execution_count(database) == 1


class FailureRegistry(ActionRegistry):
    def execute(self, context: ActionContext) -> ActionOutcome:
        del context
        raise DefinitiveActionFailure


class UnknownRegistry(ActionRegistry):
    def execute(self, context: ActionContext) -> ActionOutcome:
        del context
        raise UnknownActionOutcome


class EmptyRegistry(ActionRegistry):
    @property
    def actions(self) -> frozenset[ExecutionAction]:
        return frozenset()


@pytest.mark.parametrize(
    ("registry", "expected_status", "expected_code", "audit_type"),
    [
        (
            FailureRegistry(),
            ExecutionStatus.FAILED,
            ExecutionResultCode.DEFINITIVE_FAILURE,
            AuditEventType.EXECUTION_FAILED,
        ),
        (
            UnknownRegistry(),
            ExecutionStatus.UNKNOWN,
            ExecutionResultCode.OUTCOME_UNKNOWN,
            AuditEventType.EXECUTION_UNKNOWN,
        ),
    ],
)
def test_failed_and_unknown_executions_are_terminal_without_retry(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
    registry: ActionRegistry,
    expected_status: ExecutionStatus,
    expected_code: ExecutionResultCode,
    audit_type: AuditEventType,
) -> None:
    approvals, _executions, repository, database, clock = execution_boundary
    approval_id = approved_id(approvals)
    service = ExecutionService(repository, registry, "development-approver", clock)
    result = service.execute(approval_id)
    assert result.status is expected_status
    assert result.result_code is expected_code
    assert _audit_types(database)[-1] == audit_type.value
    with pytest.raises(ExecutionAlreadyCompletedError):
        service.execute(approval_id)
    assert _execution_count(database) == 1


def test_non_allowlisted_registry_result_fails_closed(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, _executions, repository, _database, clock = execution_boundary
    service = ExecutionService(repository, EmptyRegistry(), "development-approver", clock)
    result = service.execute(approved_id(approvals))
    assert result.status is ExecutionStatus.FAILED
    assert result.safe_summary == "Action is not allowlisted."
    assert service.verify_integrity(result.execution_id)


def test_execution_audit_chain_contains_created_claimed_and_succeeded(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, repository, database, _clock = execution_boundary
    result = executions.execute(approved_id(approvals))
    audit_types = _audit_types(database)
    assert audit_types[-3:] == [
        AuditEventType.EXECUTION_CREATED.value,
        AuditEventType.EXECUTION_CLAIMED.value,
        AuditEventType.EXECUTION_SUCCEEDED.value,
    ]
    assert repository.verify_audit_chain(result.approval_id)
    assert repository.verify_integrity(result.execution_id)


@pytest.mark.parametrize(
    ("table", "column", "value"),
    [
        ("approval_audit_events", "actor_id", "tampered-actor"),
        ("executions", "safe_summary", "Tampered execution summary."),
        ("internal_action_effects", "content", "Tampered internal effect."),
    ],
)
def test_execution_and_audit_tampering_is_detected(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
    table: str,
    column: str,
    value: str,
) -> None:
    approvals, executions, repository, database, _clock = execution_boundary
    result = executions.execute(approved_id(approvals))
    allowed = {
        ("approval_audit_events", "actor_id"),
        ("executions", "safe_summary"),
        ("internal_action_effects", "content"),
    }
    assert (table, column) in allowed
    connection = sqlite3.connect(database)
    try:
        key = "approval_id" if table == "approval_audit_events" else "execution_id"
        key_value = result.approval_id if key == "approval_id" else result.execution_id
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE {key} = ?",  # noqa: S608
            (value, key_value),
        )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_integrity(result.execution_id)
    with pytest.raises(ExecutionIntegrityError):
        executions.get(result.execution_id)


def test_execution_repository_rejects_invalid_completion_and_unknown_identity(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, _executions, repository, _database, clock = execution_boundary
    approval_id = approved_id(approvals)
    claimed, _approval = repository.claim(approval_id, clock.value, "development-approver")
    with pytest.raises(ExecutionConflictError):
        repository.complete(
            claimed.execution_id,
            ExecutionStatus.CLAIMED,
            clock.value,
            "invalid",
        )
    with pytest.raises(ExecutionConflictError):
        repository.complete(
            claimed.execution_id,
            ExecutionStatus.SUCCEEDED,
            clock.value,
            "missing outcome",
        )
    outcome = ActionOutcome(
        result_code="COMPLETED",
        safe_summary="Bounded outcome.",
        effect=InternalActionEffect(object_type="NONE", content="NO_OP"),
    )
    with pytest.raises(ExecutionConflictError):
        repository.complete(
            claimed.execution_id,
            ExecutionStatus.FAILED,
            clock.value,
            "invalid effect",
            outcome,
        )
    with pytest.raises(ExecutionNotFoundError):
        repository.get_execution("exe_abcdefghijklmnopqrstuvwxyz")


def test_execution_model_rejects_inconsistent_lifecycle_and_non_utc() -> None:
    base: dict[str, object] = {
        "execution_id": "exe_abcdefghijklmnopqrstuvwxyz",
        "approval_id": "apr_abcdefghijklmnopqrstuvwxyz",
        "event_id": "evt_abcdefghijklmnopqrst",
        "action": ExecutionAction.NO_OP,
        "status": ExecutionStatus.SUCCEEDED,
        "started_at": FIXED_NOW,
        "completed_at": FIXED_NOW,
        "result_code": ExecutionResultCode.COMPLETED,
        "safe_summary": "Complete.",
        "actor_id": "development-approver",
    }
    for updates in (
        {"completed_at": None},
        {"result_code": None, "safe_summary": None},
        {"result_code": ExecutionResultCode.OUTCOME_UNKNOWN},
        {"started_at": FIXED_NOW.astimezone(timezone(timedelta(hours=1)))},
    ):
        with pytest.raises(ValidationError):
            ExecutionRecord.model_validate({**base, **updates})


def test_completed_execution_rejects_direct_completion_replay(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, repository, _database, clock = execution_boundary
    result = executions.execute(approved_id(approvals))
    with pytest.raises(ExecutionAlreadyCompletedError):
        repository.complete(
            result.execution_id,
            ExecutionStatus.SUCCEEDED,
            clock.value,
            "Replay is prohibited.",
            ActionRegistry().execute(
                ActionContext(
                    execution_id=result.execution_id,
                    approval_id=result.approval_id,
                    event_id=result.event_id,
                    action=result.action,
                    risk=RiskLevel.MEDIUM,
                    started_at=result.started_at,
                )
            ),
        )


def test_broken_approval_audit_chain_prevents_claim(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, _repository, database, _clock = execution_boundary
    approval_id = approved_id(approvals)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE approval_audit_events SET event_hash = ? WHERE sequence_number = 1",
            ("f" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ExecutionIntegrityError):
        executions.execute(approval_id)


def test_execution_read_rechecks_approval_provenance(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> None:
    approvals, executions, _repository, database, _clock = execution_boundary
    result = executions.execute(approved_id(approvals))
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE approvals SET provenance_hash = ? WHERE approval_id = ?",
            ("f" * 64, result.approval_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ApprovalProvenanceInvalidError):
        executions.get(result.execution_id)


@pytest.fixture
def execution_client(
    execution_boundary: tuple[
        ApprovalService, ExecutionService, SQLiteExecutionRepository, Path, MutableClock
    ],
) -> Iterator[tuple[TestClient, ApprovalService, ExecutionService]]:
    approvals, executions, _repository, _database, _clock = execution_boundary
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_execution_service] = lambda: executions
    with TestClient(app) as client:
        yield client, approvals, executions


def test_execution_api_returns_safe_result_and_status(
    execution_client: tuple[TestClient, ApprovalService, ExecutionService],
) -> None:
    client, approvals, _executions = execution_client
    approval_id = approved_id(approvals)
    response = client.post(
        "/api/v1/actions/execute",
        json={"approval_id": approval_id},
        headers={"X-Request-ID": "phase6-request-id"},
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"]
    assert response.headers["X-Request-ID"] != "phase6-request-id"
    body = response.json()
    assert body["status"] == "SUCCEEDED"
    assert body["action"] == "REQUEST_HUMAN_REVIEW"
    assert set(body) == {
        "execution_id",
        "approval_id",
        "event_id",
        "action",
        "status",
        "started_at",
        "completed_at",
        "result_code",
        "safe_summary",
    }
    serialized = json.dumps(body).lower()
    for prohibited in ("payload", "credential", "provider", "prompt", "actor_id", "effect"):
        assert prohibited not in serialized
    status_response = client.get(f"/api/v1/actions/executions/{body['execution_id']}")
    assert status_response.status_code == 200
    assert status_response.json() == body


@pytest.mark.parametrize(
    "field",
    [
        "execution_id",
        "action",
        "url",
        "method",
        "headers",
        "body",
        "credentials",
        "module",
        "callable",
    ],
)
def test_execution_api_rejects_client_controlled_capabilities(
    execution_client: tuple[TestClient, ApprovalService, ExecutionService], field: str
) -> None:
    client, approvals, _executions = execution_client
    approval_id = approved_id(approvals)
    response = client.post(
        "/api/v1/actions/execute",
        json={"approval_id": approval_id, field: "client-controlled"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ACTION_VALIDATION_ERROR"


def test_execution_api_returns_stable_errors_without_internal_details(
    execution_client: tuple[TestClient, ApprovalService, ExecutionService],
) -> None:
    client, approvals, _executions = execution_client
    pending = approvals.create(canonical_event(), intelligence())
    response = client.post("/api/v1/actions/execute", json={"approval_id": pending.approval_id})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "APPROVAL_NOT_APPROVED"
    not_found = client.get("/api/v1/actions/executions/exe_abcdefghijklmnopqrstuvwxyz")
    assert not_found.status_code == 404
    assert not_found.json()["error"]["code"] == "EXECUTION_NOT_FOUND"
    for body in (response.json(), not_found.json()):
        serialized = json.dumps(body).lower()
        assert ".sqlite3" not in serialized
        assert "traceback" not in serialized


def _execution_count(database: Path) -> int:
    connection = sqlite3.connect(database)
    try:
        return cast(int, connection.execute("SELECT count(*) FROM executions").fetchone()[0])
    finally:
        connection.close()


def _audit_types(database: Path) -> list[str]:
    connection = sqlite3.connect(database)
    try:
        return [
            cast(str, row[0])
            for row in connection.execute(
                "SELECT event_type FROM approval_audit_events ORDER BY sequence_number"
            ).fetchall()
        ]
    finally:
        connection.close()
