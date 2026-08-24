"""Phase 6 single-action execution boundary tests."""

import json
import logging
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock
from typing import Literal, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from ai_business_automation.api.routes import get_execution_service
from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    AuditEventType,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    ContactTagExecutionRequest,
    EventCategory,
    EventSource,
    EventType,
    ExecutionAction,
    ExecutionFailureCategory,
    ExecutionRecord,
    ExecutionStatus,
    ExternalEvent,
    GHLAddContactTagParameters,
    GHLAddTagsRequest,
    Intent,
    Priority,
    RecommendedAction,
    RecommendedNextStep,
    Urgency,
)
from ai_business_automation.providers import (
    GHL_API_ORIGIN,
    GHL_API_VERSION,
    GHLClient,
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
    UnavailableGHLProvider,
)
from ai_business_automation.providers.ghl_factory import create_ghl_provider
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.services.actions import ContactTagExecutor
from ai_business_automation.services.approval_errors import ProvenanceIntegrityError
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.execution_errors import (
    ActionNotAllowedError,
    ActionValidationError,
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

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
EVENT_ID = "evt_phase6_contact_tag"
CONTACT_ID = "contact_123456"
TAG = "qualified-lead"
TOKEN = "phase6-fake-token-not-a-secret"


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


class RecordingProvider:
    def __init__(self, error: GHLProviderError | Exception | None = None) -> None:
        self.calls: list[GHLAddContactTagParameters] = []
        self.error = error
        self._lock = Lock()

    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        with self._lock:
            self.calls.append(parameters)
        if self.error is not None:
            raise self.error


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


def tag_event() -> CanonicalBusinessEvent:
    return EventNormalizer(clock=lambda: NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.GHL_CONTACT_TAG_REQUEST,
            source=EventSource.INTERNAL,
            occurred_at=NOW - timedelta(minutes=1),
            payload={"contact_id": CONTACT_ID, "tag": TAG},
        )
    )


def ordinary_event() -> CanonicalBusinessEvent:
    return EventNormalizer(
        clock=lambda: NOW, event_id_factory=lambda: "evt_phase6_wrong_action"
    ).normalize(
        ExternalEvent(
            event_type=EventType.CUSTOMER_REQUEST,
            source=EventSource.API,
            occurred_at=NOW - timedelta(minutes=1),
            payload={"request_type": "review"},
        )
    )


def intelligence(event_id: str = EVENT_ID) -> BusinessIntelligenceResult:
    is_tag = event_id == EVENT_ID
    return BusinessIntelligenceResult(
        event_id=event_id,
        category=EventCategory.INTERNAL if is_tag else EventCategory.CUSTOMER,
        priority=Priority.LOW,
        urgency=Urgency.LOW,
        intent=Intent.INTERNAL if is_tag else Intent.SUPPORT,
        confidence=0.93,
        summary="A bounded mutation requires trusted human approval.",
        reasons=["The deterministic policy requires an approval."],
        recommended_next_step=(
            RecommendedNextStep.REVIEW if is_tag else RecommendedNextStep.CONTACT_HUMAN
        ),
    )


def boundary(
    database: Path, provider: RecordingProvider, clock: Clock | None = None
) -> tuple[ApprovalService, ExecutionService, SQLiteExecutionRepository, Clock]:
    active_clock = clock or Clock()
    repository = SQLiteExecutionRepository(database)
    repository.initialize()
    approvals = ApprovalService(
        repository=repository,
        policy_service=PolicyDecisionService(DeterministicPolicyEngine(), clock=active_clock),
        ttl_seconds=1_800,
        approver_id="phase6-approver",
        clock=active_clock,
    )
    executions = ExecutionService(
        repository=repository,
        executor=ContactTagExecutor(provider),
        actor_id="phase6-approver",
        clock=active_clock,
    )
    return approvals, executions, repository, active_clock


def action_request(approval_id: str) -> ContactTagExecutionRequest:
    return ContactTagExecutionRequest(approval_id=approval_id, contact_id=CONTACT_ID, tag=TAG)


def approved_boundary(
    database: Path, provider: RecordingProvider
) -> tuple[ApprovalService, ExecutionService, SQLiteExecutionRepository, str]:
    approvals, executions, repository, _clock = boundary(database, provider)
    created = approvals.create(tag_event(), intelligence())
    approvals.approve(created.approval_id)
    return approvals, executions, repository, created.approval_id


def test_strict_request_and_provider_body() -> None:
    parameters = GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)
    assert GHLAddTagsRequest(tags=(parameters.tag,)).model_dump(mode="json") == {"tags": [TAG]}
    for value in ("short", "../contact_123", "https://evil.example", "contact id123"):
        with pytest.raises(ValidationError):
            GHLAddContactTagParameters(contact_id=value, tag=TAG)
    for value in (" bad", "bad\nvalue", "https://evil", "Bearer abcdefghijklmnop", "x" * 51):
        with pytest.raises(ValidationError):
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=value)
    with pytest.raises(ValidationError):
        ContactTagExecutionRequest.model_validate(
            {
                "approval_id": "apr_12345678901234567890",
                "contact_id": CONTACT_ID,
                "tag": TAG,
                "url": "https://evil.example",
            }
        )


def test_policy_and_provenance_bind_exact_action(phase6_tmp_path: Path) -> None:
    approvals, _executions, repository, _clock = boundary(
        phase6_tmp_path / "binding.sqlite3", RecordingProvider()
    )
    assert (
        approvals.policy_service.decide(tag_event(), intelligence()).action
        is RecommendedAction.ADD_CONTACT_TAG
    )
    created = approvals.create(tag_event(), intelligence())
    assert created.action_parameters == GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)
    assert repository.verify_audit_chain(created.approval_id)


def test_approved_action_executes_once_and_preserves_approval(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    approvals, executions, repository, approval_id = approved_boundary(
        phase6_tmp_path / "success.sqlite3", provider
    )
    before = approvals.get(approval_id)
    result = executions.execute(action_request(approval_id))
    assert (result.status, result.action) == (
        ExecutionStatus.SUCCEEDED,
        ExecutionAction.ADD_CONTACT_TAG,
    )
    assert provider.calls == [GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)]
    assert repository.verify_integrity(result.execution_id)
    assert approvals.get(approval_id) == before
    with pytest.raises(ExecutionAlreadyCompletedError):
        executions.execute(action_request(approval_id))
    assert len(provider.calls) == 1


@pytest.mark.parametrize("transition", ["pending", "rejected", "expired"])
def test_invalid_approval_never_calls_provider(phase6_tmp_path: Path, transition: str) -> None:
    provider = RecordingProvider()
    clock = Clock()
    approvals, executions, _repository, _clock = boundary(
        phase6_tmp_path / f"{transition}.sqlite3", provider, clock
    )
    created = approvals.create(tag_event(), intelligence())
    if transition == "rejected":
        approvals.reject(created.approval_id, "Not authorized by the reviewer.")
    elif transition == "expired":
        approvals.approve(created.approval_id)
        clock.value += timedelta(seconds=1_801)
    expected = (
        ExecutionApprovalExpiredError if transition == "expired" else ApprovalNotApprovedError
    )
    with pytest.raises(expected):
        executions.execute(action_request(created.approval_id))
    assert provider.calls == []


def test_wrong_action_or_inputs_never_call_provider(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    approvals, executions, _repository, _clock = boundary(
        phase6_tmp_path / "wrong.sqlite3", provider
    )
    wrong = approvals.create(ordinary_event(), intelligence("evt_phase6_wrong_action"))
    approvals.approve(wrong.approval_id)
    with pytest.raises(ActionNotAllowedError):
        executions.execute(action_request(wrong.approval_id))
    approved = approvals.create(tag_event(), intelligence())
    approvals.approve(approved.approval_id)
    with pytest.raises(ActionValidationError):
        executions.execute(
            ContactTagExecutionRequest(
                approval_id=approved.approval_id, contact_id=CONTACT_ID, tag="different"
            )
        )
    assert provider.calls == []


@pytest.mark.parametrize("column", ["provenance_hash", "policy_version"])
def test_tampered_provenance_or_policy_fails_closed(phase6_tmp_path: Path, column: str) -> None:
    database = phase6_tmp_path / f"tamper-{column}.sqlite3"
    provider = RecordingProvider()
    approvals, executions, _repository, _clock = boundary(database, provider)
    created = approvals.create(tag_event(), intelligence())
    approvals.approve(created.approval_id)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        value = "0" * 64 if column == "provenance_hash" else "9.9"
        query = {
            "provenance_hash": "UPDATE approvals SET provenance_hash = ? WHERE approval_id = ?",
            "policy_version": "UPDATE approvals SET policy_version = ? WHERE approval_id = ?",
        }[column]
        connection.execute(
            query,
            (value, created.approval_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises((ApprovalProvenanceInvalidError, ExecutionIntegrityError)):
        executions.execute(action_request(created.approval_id))
    assert provider.calls == []


def test_parameter_tampering_invalidates_provenance(phase6_tmp_path: Path) -> None:
    database = phase6_tmp_path / "parameter-tamper.sqlite3"
    approvals, _executions, repository, _clock = boundary(database, RecordingProvider())
    created = approvals.create(tag_event(), intelligence())
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE approvals SET action_parameters_json = ? WHERE approval_id = ?",
            (json.dumps({"contact_id": CONTACT_ID, "tag": "changed"}), created.approval_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ProvenanceIntegrityError):
        repository.get(created.approval_id, NOW)


def test_atomic_concurrent_claim_allows_one_call(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    _approvals, executions, repository, approval_id = approved_boundary(
        phase6_tmp_path / "concurrent.sqlite3", provider
    )
    barrier = Barrier(2)

    def execute() -> str:
        barrier.wait()
        try:
            return executions.execute(action_request(approval_id)).status.value
        except (ExecutionAlreadyClaimedError, ExecutionAlreadyCompletedError):
            return "DUPLICATE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: execute(), range(2)))
    assert sorted(results) == ["DUPLICATE", "SUCCEEDED"]
    assert len(provider.calls) == 1
    assert repository.verify_audit_chain(approval_id)


def test_second_repository_claim_rejects_an_existing_claim(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    _approvals, _executions, repository, approval_id = approved_boundary(
        phase6_tmp_path / "already-claimed.sqlite3", provider
    )
    parameters = GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)

    claimed, approval = repository.claim(approval_id, parameters, NOW, "phase6-approver")
    assert claimed.status is ExecutionStatus.CLAIMED
    assert approval.approval_id == approval_id
    assert repository.verify_audit_chain(approval_id)

    with pytest.raises(ExecutionAlreadyClaimedError):
        repository.claim(approval_id, parameters, NOW, "phase6-approver")

    assert provider.calls == []
    assert repository.get_execution(claimed.execution_id).status is ExecutionStatus.CLAIMED


@pytest.mark.parametrize(
    ("category", "certainty", "status", "failure"),
    [
        (
            GHLFailureCategory.BAD_REQUEST,
            GHLOutcomeCertainty.DEFINITIVE,
            ExecutionStatus.FAILED,
            ExecutionFailureCategory.PROVIDER_BAD_REQUEST,
        ),
        (
            GHLFailureCategory.AUTHENTICATION,
            GHLOutcomeCertainty.DEFINITIVE,
            ExecutionStatus.FAILED,
            ExecutionFailureCategory.PROVIDER_AUTHENTICATION,
        ),
        (
            GHLFailureCategory.RATE_LIMIT,
            GHLOutcomeCertainty.DEFINITIVE,
            ExecutionStatus.FAILED,
            ExecutionFailureCategory.PROVIDER_RATE_LIMIT,
        ),
        (
            GHLFailureCategory.PROVIDER_ERROR,
            GHLOutcomeCertainty.DEFINITIVE,
            ExecutionStatus.FAILED,
            ExecutionFailureCategory.PROVIDER_ERROR,
        ),
        (
            GHLFailureCategory.UNAVAILABLE,
            GHLOutcomeCertainty.DEFINITIVE,
            ExecutionStatus.FAILED,
            ExecutionFailureCategory.PROVIDER_UNAVAILABLE,
        ),
        (
            GHLFailureCategory.TIMEOUT,
            GHLOutcomeCertainty.UNKNOWN,
            ExecutionStatus.UNKNOWN,
            ExecutionFailureCategory.PROVIDER_TIMEOUT,
        ),
        (
            GHLFailureCategory.UNKNOWN,
            GHLOutcomeCertainty.UNKNOWN,
            ExecutionStatus.UNKNOWN,
            ExecutionFailureCategory.UNKNOWN_OUTCOME,
        ),
    ],
)
def test_failures_are_durable_and_never_retried(
    phase6_tmp_path: Path,
    category: GHLFailureCategory,
    certainty: GHLOutcomeCertainty,
    status: ExecutionStatus,
    failure: ExecutionFailureCategory,
) -> None:
    provider = RecordingProvider(GHLProviderError(category, certainty))
    _approvals, executions, repository, approval_id = approved_boundary(
        phase6_tmp_path / f"failure-{category}.sqlite3", provider
    )
    result = executions.execute(action_request(approval_id))
    assert (result.status, result.failure_category) == (status, failure)
    assert repository.get_execution(result.execution_id) == result
    with pytest.raises(ExecutionAlreadyCompletedError):
        executions.execute(action_request(approval_id))
    assert len(provider.calls) == 1


def test_unexpected_exception_is_unknown(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider(RuntimeError("raw provider customer response"))
    _approvals, executions, _repository, approval_id = approved_boundary(
        phase6_tmp_path / "unknown.sqlite3", provider
    )
    result = executions.execute(action_request(approval_id))
    assert (result.status, result.failure_category) == (
        ExecutionStatus.UNKNOWN,
        ExecutionFailureCategory.UNKNOWN_OUTCOME,
    )
    assert "raw provider" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("status_code", "category"),
    [
        (400, GHLFailureCategory.BAD_REQUEST),
        (401, GHLFailureCategory.AUTHENTICATION),
        (403, GHLFailureCategory.AUTHENTICATION),
        (429, GHLFailureCategory.RATE_LIMIT),
        (500, GHLFailureCategory.PROVIDER_ERROR),
    ],
)
def test_ghl_http_failures_are_safely_classified(
    status_code: int, category: GHLFailureCategory
) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(status_code, text="secret provider body")
    )
    client = GHLClient(SecretStr(TOKEN), "v3", 5.0, transport=transport)
    with pytest.raises(GHLProviderError) as captured:
        client.add_contact_tag(GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG))
    assert captured.value.category is category
    assert captured.value.certainty is GHLOutcomeCertainty.DEFINITIVE
    assert "secret provider body" not in str(captured.value)


def test_ghl_contract_is_fixed_and_response_is_discarded() -> None:
    captured: list[httpx.Request] = []

    def handler(request_: httpx.Request) -> httpx.Response:
        captured.append(request_)
        return httpx.Response(200, json={"customer": "raw provider data"})

    client = GHLClient(SecretStr(TOKEN), "v3", 5.0, transport=httpx.MockTransport(handler))
    client.add_contact_tag(GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG))
    sent = captured[0]
    assert sent.method == "POST"
    assert str(sent.url) == f"{GHL_API_ORIGIN}/contacts/{CONTACT_ID}/tags"
    assert sent.headers["Version"] == GHL_API_VERSION
    assert sent.headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(sent.content) == {"tags": [TAG]}


def test_transport_certainty_is_closed() -> None:
    parameters = GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)

    def timeout(request_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("ambiguous", request=request_)

    def connect(request_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("definite", request=request_)

    cases = (
        (timeout, GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN),
        (connect, GHLFailureCategory.UNAVAILABLE, GHLOutcomeCertainty.DEFINITIVE),
    )
    for handler, expected, certainty in cases:
        client = GHLClient(SecretStr(TOKEN), "v3", 5.0, transport=httpx.MockTransport(handler))
        with pytest.raises(GHLProviderError) as captured:
            client.add_contact_tag(parameters)
        assert (captured.value.category, captured.value.certainty) == (expected, certainty)


def test_credentials_are_server_owned_and_not_logged_or_persisted(
    phase6_tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    assert isinstance(
        create_ghl_provider(Settings(environment=Environment.TEST, ghl_api_key=TOKEN)), GHLClient
    )
    assert isinstance(
        create_ghl_provider(Settings(environment=Environment.TEST)), UnavailableGHLProvider
    )
    database = phase6_tmp_path / "secrets.sqlite3"
    _approvals, executions, _repository, approval_id = approved_boundary(
        database, RecordingProvider()
    )
    with caplog.at_level(logging.INFO):
        executions.execute(action_request(approval_id))
    assert TOKEN not in caplog.text
    assert TOKEN.encode() not in database.read_bytes()


def test_execution_audit_and_integrity_guards(phase6_tmp_path: Path) -> None:
    database = phase6_tmp_path / "audit.sqlite3"
    _approvals, executions, repository, approval_id = approved_boundary(
        database, RecordingProvider()
    )
    result = executions.execute(action_request(approval_id))
    connection = sqlite3.connect(database)
    try:
        values = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM approval_audit_events WHERE approval_id = ? "
                "ORDER BY sequence_number",
                (approval_id,),
            )
        ]
    finally:
        connection.close()
    assert values[-3:] == [
        AuditEventType.EXECUTION_AUTHORIZED.value,
        AuditEventType.EXECUTION_CLAIMED.value,
        AuditEventType.EXECUTION_SUCCEEDED.value,
    ]
    assert repository.verify_integrity(result.execution_id)
    with pytest.raises(ExecutionAlreadyCompletedError):
        repository.complete(
            result.execution_id,
            ExecutionStatus.FAILED,
            NOW,
            ExecutionFailureCategory.INTERNAL_ERROR,
        )
    with pytest.raises(ExecutionConflictError):
        repository.complete(result.execution_id, ExecutionStatus.CLAIMED, NOW, None)
    with pytest.raises(ExecutionConflictError):
        repository.complete(
            result.execution_id,
            ExecutionStatus.SUCCEEDED,
            NOW,
            ExecutionFailureCategory.INTERNAL_ERROR,
        )
    with pytest.raises(ExecutionNotFoundError):
        repository.get_execution("exe_12345678901234567890")
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE executions SET tag = 'tampered' WHERE execution_id = ?",
            (result.execution_id,),
        )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_integrity(result.execution_id)
    with pytest.raises(ExecutionIntegrityError):
        repository.get_execution(result.execution_id)


def test_api_returns_only_safe_bounded_result(phase6_tmp_path: Path) -> None:
    _approvals, executions, _repository, approval_id = approved_boundary(
        phase6_tmp_path / "api.sqlite3", RecordingProvider()
    )
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_execution_service] = lambda: executions
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/actions/contact-tag",
            json={"approval_id": approval_id, "contact_id": CONTACT_ID, "tag": TAG},
        )
        invalid = client.post(
            "/api/v1/actions/contact-tag",
            json={
                "approval_id": approval_id,
                "contact_id": CONTACT_ID,
                "tag": TAG,
                "url": "https://evil.example",
            },
        )
    assert response.status_code == 200
    assert response.json() == {
        "execution_id": response.json()["execution_id"],
        "status": "SUCCEEDED",
        "action": "ADD_CONTACT_TAG",
    }
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "ACTION_VALIDATION_ERROR"
    assert TOKEN not in response.text


def test_no_generic_or_ai_direct_execution_capability_exists() -> None:
    root = Path("src/ai_business_automation")
    action_source = (root / "services/actions.py").read_text(encoding="utf-8")
    provider_source = (root / "providers/ghl.py").read_text(encoding="utf-8")
    routes_source = (root / "api/routes.py").read_text(encoding="utf-8")
    combined = action_source + routes_source
    assert "ActionRegistry" not in combined
    assert "subprocess" not in combined
    assert "os.system" not in combined
    assert "n8n" not in combined.lower()
    assert "client.request(" not in provider_source
    assert "client.post(" in provider_source
    assert "/api/v1/actions/execute" not in routes_source
    assert list(ExecutionAction) == [ExecutionAction.ADD_CONTACT_TAG]


def test_execution_record_rejects_invalid_lifecycle_combinations(
    phase6_tmp_path: Path,
) -> None:
    _approvals, executions, _repository, approval_id = approved_boundary(
        phase6_tmp_path / "record-validation.sqlite3", RecordingProvider()
    )
    record = executions.execute(action_request(approval_id))
    values = record.model_dump()

    invalid_updates = (
        {"created_at": datetime(2026, 8, 24, 12, 0)},
        {"status": ExecutionStatus.PENDING, "completed_at": record.completed_at},
        {"failure_category": ExecutionFailureCategory.INTERNAL_ERROR},
        {
            "status": ExecutionStatus.FAILED,
            "completed_at": record.completed_at,
            "failure_category": None,
        },
    )
    for updates in invalid_updates:
        with pytest.raises(ValidationError):
            ExecutionRecord.model_validate({**values, **updates})


def test_provider_configuration_and_unavailable_boundary_are_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported GHL API version"):
        GHLClient(SecretStr(TOKEN), cast(Literal["v3"], "v2"), 5.0)
    for timeout_seconds in (0.5, 31.0):
        with pytest.raises(ValueError, match="timeout"):
            GHLClient(SecretStr(TOKEN), "v3", timeout_seconds)
    with pytest.raises(GHLProviderError) as unavailable:
        UnavailableGHLProvider().add_contact_tag(
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)
        )
    assert unavailable.value.category is GHLFailureCategory.AUTHENTICATION
    assert unavailable.value.certainty is GHLOutcomeCertainty.DEFINITIVE


def test_ambiguous_request_error_and_oversized_response_are_unknown() -> None:
    parameters = GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG)

    def interrupted(request_: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("connection interrupted", request=request_)

    transports = (
        httpx.MockTransport(interrupted),
        httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 4_097)),
    )
    for transport in transports:
        client = GHLClient(SecretStr(TOKEN), "v3", 5.0, transport=transport)
        with pytest.raises(GHLProviderError) as captured:
            client.add_contact_tag(parameters)
        assert captured.value.category is GHLFailureCategory.UNKNOWN
        assert captured.value.certainty is GHLOutcomeCertainty.UNKNOWN


def test_unexpected_provider_status_is_definite_provider_error() -> None:
    client = GHLClient(
        SecretStr(TOKEN),
        "v3",
        5.0,
        transport=httpx.MockTransport(lambda _request: httpx.Response(418)),
    )
    with pytest.raises(GHLProviderError) as captured:
        client.add_contact_tag(GHLAddContactTagParameters(contact_id=CONTACT_ID, tag=TAG))
    assert captured.value.category is GHLFailureCategory.PROVIDER_ERROR
    assert captured.value.certainty is GHLOutcomeCertainty.DEFINITIVE


def test_execution_service_read_integrity_and_utc_clock_guards(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    _approvals, executions, _repository, approval_id = approved_boundary(
        phase6_tmp_path / "service-helpers.sqlite3", provider
    )
    completed = executions.execute(action_request(approval_id))
    assert executions.get(completed.execution_id) == completed
    assert executions.verify_integrity(completed.execution_id)

    approvals, invalid_clock_service, _repository, invalid_clock = boundary(
        phase6_tmp_path / "naive-clock.sqlite3", provider
    )
    created = approvals.create(tag_event(), intelligence())
    approvals.approve(created.approval_id)
    invalid_clock.value = datetime(2026, 8, 24, 12, 0)
    with pytest.raises(ValueError, match="UTC"):
        invalid_clock_service.execute(action_request(created.approval_id))


@pytest.mark.parametrize("target", ["audit", "provenance"])
def test_post_execution_trust_record_tampering_is_detected(
    phase6_tmp_path: Path, target: str
) -> None:
    database = phase6_tmp_path / f"post-execution-{target}.sqlite3"
    _approvals, executions, repository, approval_id = approved_boundary(
        database, RecordingProvider()
    )
    completed = executions.execute(action_request(approval_id))
    connection = sqlite3.connect(database)
    try:
        if target == "audit":
            connection.execute(
                "UPDATE approval_audit_events SET actor_id = 'tampered' "
                "WHERE approval_id = ? AND sequence_number = 1",
                (approval_id,),
            )
        else:
            connection.execute(
                "UPDATE approvals SET provenance_hash = ? WHERE approval_id = ?",
                ("0" * 64, approval_id),
            )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_integrity(completed.execution_id)
    expected = ExecutionIntegrityError if target == "audit" else ApprovalProvenanceInvalidError
    with pytest.raises(expected):
        repository.get_execution(completed.execution_id)


def test_safe_api_error_for_unapproved_execution(phase6_tmp_path: Path) -> None:
    provider = RecordingProvider()
    approvals, executions, _repository, _clock = boundary(
        phase6_tmp_path / "api-pending.sqlite3", provider
    )
    pending = approvals.create(tag_event(), intelligence())
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_execution_service] = lambda: executions
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/actions/contact-tag",
            json={
                "approval_id": pending.approval_id,
                "contact_id": CONTACT_ID,
                "tag": TAG,
            },
        )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "APPROVAL_NOT_APPROVED"
    assert "traceback" not in response.text.lower()
    assert provider.calls == []
