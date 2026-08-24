"""Phase 7 controlled HighLevel integration and trust-boundary tests."""

import json
import logging
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings
from ai_business_automation.models import (
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    EventCategory,
    EventSource,
    EventType,
    ExecutionFailureCategory,
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
    GHLClient,
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
    UnavailableGHLProvider,
)
from ai_business_automation.providers.ghl_factory import create_ghl_provider
from ai_business_automation.repositories import SQLiteExecutionRepository
from ai_business_automation.services.actions import ActionRegistry
from ai_business_automation.services.approval_errors import ProvenanceIntegrityError
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.execution_errors import (
    ApprovalNotApprovedError,
    ExecutionAlreadyCompletedError,
    ExecutionApprovalExpiredError,
    ExecutionIntegrityError,
)
from ai_business_automation.services.executions import ExecutionService
from ai_business_automation.services.normalization import EventNormalizer
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
EVENT_ID = "evt_phase7_ghl_identity"
CONTACT_ID = "contact_123456"
SECRET_MARKER = "phase7-placeholder-credential"


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


class RecordingProvider:
    def __init__(self, error: GHLProviderError | None = None) -> None:
        self.calls: list[GHLAddContactTagParameters] = []
        self.error = error

    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        self.calls.append(parameters)
        if self.error is not None:
            raise self.error


@pytest.fixture
def phase7_tmp_path() -> Iterator[Path]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = root / f"phase7-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def ghl_event() -> CanonicalBusinessEvent:
    return EventNormalizer(clock=lambda: NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.GHL_CONTACT_TAG_REQUEST,
            source=EventSource.INTERNAL,
            occurred_at=NOW - timedelta(minutes=1),
            payload={"contact_id": CONTACT_ID, "tags": ["vip", "qualified-lead"]},
        )
    )


def ghl_intelligence() -> BusinessIntelligenceResult:
    return BusinessIntelligenceResult(
        event_id=EVENT_ID,
        category=EventCategory.INTERNAL,
        priority=Priority.LOW,
        urgency=Urgency.LOW,
        intent=Intent.INTERNAL,
        confidence=0.93,
        summary="A requested external tag mutation requires approval.",
        reasons=["The event explicitly requests the one allowlisted operation."],
        recommended_next_step=RecommendedNextStep.REVIEW,
    )


def boundary(
    database: Path,
    provider: RecordingProvider,
    clock: Clock | None = None,
) -> tuple[ApprovalService, ExecutionService, SQLiteExecutionRepository, Clock]:
    active_clock = clock or Clock()
    repository = SQLiteExecutionRepository(database)
    repository.initialize()
    approvals = ApprovalService(
        repository=repository,
        policy_service=PolicyDecisionService(DeterministicPolicyEngine(), clock=active_clock),
        ttl_seconds=1_800,
        approver_id="phase7-approver",
        clock=active_clock,
    )
    executions = ExecutionService(
        repository=repository,
        registry=ActionRegistry(provider),
        actor_id="phase7-approver",
        clock=active_clock,
    )
    return approvals, executions, repository, active_clock


def test_strict_action_parameters_are_canonical_and_bounded() -> None:
    parameters = GHLAddContactTagParameters(
        contact_id=CONTACT_ID,
        tags=("vip", "Qualified Lead"),
    )
    assert parameters.tags == ("Qualified Lead", "vip")
    assert GHLAddTagsRequest(tags=parameters.tags).model_dump(mode="json") == {
        "tags": ["Qualified Lead", "vip"]
    }
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip", "VIP"))
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters.model_validate({"contact_id": CONTACT_ID, "tags": "vip"})
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters.model_validate({"contact_id": CONTACT_ID, "tags": [1]})
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("Bearer credentialmarker",))


@pytest.mark.parametrize(
    "contact_id",
    ["short", "contact/id123", "https://evil.example", "contact id123", "x" * 41],
)
def test_malformed_contact_ids_are_rejected(contact_id: str) -> None:
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters(contact_id=contact_id, tags=("vip",))


@pytest.mark.parametrize(
    "tags",
    [(), tuple(f"tag-{index}" for index in range(11)), ("x" * 51,), ("https://evil",), (" bad",)],
)
def test_invalid_tags_are_rejected(tags: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=tags)


def test_arbitrary_action_body_fields_and_external_sources_are_rejected() -> None:
    with pytest.raises(ValidationError):
        GHLAddContactTagParameters.model_validate(
            {"contact_id": CONTACT_ID, "tags": ["vip"], "url": "https://evil.example"}
        )
    with pytest.raises(ValidationError):
        ExternalEvent(
            event_type=EventType.GHL_CONTACT_TAG_REQUEST,
            source=EventSource.API,
            occurred_at=NOW,
            payload={"contact_id": CONTACT_ID, "tags": ["vip"]},
        )


def test_policy_and_approval_bind_exact_parameters(phase7_tmp_path: Path) -> None:
    approvals, _executions, repository, _clock = boundary(
        phase7_tmp_path / "binding.sqlite3", RecordingProvider()
    )
    event = ghl_event()
    decision = approvals.policy_service.decide(event, ghl_intelligence())
    assert decision.action is RecommendedAction.GHL_ADD_CONTACT_TAG
    created = approvals.create(event, ghl_intelligence())
    assert created.action_parameters == GHLAddContactTagParameters(
        contact_id=CONTACT_ID, tags=("qualified-lead", "vip")
    )
    assert repository.verify_audit_chain(created.approval_id)


def test_parameter_or_event_tampering_invalidates_provenance(phase7_tmp_path: Path) -> None:
    database = phase7_tmp_path / "tamper.sqlite3"
    approvals, _executions, repository, _clock = boundary(database, RecordingProvider())
    created = approvals.create(ghl_event(), ghl_intelligence())
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE approvals SET action_parameters_json = ? WHERE approval_id = ?",
            (json.dumps({"contact_id": "contact_999999", "tags": ["vip"]}), created.approval_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ProvenanceIntegrityError):
        repository.get(created.approval_id, NOW)


def test_success_executes_exactly_once_and_persists_no_secret(phase7_tmp_path: Path) -> None:
    database = phase7_tmp_path / "success.sqlite3"
    provider = RecordingProvider()
    approvals, executions, repository, _clock = boundary(database, provider)
    created = approvals.create(ghl_event(), ghl_intelligence())
    approvals.approve(created.approval_id)
    result = executions.execute(created.approval_id)
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.failure_category is None
    assert provider.calls == [created.action_parameters]
    assert repository.verify_integrity(result.execution_id)
    with pytest.raises(ExecutionAlreadyCompletedError):
        executions.execute(created.approval_id)
    assert len(provider.calls) == 1
    assert SECRET_MARKER.encode() not in database.read_bytes()
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT count(*) FROM internal_action_effects").fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("category", "certainty", "status"),
    [
        (GHLFailureCategory.AUTHENTICATION, GHLOutcomeCertainty.DEFINITIVE, ExecutionStatus.FAILED),
        (GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN, ExecutionStatus.UNKNOWN),
        (GHLFailureCategory.NETWORK, GHLOutcomeCertainty.UNKNOWN, ExecutionStatus.UNKNOWN),
    ],
)
def test_failure_certainty_drives_terminal_state_without_retry(
    phase7_tmp_path: Path,
    category: GHLFailureCategory,
    certainty: GHLOutcomeCertainty,
    status: ExecutionStatus,
) -> None:
    provider = RecordingProvider(GHLProviderError(category, certainty))
    approvals, executions, repository, _clock = boundary(
        phase7_tmp_path / f"{category.value}.sqlite3", provider
    )
    created = approvals.create(ghl_event(), ghl_intelligence())
    approvals.approve(created.approval_id)
    result = executions.execute(created.approval_id)
    assert result.status is status
    assert result.failure_category is ExecutionFailureCategory(category.value)
    assert len(provider.calls) == 1
    with pytest.raises(ExecutionAlreadyCompletedError):
        executions.execute(created.approval_id)
    assert len(provider.calls) == 1
    assert repository.verify_audit_chain(created.approval_id)


def test_pending_rejected_and_expired_approvals_never_call_provider(
    phase7_tmp_path: Path,
) -> None:
    for state in ("pending", "rejected", "expired"):
        provider = RecordingProvider()
        clock = Clock()
        approvals, executions, _repository, _clock = boundary(
            phase7_tmp_path / f"{state}.sqlite3", provider, clock
        )
        created = approvals.create(ghl_event(), ghl_intelligence())
        if state == "rejected":
            approvals.reject(created.approval_id, "Not authorized")
        if state == "expired":
            approvals.approve(created.approval_id)
            clock.value += timedelta(seconds=1_801)
        error = ExecutionApprovalExpiredError if state == "expired" else ApprovalNotApprovedError
        with pytest.raises(error):
            executions.execute(created.approval_id)
        assert provider.calls == []


def test_approved_internal_action_cannot_invoke_ghl(phase7_tmp_path: Path) -> None:
    provider = RecordingProvider()
    approvals, executions, _repository, _clock = boundary(
        phase7_tmp_path / "internal.sqlite3", provider
    )
    event = EventNormalizer(clock=lambda: NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.CUSTOMER_REQUEST,
            source=EventSource.API,
            occurred_at=NOW - timedelta(minutes=1),
            payload={"request_type": "review"},
        )
    )
    intelligence = ghl_intelligence().model_copy(
        update={
            "category": EventCategory.CUSTOMER,
            "intent": Intent.SUPPORT,
            "recommended_next_step": RecommendedNextStep.CONTACT_HUMAN,
        }
    )
    created = approvals.create(event, intelligence)
    approvals.approve(created.approval_id)
    assert executions.execute(created.approval_id).status is ExecutionStatus.SUCCEEDED
    assert provider.calls == []


def client_with(handler: httpx.MockTransport) -> GHLClient:
    return GHLClient(SecretStr(SECRET_MARKER), "v3", 5.0, transport=handler)


def test_http_contract_is_fixed_and_response_is_bounded() -> None:
    observed: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(201, json={"tags": ["vip", "existing"]})

    client_with(httpx.MockTransport(respond)).add_contact_tag(
        GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
    )
    request = observed[0]
    assert request.method == "POST"
    assert str(request.url) == ("https://services.leadconnectorhq.com/contacts/contact_123456/tags")
    assert request.headers["Version"] == "v3"
    assert request.headers["Authorization"] == f"Bearer {SECRET_MARKER}"
    assert json.loads(request.content) == {"tags": ["vip"]}
    assert "Idempotency" not in request.headers


@pytest.mark.parametrize(
    ("status", "category"),
    [
        (400, GHLFailureCategory.VALIDATION),
        (401, GHLFailureCategory.AUTHENTICATION),
        (403, GHLFailureCategory.AUTHORIZATION),
        (404, GHLFailureCategory.NOT_FOUND),
        (422, GHLFailureCategory.VALIDATION),
        (429, GHLFailureCategory.RATE_LIMIT),
        (500, GHLFailureCategory.SERVER_ERROR),
    ],
)
def test_http_failures_are_safely_classified(status: int, category: GHLFailureCategory) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(status, text=SECRET_MARKER))
    with pytest.raises(GHLProviderError) as captured:
        client_with(transport).add_contact_tag(
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
        )
    assert captured.value.category is category
    assert captured.value.certainty is GHLOutcomeCertainty.DEFINITIVE
    assert SECRET_MARKER not in str(captured.value)


@pytest.mark.parametrize("response", [httpx.Response(200), httpx.Response(201, text="bad-json")])
def test_unexpected_or_malformed_success_is_unknown(response: httpx.Response) -> None:
    transport = httpx.MockTransport(lambda request: response)
    with pytest.raises(GHLProviderError) as captured:
        client_with(transport).add_contact_tag(
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
        )
    assert captured.value.category is GHLFailureCategory.UNKNOWN
    assert captured.value.certainty is GHLOutcomeCertainty.UNKNOWN


def test_oversized_or_incomplete_success_is_unknown() -> None:
    responses = [
        httpx.Response(201, content=b"x" * 4_097),
        httpx.Response(201, json={"tags": ["different"]}),
    ]
    for response in responses:
        with pytest.raises(GHLProviderError) as captured:
            client_with(httpx.MockTransport(lambda request, item=response: item)).add_contact_tag(
                GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
            )
        assert captured.value.certainty is GHLOutcomeCertainty.UNKNOWN


@pytest.mark.parametrize(
    ("exception", "category", "certainty"),
    [
        (httpx.ReadTimeout("timeout"), GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN),
        (
            httpx.ConnectError("connect"),
            GHLFailureCategory.NETWORK,
            GHLOutcomeCertainty.DEFINITIVE,
        ),
        (
            httpx.ReadError("interrupted"),
            GHLFailureCategory.NETWORK,
            GHLOutcomeCertainty.UNKNOWN,
        ),
    ],
)
def test_transport_failures_are_classified(
    exception: httpx.RequestError,
    category: GHLFailureCategory,
    certainty: GHLOutcomeCertainty,
) -> None:
    def raise_transport(request: httpx.Request) -> httpx.Response:
        exception.request = request
        raise exception

    with pytest.raises(GHLProviderError) as captured:
        client_with(httpx.MockTransport(raise_transport)).add_contact_tag(
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
        )
    assert captured.value.category is category
    assert captured.value.certainty is certainty


def test_configuration_is_server_owned_secret_and_bounded() -> None:
    settings = Settings(
        environment=Environment.TEST,
        ghl_api_key=SECRET_MARKER,
        ghl_api_version="v3",
        ghl_timeout_seconds=5,
    )
    assert isinstance(settings.ghl_api_key, SecretStr)
    assert SECRET_MARKER not in repr(settings)
    assert isinstance(create_ghl_provider(settings), GHLClient)
    assert create_ghl_provider(Settings(environment=Environment.TEST)).__class__.__name__ == (
        "UnavailableGHLProvider"
    )
    with pytest.raises(ValidationError):
        Settings(environment=Environment.TEST, ghl_api_version="v4")
    with pytest.raises(ValidationError):
        Settings(environment=Environment.TEST, ghl_timeout_seconds=31)
    with pytest.raises(ValueError):
        GHLClient(SecretStr(SECRET_MARKER), "v3", 0.5)
    with pytest.raises(ValueError):
        GHLClient(SecretStr(SECRET_MARKER), "v4", 5.0)  # type: ignore[arg-type]
    with pytest.raises(GHLProviderError):
        UnavailableGHLProvider().add_contact_tag(
            GHLAddContactTagParameters(contact_id=CONTACT_ID, tags=("vip",))
        )


def test_provider_failures_and_secrets_do_not_leak_to_logs(
    phase7_tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = RecordingProvider(
        GHLProviderError(GHLFailureCategory.AUTHENTICATION, GHLOutcomeCertainty.DEFINITIVE)
    )
    approvals, executions, _repository, _clock = boundary(
        phase7_tmp_path / "logs.sqlite3", provider
    )
    created = approvals.create(ghl_event(), ghl_intelligence())
    approvals.approve(created.approval_id)
    with caplog.at_level(logging.INFO):
        public = executions.execute(created.approval_id).public().model_dump_json()
    output = caplog.text + public
    assert SECRET_MARKER not in output
    assert CONTACT_ID not in output
    assert "Authorization" not in output
    assert "GHL_AUTHENTICATION" not in public


def test_audit_failure_category_is_hash_bound(phase7_tmp_path: Path) -> None:
    database = phase7_tmp_path / "audit.sqlite3"
    provider = RecordingProvider(
        GHLProviderError(GHLFailureCategory.RATE_LIMIT, GHLOutcomeCertainty.DEFINITIVE)
    )
    approvals, executions, repository, _clock = boundary(database, provider)
    created = approvals.create(ghl_event(), ghl_intelligence())
    approvals.approve(created.approval_id)
    executions.execute(created.approval_id)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT failure_category FROM approval_audit_events "
            "WHERE event_type = 'EXECUTION_FAILED'"
        ).fetchone() == ("GHL_RATE_LIMIT",)
        connection.execute(
            "UPDATE approval_audit_events SET failure_category = 'GHL_UNKNOWN' "
            "WHERE event_type = 'EXECUTION_FAILED'"
        )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_audit_chain(created.approval_id)
    with pytest.raises(ExecutionIntegrityError):
        executions.execute(created.approval_id)
