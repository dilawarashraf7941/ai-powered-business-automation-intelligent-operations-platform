"""Phase 5 trusted approval persistence, integrity, API, and concurrency tests."""

import secrets
import shutil
import sqlite3
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import ai_business_automation.repositories.approvals as repository_module
from ai_business_automation.api.routes import get_approval_service, get_intelligence_service
from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    ApprovalRecord,
    ApprovalStatus,
    AuditEvent,
    AuditEventType,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    EventCategory,
    EventSource,
    EventType,
    ExternalEvent,
    Intent,
    Priority,
    RecommendedNextStep,
    RejectionRequest,
    Urgency,
)
from ai_business_automation.models.events import JsonValue
from ai_business_automation.providers import AIAnalysisRequest, AITimeoutError
from ai_business_automation.repositories import SQLiteApprovalRepository
from ai_business_automation.services.approval_errors import (
    ApprovalConflictError,
    ApprovalExpiredError,
    ApprovalInvalidStateError,
    ApprovalNotFoundError,
    PolicyValidationError,
    ProvenanceIntegrityError,
)
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.intelligence import BusinessIntelligenceService
from ai_business_automation.services.normalization import EventNormalizer
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService
from ai_business_automation.services.provenance import (
    build_trusted_provenance,
    provenance_hash,
)

FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
EVENT_ID = "evt_fixed_server_identity"


@dataclass
class MutableClock:
    value: datetime = FIXED_NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class ApprovalFakeProvider:
    def __init__(
        self,
        output: Mapping[str, object] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.output = output or provider_output()
        self.error = error
        self.requests: list[AIAnalysisRequest] = []

    @property
    def name(self) -> str:
        return "fake"

    async def analyze(self, request: AIAnalysisRequest) -> Mapping[str, object]:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.output


def provider_output(**updates: object) -> dict[str, object]:
    result: dict[str, object] = {
        "priority": "LOW",
        "urgency": "LOW",
        "intent": "SUPPORT",
        "confidence": 0.95,
        "summary": "A customer request requires human contact.",
        "reasons": ["The recommendation requires human review."],
        "recommended_next_step": "CONTACT_HUMAN",
    }
    result.update(updates)
    return result


def external_api_event(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "event_type": "CUSTOMER_REQUEST",
        "source": "WEB_FORM",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {"request_type": "demo"},
    }
    values.update(updates)
    return values


def canonical_event(**payload: JsonValue) -> CanonicalBusinessEvent:
    return EventNormalizer(clock=lambda: FIXED_NOW, event_id_factory=lambda: EVENT_ID).normalize(
        ExternalEvent(
            event_type=EventType.CUSTOMER_REQUEST,
            source=EventSource.API,
            occurred_at=FIXED_NOW - timedelta(minutes=1),
            payload={"request_type": "demo", **payload},
        )
    )


def intelligence(**updates: object) -> BusinessIntelligenceResult:
    values: dict[str, object] = {
        "event_id": EVENT_ID,
        "category": EventCategory.CUSTOMER,
        "priority": Priority.LOW,
        "urgency": Urgency.LOW,
        "intent": Intent.SUPPORT,
        "confidence": 0.95,
        "summary": "A customer request requires human contact.",
        "reasons": ["The recommendation requires human review."],
        "recommended_next_step": RecommendedNextStep.CONTACT_HUMAN,
    }
    values.update(updates)
    return BusinessIntelligenceResult(**values)  # type: ignore[arg-type]


@pytest.fixture
def workspace_tmp_path() -> Iterator[Path]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = root / f"phase5-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def approval_boundary(
    workspace_tmp_path: Path,
) -> tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock]:
    database = workspace_tmp_path / "approvals.sqlite3"
    clock = MutableClock()
    repository = SQLiteApprovalRepository(database)
    repository.initialize()
    policy = PolicyDecisionService(DeterministicPolicyEngine(), clock=clock)
    service = ApprovalService(
        repository=repository,
        policy_service=policy,
        ttl_seconds=1_800,
        approver_id="development-approver",
        clock=clock,
    )
    return service, repository, database, clock


@pytest.fixture
def approval_client(
    workspace_tmp_path: Path,
) -> Iterator[tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock]]:
    database = workspace_tmp_path / "api-approvals.sqlite3"
    clock = MutableClock()
    repository = SQLiteApprovalRepository(database)
    repository.initialize()
    policy = PolicyDecisionService(DeterministicPolicyEngine(), clock=clock)
    approval_service = ApprovalService(
        repository=repository,
        policy_service=policy,
        ttl_seconds=1_800,
        approver_id="development-approver",
        clock=clock,
    )
    provider = ApprovalFakeProvider()
    intelligence_service = BusinessIntelligenceService(provider, 8_192, 800)
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_approval_service] = lambda: approval_service
    app.dependency_overrides[get_intelligence_service] = lambda: intelligence_service
    with TestClient(app) as client:
        yield client, provider, approval_service, database, clock


def test_create_pending_approval_with_server_owned_fields(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    record = service.create(canonical_event(), intelligence())
    assert record.approval_id.startswith("apr_")
    assert record.approval_id != EVENT_ID
    assert record.status is ApprovalStatus.PENDING
    assert record.decision.value == "REQUIRE_HUMAN_APPROVAL"
    assert record.created_at == clock.value
    assert record.expires_at == clock.value + timedelta(seconds=1_800)
    assert record.decided_at is None
    assert record.approver_id is None
    assert len(record.provenance_hash) == 64
    assert record.provenance_hash == record.provenance_hash.lower()
    assert repository.verify_audit_chain(record.approval_id)


@pytest.mark.parametrize(
    "analysis",
    [
        intelligence(recommended_next_step=RecommendedNextStep.REVIEW),
        intelligence(
            priority=Priority.HIGH,
            recommended_next_step=RecommendedNextStep.NO_ACTION,
        ),
    ],
)
def test_allow_and_deny_do_not_create_approval(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    analysis: BusinessIntelligenceResult,
) -> None:
    service, _repository, database, _clock = approval_boundary
    with pytest.raises(PolicyValidationError):
        service.create(canonical_event(), analysis)
    assert _approval_count(database) == 0


def test_provenance_hash_is_deterministic_and_server_generated(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, _repository, _database, _clock = approval_boundary
    event = canonical_event()
    analysis = intelligence()
    decision = service.policy_service.decide(event, analysis)
    first = build_trusted_provenance(event, analysis, decision)
    second = build_trusted_provenance(event, analysis, decision)
    assert first == second
    assert provenance_hash(first) == provenance_hash(second)
    assert len(provenance_hash(first)) == 64


def test_pending_read_and_automatic_persisted_expiry(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    assert service.get(created.approval_id).status is ApprovalStatus.PENDING
    clock.advance(1_801)
    expired = service.get(created.approval_id)
    assert expired.status is ApprovalStatus.EXPIRED
    assert expired.decided_at == clock.value
    assert service.get(created.approval_id).status is ApprovalStatus.EXPIRED
    assert repository.verify_audit_chain(created.approval_id)


def test_pending_to_approved_uses_server_approver(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    clock.advance(10)
    approved = service.approve(created.approval_id)
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.decided_at == clock.value
    assert approved.approver_id == "development-approver"
    assert approved.rejection_reason is None
    assert repository.verify_audit_chain(created.approval_id)


def test_pending_to_rejected_stores_bounded_reason_without_returning_it(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    clock.advance(10)
    rejected = service.reject(created.approval_id, "Insufficient verified business context.")
    assert rejected.status is ApprovalStatus.REJECTED
    assert rejected.approver_id == "development-approver"
    assert rejected.decided_at == clock.value
    assert rejected.rejection_reason == "Insufficient verified business context."
    assert "rejection_reason" not in rejected.public().model_dump()
    assert repository.verify_audit_chain(created.approval_id)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("approve", "approve"),
        ("approve", "reject"),
        ("reject", "approve"),
        ("reject", "reject"),
    ],
)
def test_terminal_approval_cannot_transition_again(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    first: str,
    second: str,
) -> None:
    service, repository, _database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    _transition(service, created.approval_id, first)
    with pytest.raises(ApprovalInvalidStateError):
        _transition(service, created.approval_id, second)
    assert repository.verify_audit_chain(created.approval_id)


@pytest.mark.parametrize("transition", ["approve", "reject"])
def test_expired_approval_cannot_transition(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    transition: str,
) -> None:
    service, _repository, _database, clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    clock.advance(1_801)
    with pytest.raises(ApprovalExpiredError):
        _transition(service, created.approval_id, transition)
    assert service.get(created.approval_id).status is ApprovalStatus.EXPIRED


@pytest.mark.parametrize(
    "reason",
    ["", "   ", "x" * 501, "visit https://untrusted.invalid", "bash unsafe", "bad\u0001text"],
)
def test_rejection_reason_is_strictly_bounded(reason: str) -> None:
    with pytest.raises(ValidationError):
        RejectionRequest(reason=reason)


def test_rejection_reason_is_trimmed_and_rejects_extended_control_characters() -> None:
    assert RejectionRequest(reason="  Human review found insufficient context.  ").reason == (
        "Human review found insufficient context."
    )
    with pytest.raises(ValidationError):
        RejectionRequest(reason="unsafe\x7fcontrol")


def test_canonical_content_is_hashed_but_not_stored(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, _repository, database, _clock = approval_boundary
    marker = "customer-content-must-not-be-stored"
    reason_marker = "ai-reason-must-not-be-stored"
    service.create(
        canonical_event(message_text=marker),
        intelligence(summary=marker, reasons=[reason_marker]),
    )
    connection = sqlite3.connect(database)
    try:
        row = cast(
            tuple[str, str],
            connection.execute("SELECT evidence_json, provenance_json FROM approvals").fetchone(),
        )
    finally:
        connection.close()
    serialized = "".join(row)
    assert marker not in serialized
    assert reason_marker not in serialized
    assert "prompt" not in serialized.lower()
    assert "credential" not in serialized.lower()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("provenance_hash", "a" * 64),
        ("policy_version", "2.0"),
        ("risk", "CRITICAL"),
        ("event_id", "evt_tampered_server_identity"),
        (
            "evidence_json",
            '[{"code":"LOW_CONFIDENCE","source":"AI_ANALYSIS","value":0.1}]',
        ),
    ],
)
def test_approval_provenance_and_authoritative_tampering_fails_closed(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    column: str,
    value: str,
) -> None:
    service, repository, database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    _tamper_column(database, column, value, created.approval_id)
    with pytest.raises(ProvenanceIntegrityError):
        service.approve(created.approval_id)
    assert repository.verify_audit_chain(created.approval_id)


def test_audit_creation_and_hash_chain_succeeds(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    service.approve(created.approval_id)
    events = _audit_rows(database, created.approval_id)
    assert [row[0] for row in events] == ["APPROVAL_CREATED", "APPROVAL_APPROVED"]
    assert events[0][1] == "0" * 64
    assert events[1][1] == events[0][2]
    assert repository.verify_audit_chain(created.approval_id)


@pytest.mark.parametrize("tamper", ["modified", "deleted", "reordered", "broken_link"])
def test_audit_tampering_is_detected(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    tamper: str,
) -> None:
    service, repository, database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    service.approve(created.approval_id)
    connection = sqlite3.connect(database)
    try:
        if tamper == "modified":
            connection.execute(
                "UPDATE approval_audit_events SET actor_id = ? WHERE sequence_number = ?",
                ("modified-actor", 1),
            )
        elif tamper == "deleted":
            connection.execute("DELETE FROM approval_audit_events WHERE sequence_number = ?", (2,))
        elif tamper == "reordered":
            connection.execute(
                "UPDATE approval_audit_events SET sequence_number = ? WHERE sequence_number = ?",
                (100, 1),
            )
            connection.execute(
                "UPDATE approval_audit_events SET sequence_number = ? WHERE sequence_number = ?",
                (1, 2),
            )
            connection.execute(
                "UPDATE approval_audit_events SET sequence_number = ? WHERE sequence_number = ?",
                (2, 100),
            )
        else:
            connection.execute(
                """
                UPDATE approval_audit_events SET previous_event_hash = ?
                WHERE sequence_number = ?
                """,
                ("f" * 64, 2),
            )
        connection.commit()
    finally:
        connection.close()
    assert not repository.verify_audit_chain(created.approval_id)


def test_duplicate_audit_identity_is_detected_by_verifier(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, repository, _database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    service.approve(created.approval_id)
    original = repository_module._audit_from_row
    seen: list[str] = []

    def duplicate_second(row: sqlite3.Row) -> AuditEvent:
        event = original(row)
        if not seen:
            seen.append(event.audit_event_id)
            return event
        return event.model_copy(update={"audit_event_id": seen[0]})

    monkeypatch.setattr(repository_module, "_audit_from_row", duplicate_second)
    assert not repository.verify_audit_chain(created.approval_id)


def test_database_primary_key_prevents_duplicate_audit_identity(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, _repository, database, _clock = approval_boundary
    service.create(canonical_event(), intelligence())
    connection = sqlite3.connect(database)
    try:
        row = connection.execute("SELECT * FROM approval_audit_events").fetchone()
        assert row is not None
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO approval_audit_events (
                    audit_event_id, approval_id, sequence_number, event_type,
                    execution_id, event_id, failure_category, status, actor_id, occurred_at,
                    previous_event_hash, event_hash
                ) SELECT audit_event_id, approval_id, sequence_number, event_type,
                    execution_id, event_id, failure_category, status, actor_id, occurred_at,
                    previous_event_hash, event_hash
                  FROM approval_audit_events WHERE audit_event_id = ?
                """,
                (row[0],),
            )
    finally:
        connection.close()


def test_concurrent_double_approve_has_one_winner(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    barrier = Barrier(2)

    def approve() -> object:
        barrier.wait()
        try:
            return service.approve(created.approval_id)
        except ApprovalInvalidStateError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: approve(), range(2)))
    assert sum(isinstance(result, ApprovalRecord) for result in results) == 1
    assert sum(isinstance(result, ApprovalInvalidStateError) for result in results) == 1
    assert service.get(created.approval_id).status is ApprovalStatus.APPROVED
    assert repository.verify_audit_chain(created.approval_id)


def test_concurrent_approve_reject_race_has_one_terminal_winner(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, _clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    barrier = Barrier(2)

    def transition(kind: str) -> object:
        barrier.wait()
        try:
            return _transition(service, created.approval_id, kind)
        except ApprovalInvalidStateError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(transition, ["approve", "reject"]))
    assert sum(isinstance(result, ApprovalRecord) for result in results) == 1
    assert sum(isinstance(result, ApprovalInvalidStateError) for result in results) == 1
    assert service.get(created.approval_id).status in {
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
    }
    assert repository.verify_audit_chain(created.approval_id)


def test_expiry_approve_race_never_approves(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    created = service.create(canonical_event(), intelligence())
    clock.advance(1_801)
    barrier = Barrier(2)

    def operation(kind: str) -> object:
        barrier.wait()
        try:
            return (
                service.get(created.approval_id)
                if kind == "read"
                else service.approve(created.approval_id)
            )
        except (ApprovalExpiredError, ApprovalInvalidStateError) as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(operation, ["read", "approve"]))
    assert service.get(created.approval_id).status is ApprovalStatus.EXPIRED
    assert repository.verify_audit_chain(created.approval_id)


def test_approval_creation_api_response_is_safe_and_server_owned(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
) -> None:
    client, provider, _service, _database, clock = approval_client
    response = client.post("/api/v1/approvals", json=external_api_event())
    assert response.status_code == 201
    result = response.json()
    assert result["approval_id"].startswith("apr_")
    assert result["status"] == "PENDING"
    assert result["decision"] == "REQUIRE_HUMAN_APPROVAL"
    assert result["expires_at"] == (clock.value + timedelta(seconds=1_800)).isoformat().replace(
        "+00:00", "Z"
    )
    assert len(result["provenance_hash"]) == 64
    assert response.headers["X-Request-ID"]
    assert len(provider.requests) == 1
    for forbidden in (
        "payload",
        "evidence",
        "confidence",
        "summary",
        "reasons",
        "prompt",
        "provider",
        "rejection_reason",
    ):
        assert forbidden not in result


@pytest.mark.parametrize(
    "field",
    [
        "approval_id",
        "approver_id",
        "created_at",
        "expires_at",
        "decided_at",
        "ttl",
        "policy_version",
        "decision",
        "action",
        "risk",
        "evidence",
        "provenance_hash",
    ],
)
def test_client_authoritative_approval_fields_are_rejected_before_ai(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
    field: str,
) -> None:
    client, provider, _service, _database, _clock = approval_client
    response = client.post(
        "/api/v1/approvals", json=external_api_event(**{field: "client-controlled"})
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "APPROVAL_VALIDATION_ERROR"
    assert provider.requests == []


@pytest.mark.parametrize(
    "output",
    [
        provider_output(recommended_next_step="REVIEW"),
        provider_output(priority="HIGH", recommended_next_step="NO_ACTION"),
    ],
)
def test_api_allow_and_deny_create_no_approval(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
    output: dict[str, object],
) -> None:
    client, provider, _service, database, _clock = approval_client
    provider.output = output
    response = client.post("/api/v1/approvals", json=external_api_event())
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "POLICY_VALIDATION_FAILED"
    assert _approval_count(database) == 0


def test_api_read_approve_and_reject_lifecycles(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
) -> None:
    client, _provider, _service, _database, _clock = approval_client
    first = client.post("/api/v1/approvals", json=external_api_event()).json()["approval_id"]
    pending = client.get(f"/api/v1/approvals/{first}")
    assert pending.status_code == 200
    assert pending.json()["status"] == "PENDING"
    approved = client.post(f"/api/v1/approvals/{first}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["approver_id"] == "development-approver"

    second = client.post("/api/v1/approvals", json=external_api_event()).json()["approval_id"]
    rejected = client.post(
        f"/api/v1/approvals/{second}/reject",
        json={"reason": "A human rejected this recommendation."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert "reason" not in rejected.json()


def test_api_read_persists_expiry(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
) -> None:
    client, _provider, _service, _database, clock = approval_client
    approval_id = client.post("/api/v1/approvals", json=external_api_event()).json()["approval_id"]
    clock.advance(1_801)
    response = client.get(f"/api/v1/approvals/{approval_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "EXPIRED"


def test_api_rejects_client_transition_metadata_and_unsafe_reason(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
) -> None:
    client, _provider, _service, _database, _clock = approval_client
    approval_id = client.post("/api/v1/approvals", json=external_api_event()).json()["approval_id"]
    approve = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"approver_id": "client-actor", "decided_at": "2026-01-01T00:00:00Z"},
    )
    assert approve.status_code == 422
    reject = client.post(
        f"/api/v1/approvals/{approval_id}/reject",
        json={"reason": "visit https://untrusted.invalid", "approver_id": "client"},
    )
    assert reject.status_code == 422
    assert client.get(f"/api/v1/approvals/{approval_id}").json()["status"] == "PENDING"


def test_api_not_found_and_sql_injection_are_safe(
    approval_client: tuple[TestClient, ApprovalFakeProvider, ApprovalService, Path, MutableClock],
) -> None:
    client, _provider, _service, _database, _clock = approval_client
    missing = client.get("/api/v1/approvals/apr_missing_server_identity")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "APPROVAL_NOT_FOUND"
    injection = client.get("/api/v1/approvals/apr_x%27%20OR%201%3D1--")
    assert injection.status_code == 422
    assert "sql" not in injection.text.lower()


def test_ai_failure_creates_no_approval_and_preserves_request_id(
    workspace_tmp_path: Path,
) -> None:
    database = workspace_tmp_path / "failure.sqlite3"
    repository = SQLiteApprovalRepository(database)
    repository.initialize()
    approval_service = ApprovalService(
        repository,
        PolicyDecisionService(DeterministicPolicyEngine()),
        1_800,
        "development-approver",
    )
    intelligence_service = BusinessIntelligenceService(
        ApprovalFakeProvider(error=AITimeoutError()), 8_192, 800
    )
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_approval_service] = lambda: approval_service
    app.dependency_overrides[get_intelligence_service] = lambda: intelligence_service
    with TestClient(app) as client:
        response = client.post("/api/v1/approvals", json=external_api_event())
    assert response.status_code == 504
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]
    assert _approval_count(database) == 0


@pytest.mark.parametrize(
    "path",
    ["../unsafe.sqlite3", "C:\\unsafe.sqlite3", "/absolute.sqlite3", "unsafe.db"],
)
def test_arbitrary_database_paths_are_rejected(path: str) -> None:
    with pytest.raises(ValidationError):
        Settings(approval_database_path=path)


def test_approval_ttl_and_development_identity_configuration_are_bounded() -> None:
    assert Settings().approval_ttl_seconds == 1_800
    assert Settings().approver_id == "development-approver"
    for values in (
        {"approval_ttl_seconds": 59},
        {"approval_ttl_seconds": 86_401},
        {"approver_id": "unsafe identity"},
        {"approver_id": "x" * 65},
    ):
        with pytest.raises(ValidationError):
            Settings(**values)


def test_repository_uses_parameterized_values_and_no_dynamic_sql() -> None:
    source = Path(repository_module.__file__).read_text(encoding="utf-8")
    assert "SELECT * FROM approvals WHERE approval_id = ?" in source
    assert "WHERE approval_id = ? AND status = 'PENDING'" in source
    for forbidden in ('f"SELECT', 'f"UPDATE', 'f"INSERT', ".format("):
        assert forbidden not in source


@pytest.mark.parametrize(
    "updates",
    [
        {"created_at": FIXED_NOW.astimezone(timezone(timedelta(hours=5)))},
        {"expires_at": FIXED_NOW},
        {"decided_at": FIXED_NOW, "approver_id": "actor"},
        {"rejection_reason": "Unexpected rejection metadata."},
        {"status": ApprovalStatus.APPROVED},
        {
            "status": ApprovalStatus.APPROVED,
            "decided_at": FIXED_NOW,
            "approver_id": "actor",
            "rejection_reason": "Not valid for approval.",
        },
        {"status": ApprovalStatus.REJECTED},
        {"status": ApprovalStatus.EXPIRED},
        {
            "status": ApprovalStatus.EXPIRED,
            "decided_at": FIXED_NOW,
            "approver_id": "actor",
        },
    ],
)
def test_approval_record_rejects_inconsistent_lifecycle_metadata(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
    updates: dict[str, object],
) -> None:
    service, _repository, _database, _clock = approval_boundary
    valid = service.create(canonical_event(), intelligence()).model_dump()
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate({**valid, **updates})


def test_audit_event_rejects_non_utc_timestamp() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            audit_event_id="aud_fixed_server_audit_identity",
            approval_id="apr_fixed_server_approval_identity",
            sequence_number=1,
            event_type=AuditEventType.APPROVAL_CREATED,
            status=ApprovalStatus.PENDING,
            actor_id="SYSTEM",
            occurred_at=FIXED_NOW.astimezone(timezone(timedelta(hours=5))),
            previous_event_hash="0" * 64,
            event_hash="a" * 64,
        )


def test_repository_rejects_duplicate_approval_and_invalid_target(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, clock = approval_boundary
    fixed_id = "apr_fixed_server_approval_identity"
    fixed_service = ApprovalService(
        repository,
        service.policy_service,
        1_800,
        "development-approver",
        clock=clock,
        approval_id_factory=lambda: fixed_id,
    )
    fixed_service.create(canonical_event(), intelligence())
    with pytest.raises(ApprovalConflictError):
        fixed_service.create(canonical_event(), intelligence())
    with pytest.raises(ApprovalInvalidStateError):
        repository.transition(
            fixed_id,
            ApprovalStatus.PENDING,
            clock.value,
            "development-approver",
        )
    with pytest.raises(ApprovalNotFoundError):
        repository.verify_audit_chain("apr_missing_server_identity")


def test_approval_service_rejects_invalid_ttl_and_non_utc_clock(
    approval_boundary: tuple[ApprovalService, SQLiteApprovalRepository, Path, MutableClock],
) -> None:
    service, repository, _database, _clock = approval_boundary
    with pytest.raises(ValueError):
        ApprovalService(repository, service.policy_service, 59, "development-approver")
    invalid_clock_service = ApprovalService(
        repository,
        service.policy_service,
        1_800,
        "development-approver",
        clock=lambda: datetime(2026, 8, 23, 12, 0),
    )
    with pytest.raises(ValueError):
        invalid_clock_service.create(canonical_event(), intelligence())
    created = service.create(canonical_event(), intelligence())
    assert service.verify_audit_integrity(created.approval_id)


def _transition(service: ApprovalService, approval_id: str, kind: str) -> ApprovalRecord:
    if kind == "approve":
        return service.approve(approval_id)
    return service.reject(approval_id, "A bounded human rejection reason.")


def _approval_count(database: Path) -> int:
    connection = sqlite3.connect(database)
    try:
        row = connection.execute("SELECT COUNT(*) FROM approvals").fetchone()
        assert row is not None
        return int(row[0])
    finally:
        connection.close()


def _tamper_column(database: Path, column: str, value: str, approval_id: str) -> None:
    allowed_columns = {"provenance_hash", "policy_version", "risk", "event_id", "evidence_json"}
    assert column in allowed_columns
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        statement_by_column = {
            "provenance_hash": "UPDATE approvals SET provenance_hash = ? WHERE approval_id = ?",
            "policy_version": "UPDATE approvals SET policy_version = ? WHERE approval_id = ?",
            "risk": "UPDATE approvals SET risk = ? WHERE approval_id = ?",
            "event_id": "UPDATE approvals SET event_id = ? WHERE approval_id = ?",
            "evidence_json": "UPDATE approvals SET evidence_json = ? WHERE approval_id = ?",
        }
        connection.execute(statement_by_column[column], (value, approval_id))
        connection.commit()
    finally:
        connection.close()


def _audit_rows(database: Path, approval_id: str) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """
            SELECT event_type, previous_event_hash, event_hash
            FROM approval_audit_events WHERE approval_id = ? ORDER BY sequence_number
            """,
            (approval_id,),
        ).fetchall()
        return [(str(row[0]), str(row[1]), str(row[2])) for row in rows]
    finally:
        connection.close()
