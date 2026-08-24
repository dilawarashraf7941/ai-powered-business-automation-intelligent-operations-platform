"""Phase 8 bounded observability and operational safety tests."""

import json
import logging
import re
import secrets
import shutil
import socket
from collections.abc import Iterator
from io import StringIO
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_business_automation.api.routes import (
    get_approval_service,
    get_execution_service,
    get_intelligence_service,
    get_policy_service,
)
from ai_business_automation.config import Environment, Settings
from ai_business_automation.logging import JsonFormatter, redact
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    AuthRole,
    FailureCategory,
    MetricName,
    ReadinessStatus,
)
from ai_business_automation.providers import (
    GHLFailureCategory,
    GHLOutcomeCertainty,
    GHLProviderError,
)
from ai_business_automation.repositories import SQLiteApprovalRepository
from ai_business_automation.repositories.security_audit import SecurityAuditRepository
from ai_business_automation.services.approvals import ApprovalService
from ai_business_automation.services.intelligence import BusinessIntelligenceService
from ai_business_automation.services.observability import (
    LocalReadinessProbe,
    OperationalMetrics,
)
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService
from tests.test_phase4 import PolicyFakeProvider, api_event, provider_output
from tests.test_phase5 import ApprovalFakeProvider, MutableClock, external_api_event
from tests.test_phase6 import RecordingProvider, action_request, approved_boundary

_TOKEN = "fake-phase8-admin-token"


def _settings(role: AuthRole = AuthRole.ADMIN) -> Settings:
    return Settings(
        environment=Environment.TEST,
        approval_database_path="phase8.sqlite3",
        auth_token_1=SecretStr(_TOKEN),
        auth_actor_1="phase8-actor",
        auth_role_1=role,
    )


def _client(app: FastAPI | None = None) -> TestClient:
    active_app = app or create_app(_settings())
    return TestClient(active_app, headers={"Authorization": f"Bearer {_TOKEN}"})


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = (root / f"phase8-{secrets.token_hex(12)}").resolve()
    path.mkdir()
    monkeypatch.chdir(path)
    try:
        yield
    finally:
        monkeypatch.chdir(Path(__file__).resolve().parents[1])
        shutil.rmtree(path, ignore_errors=True)


def _capture_logs() -> tuple[StringIO, logging.Handler]:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logging.getLogger("ai_business_automation").addHandler(handler)
    return stream, handler


def test_request_id_is_server_owned_fixed_hex_and_correlates_logs_and_errors() -> None:
    app = create_app(_settings())
    stream, handler = _capture_logs()
    client_value = "client-correlation-must-be-replaced"
    customer_marker = "customer-content-must-never-be-logged"
    try:
        with _client(app) as client:
            response = client.post(
                "/api/v1/actions/contact-tag",
                json={"customer_text": customer_marker},
                headers={
                    "Authorization": f"Bearer {_TOKEN}",
                    "Cookie": "session=cookie-must-not-be-logged",
                    "X-Request-ID": client_value,
                },
            )
    finally:
        logging.getLogger("ai_business_automation").removeHandler(handler)
    request_id = response.headers["X-Request-ID"]
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert response.status_code == 422
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)
    assert request_id != client_value
    assert response.json()["error"]["request_id"] == request_id
    assert records
    assert all(record.get("request_id") == request_id for record in records)
    serialized = stream.getvalue()
    for forbidden in (_TOKEN, client_value, customer_marker, "cookie-must-not-be-logged"):
        assert forbidden not in serialized


def test_health_is_public_constant_and_uses_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail("health attempted an external connection")

    with TestClient(create_app(_settings())) as client:
        monkeypatch.setattr(socket.socket, "connect", blocked_connect)
        response = client.get("/health", headers={"X-Request-ID": "client-value"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["X-Request-ID"])


def test_readiness_checks_only_local_sqlite_and_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail("readiness attempted an external connection")

    app = create_app(_settings())
    with TestClient(app) as client:
        monkeypatch.setattr(socket.socket, "connect", blocked_connect)
        ready = client.get("/ready")
        app.state.readiness = LocalReadinessProbe(
            SecurityAuditRepository(Path("missing-parent/local.sqlite3"))
        )
        not_ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    assert not_ready.status_code == 503
    assert not_ready.json() == {"status": "not_ready"}
    assert "missing-parent" not in not_ready.text
    assert not Path("missing-parent").exists()


def test_admin_status_is_admin_only_bounded_and_preserves_headers() -> None:
    non_admin = create_app(_settings(AuthRole.EXECUTOR))
    with _client(non_admin) as client:
        forbidden = client.get("/api/v1/admin/status")
    assert forbidden.status_code == 403

    app = create_app(_settings())
    with _client(app) as client:
        response = client.get(
            "/api/v1/admin/status", headers={"Origin": "https://untrusted.invalid"}
        )
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "ok"
    assert body["actor_role"] == "ADMIN"
    assert body["policy_version"] == "1.0"
    assert body["supported_actions"] == ["ADD_CONTACT_TAG"]
    assert body["readiness"] == "ready"
    assert set(body["metrics"]) == {name.value for name in MetricName} | {"request_latency"}
    assert len(response.content) < 2_048
    for forbidden_value in ("environment", "database", "sqlite3", _TOKEN, "provider"):
        assert forbidden_value not in response.text.lower()
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers


def test_recursive_redaction_and_log_output_are_strictly_bounded() -> None:
    sensitive = {
        "authorization": "one",
        "nested": {
            "proxy-authorization": "two",
            "api_key": "three",
            "apikey": "four",
            "access_token": "five",
            "refresh_token": "six",
            "password": "seven",
            "secret": "eight",
            "credential": "nine",
            "cookie": "ten",
            "set-cookie": "eleven",
        },
    }
    cleaned = redact(sensitive)
    assert cleaned["authorization"] == "[REDACTED]"
    assert set(cleaned["nested"].values()) == {"[REDACTED]"}
    deep = redact({"deep": {"a": {"b": {"c": {"d": {"e": "value"}}}}}})
    assert deep["deep"]["a"]["b"]["c"]["d"] == "[TRUNCATED]"
    assert len(redact(list(range(100)))) == 20
    assert len(json.dumps(redact([list(range(20)) for _ in range(20)]))) < 512

    record = logging.LogRecord(
        "test",
        logging.ERROR,
        __file__,
        1,
        "https://customer.invalid customer prompt and provider response",
        (),
        None,
    )
    for field in (
        "request_id",
        "actor_id",
        "role",
        "operation",
        "endpoint_category",
        "outcome",
        "status_class",
        "event_id",
        "event_type",
        "source",
        "category",
        "error_category",
        "failure_category",
        "provider",
        "latency_ms",
        "duration_ms",
        "decision",
        "action",
        "risk",
        "policy_version",
        "approval_id",
        "status",
        "execution_id",
        "result_code",
    ):
        setattr(record, field, "x" * 10_000)
    record.authorization = f"Bearer {_TOKEN}"
    serialized = JsonFormatter().format(record)
    parsed = json.loads(serialized)
    assert len(serialized.encode("utf-8")) <= 4_096
    assert parsed["event"] == "unclassified_event"
    assert _TOKEN not in serialized
    assert "https://" not in serialized
    assert "authorization" not in serialized.lower()


def test_metric_registry_has_closed_saturating_fixed_memory_and_latency() -> None:
    metrics = OperationalMetrics()
    for name in MetricName:
        metrics.increment(name)
    metrics.observe_request_latency(-100)
    metrics.observe_request_latency(25)
    metrics.observe_request_latency(99_999_999)
    snapshot = metrics.snapshot().model_dump()
    assert metrics.counter_slots == len(MetricName) == 15
    assert all(snapshot[name.value] == 1 for name in MetricName)
    assert snapshot["request_latency"] == {
        "count": 3,
        "total_ms": 3_600_025,
        "minimum_ms": 0,
        "maximum_ms": 3_600_000,
    }
    serialized = json.dumps(snapshot)
    for forbidden in ("customer", "event_id", "approval_id", "actor_id", "url"):
        assert forbidden not in serialized


def test_request_and_authentication_metrics_increment_without_dynamic_labels() -> None:
    app = create_app(_settings())
    with TestClient(app) as client:
        failed = client.get(
            "/api/v1/admin/status",
            headers={"Authorization": "Bearer fake-invalid-phase8-token"},
        )
        succeeded = client.get(
            "/api/v1/admin/status", headers={"Authorization": f"Bearer {_TOKEN}"}
        )
    snapshot = app.state.metrics.snapshot()
    assert failed.status_code == 401
    assert succeeded.status_code == 200
    assert snapshot.requests_total == 2
    assert snapshot.requests_failed == 1
    assert snapshot.authentication_failure == 1
    assert snapshot.authentication_success == 1
    assert snapshot.request_latency.count == 2
    assert app.state.metrics.counter_slots == 15


def test_policy_metrics_cover_all_closed_decisions() -> None:
    provider = PolicyFakeProvider(provider_output(recommended_next_step="NO_ACTION"))
    intelligence = BusinessIntelligenceService(provider, 8_192, 800)
    policy = PolicyDecisionService(DeterministicPolicyEngine())
    app = create_app(_settings())
    app.dependency_overrides[get_intelligence_service] = lambda: intelligence
    app.dependency_overrides[get_policy_service] = lambda: policy
    with _client(app) as client:
        assert client.post("/api/v1/events/decide", json=api_event()).status_code == 200
        provider.output = provider_output(confidence=0.5)
        assert client.post("/api/v1/events/decide", json=api_event()).status_code == 200
        provider.output = provider_output(priority="HIGH", recommended_next_step="NO_ACTION")
        assert client.post("/api/v1/events/decide", json=api_event()).status_code == 200
    snapshot = app.state.metrics.snapshot()
    assert snapshot.policy_decisions_allow == 1
    assert snapshot.policy_decisions_approval == 1
    assert snapshot.policy_decisions_deny == 1


def test_approval_metrics_cover_lifecycle() -> None:
    database = Path("approval-metrics.sqlite3")
    clock = MutableClock()
    repository = SQLiteApprovalRepository(database)
    repository.initialize()
    approvals = ApprovalService(
        repository,
        PolicyDecisionService(DeterministicPolicyEngine(), clock=clock),
        1_800,
        "unused-server-actor",
        clock,
    )
    provider = ApprovalFakeProvider()
    intelligence = BusinessIntelligenceService(provider, 8_192, 800)
    app = create_app(_settings())
    app.dependency_overrides[get_approval_service] = lambda: approvals
    app.dependency_overrides[get_intelligence_service] = lambda: intelligence
    with _client(app) as client:
        approved_id = client.post("/api/v1/approvals", json=external_api_event()).json()[
            "approval_id"
        ]
        assert client.post(f"/api/v1/approvals/{approved_id}/approve").status_code == 200
        rejected_id = client.post("/api/v1/approvals", json=external_api_event()).json()[
            "approval_id"
        ]
        assert (
            client.post(
                f"/api/v1/approvals/{rejected_id}/reject",
                json={"reason": "A bounded reviewer rejection."},
            ).status_code
            == 200
        )
        expired_id = client.post("/api/v1/approvals", json=external_api_event()).json()[
            "approval_id"
        ]
        clock.advance(1_801)
        assert client.get(f"/api/v1/approvals/{expired_id}").json()["status"] == "EXPIRED"
    snapshot = app.state.metrics.snapshot()
    assert snapshot.approvals_created == 3
    assert snapshot.approvals_approved == 1
    assert snapshot.approvals_rejected == 1
    assert snapshot.approvals_expired == 1
    assert snapshot.policy_decisions_approval == 3


def test_execution_metrics_cover_success_and_unknown_without_retry() -> None:
    successful_provider = RecordingProvider()
    _approvals, successful, _repository, successful_id = approved_boundary(
        Path("successful.sqlite3"), successful_provider
    )
    unknown_provider = RecordingProvider(
        GHLProviderError(GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN)
    )
    _approvals, unknown, _repository, unknown_id = approved_boundary(
        Path("unknown.sqlite3"), unknown_provider
    )
    current_service = [successful]
    app = create_app(_settings())
    app.dependency_overrides[get_execution_service] = lambda: current_service[0]
    with _client(app) as client:
        succeeded = client.post(
            "/api/v1/actions/contact-tag",
            json=action_request(successful_id).model_dump(mode="json"),
        )
        current_service[0] = unknown
        indeterminate = client.post(
            "/api/v1/actions/contact-tag",
            json=action_request(unknown_id).model_dump(mode="json"),
        )
    snapshot = app.state.metrics.snapshot()
    assert succeeded.json()["status"] == "SUCCEEDED"
    assert indeterminate.json()["status"] == "UNKNOWN"
    assert snapshot.executions_started == 2
    assert snapshot.executions_succeeded == 1
    assert snapshot.executions_unknown == 1
    assert snapshot.executions_failed == 0
    assert len(successful_provider.calls) == len(unknown_provider.calls) == 1


def test_failure_categories_are_closed_and_safe() -> None:
    assert {category.value for category in FailureCategory} == {
        "VALIDATION_ERROR",
        "AUTHENTICATION_FAILURE",
        "AUTHORIZATION_FAILURE",
        "POLICY_FAILURE",
        "APPROVAL_FAILURE",
        "EXECUTION_FAILURE",
        "GHL_AUTHENTICATION",
        "GHL_RATE_LIMIT",
        "GHL_BAD_REQUEST",
        "GHL_UNAVAILABLE",
        "GHL_TIMEOUT",
        "PERSISTENCE_FAILURE",
        "AI_FAILURE",
        "INTERNAL_FAILURE",
    }
    assert list(ReadinessStatus) == [ReadinessStatus.READY, ReadinessStatus.NOT_READY]
