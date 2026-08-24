"""Phase 9 server-side bearer authentication and closed-role authorization tests."""

import hmac
import json
import logging
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings
from ai_business_automation.logging import JsonFormatter
from ai_business_automation.main import create_app
from ai_business_automation.models import AuthRole
from ai_business_automation.repositories.security_audit import SecurityAuditRepository
from ai_business_automation.security.auth import (
    AuthenticationError,
    BearerAuthenticator,
    ProcessRateLimiter,
    RateLimitError,
)

_TOKENS = {
    AuthRole.READ_ONLY: "fake-read-only-test-token",
    AuthRole.APPROVER: "fake-approver-test-token",
    AuthRole.EXECUTOR: "fake-executor-test-token",
    AuthRole.ADMIN: "fake-admin-role-test-token",
}


def _settings(role: AuthRole, **updates: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": Environment.TEST,
        "approval_database_path": "phase9.sqlite3",
        "auth_token_1": SecretStr(_TOKENS[role]),
        "auth_actor_1": f"{role.value.lower()}-actor",
        "auth_role_1": role,
    }
    values.update(updates)
    return Settings(**values)


def _client(role: AuthRole, **settings_updates: Any) -> TestClient:
    return TestClient(
        create_app(_settings(role, **settings_updates)),
        headers={"Authorization": f"Bearer {_TOKENS[role]}"},
    )


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    root = Path(".test-data")
    root.mkdir(exist_ok=True)
    path = (root / f"phase9-{secrets.token_hex(12)}").resolve()
    path.mkdir()
    monkeypatch.chdir(path)
    try:
        yield
    finally:
        monkeypatch.chdir(Path(__file__).resolve().parents[1])
        shutil.rmtree(path, ignore_errors=True)


@pytest.mark.parametrize(
    "path,body", [("/health", {"status": "ok"}), ("/ready", {"status": "ready"})]
)
def test_health_and_readiness_are_public(path: str, body: dict[str, str]) -> None:
    with TestClient(create_app(Settings(environment=Environment.TEST))) as client:
        response = client.get(path)
    assert response.status_code == 200
    assert response.json() == body


@pytest.mark.parametrize("role", list(AuthRole))
def test_each_closed_role_authenticates(role: AuthRole) -> None:
    actor = BearerAuthenticator(_settings(role)).authenticate([f"Bearer {_TOKENS[role]}"])
    assert actor.actor_id == f"{role.value.lower()}-actor"
    assert actor.role is role


@pytest.mark.parametrize(
    ("headers", "code"),
    [
        ([], "AUTHENTICATION_REQUIRED"),
        (["Basic fake-value"], "AUTHENTICATION_FAILED"),
        (["Bearer "], "AUTHENTICATION_FAILED"),
        (["Bearer fake-invalid-test-token"], "AUTHENTICATION_FAILED"),
        ([f"Bearer {'x' * 257}"], "AUTHENTICATION_FAILED"),
        (["Bearer one two"], "AUTHENTICATION_FAILED"),
    ],
)
def test_strict_bearer_parsing(headers: list[str], code: str) -> None:
    with pytest.raises(AuthenticationError) as raised:
        BearerAuthenticator(_settings(AuthRole.ADMIN)).authenticate(headers)
    assert raised.value.code == code
    assert _TOKENS[AuthRole.ADMIN] not in str(raised.value)


def test_duplicate_authorization_headers_are_rejected() -> None:
    authenticator = BearerAuthenticator(_settings(AuthRole.ADMIN))
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(
            [f"Bearer {_TOKENS[AuthRole.ADMIN]}", f"Bearer {_TOKENS[AuthRole.ADMIN]}"]
        )


def test_all_slots_use_constant_time_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        environment=Environment.TEST,
        auth_token_1=SecretStr("fake-slot-one-token"),
        auth_actor_1="one",
        auth_role_1=AuthRole.READ_ONLY,
        auth_token_2=SecretStr("fake-slot-two-token"),
        auth_actor_2="two",
        auth_role_2=AuthRole.APPROVER,
        auth_token_3=SecretStr("fake-slot-three-token"),
        auth_actor_3="three",
        auth_role_3=AuthRole.ADMIN,
    )
    authenticator = BearerAuthenticator(settings)
    calls: list[tuple[str, str]] = []
    original = hmac.compare_digest

    def observed(left: str, right: str) -> bool:
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", observed)
    actor = authenticator.authenticate(["Bearer fake-slot-one-token"])
    assert actor.actor_id == "one"
    assert len(calls) == 3
    assert {right for _, right in calls} == {
        "fake-slot-one-token",
        "fake-slot-two-token",
        "fake-slot-three-token",
    }


@pytest.mark.parametrize("role", [AuthRole.READ_ONLY, AuthRole.APPROVER, AuthRole.EXECUTOR])
def test_only_admin_can_access_admin_status(role: AuthRole) -> None:
    with _client(role) as client:
        response = client.get("/api/v1/admin/status")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_admin_status_is_safe_and_not_cached() -> None:
    with _client(AuthRole.ADMIN) as client:
        response = client.get("/api/v1/admin/status")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "authentication": "enabled",
        "authorization": "enabled",
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["X-Request-ID"]


def test_missing_authentication_is_401_with_challenge() -> None:
    app = create_app(_settings(AuthRole.READ_ONLY))
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/status")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_duplicate_headers_fail_at_the_http_boundary() -> None:
    app = create_app(_settings(AuthRole.ADMIN))
    token = _TOKENS[AuthRole.ADMIN]
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/admin/status",
            headers=[("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        )
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        (AuthRole.READ_ONLY, "/api/v1/approvals", 403),
        (AuthRole.EXECUTOR, "/api/v1/approvals", 403),
        (AuthRole.APPROVER, "/api/v1/approvals", 422),
        (AuthRole.ADMIN, "/api/v1/approvals", 422),
        (AuthRole.READ_ONLY, "/api/v1/actions/execute", 403),
        (AuthRole.APPROVER, "/api/v1/actions/execute", 403),
        (AuthRole.EXECUTOR, "/api/v1/actions/execute", 422),
        (AuthRole.ADMIN, "/api/v1/actions/execute", 422),
    ],
)
def test_mutation_authorization_matrix(role: AuthRole, path: str, expected: int) -> None:
    with _client(role) as client:
        response = client.post(path, json={})
    assert response.status_code == expected


@pytest.mark.parametrize("role", list(AuthRole))
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/approvals/apr_short",
        "/api/v1/actions/executions/exe_short",
    ],
)
def test_every_role_inherits_protected_reads(role: AuthRole, path: str) -> None:
    with _client(role) as client:
        response = client.get(path)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (AuthRole.READ_ONLY, 403),
        (AuthRole.EXECUTOR, 403),
        (AuthRole.APPROVER, 422),
        (AuthRole.ADMIN, 422),
    ],
)
@pytest.mark.parametrize("transition", ["approve", "reject"])
def test_approval_transition_matrix(role: AuthRole, expected: int, transition: str) -> None:
    with _client(role) as client:
        response = client.post(f"/api/v1/approvals/apr_short/{transition}", json={})
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (AuthRole.READ_ONLY, 403),
        (AuthRole.APPROVER, 403),
        (AuthRole.EXECUTOR, 422),
        (AuthRole.ADMIN, 422),
    ],
)
def test_reconciliation_authorization_matrix(role: AuthRole, expected: int) -> None:
    execution_id = "exe_short"
    with _client(role) as client:
        response = client.post(
            f"/api/v1/actions/executions/{execution_id}/reconcile",
            json={"outcome": "SUCCEEDED", "reason": "Verified externally."},
        )
    assert response.status_code == expected


def test_ai_analysis_requires_authentication_before_provider_use() -> None:
    app = create_app(_settings(AuthRole.READ_ONLY))
    with TestClient(app) as client:
        response = client.post("/api/v1/events/analyze", json={})
    assert response.status_code == 401


def test_basic_event_ingestion_remains_public() -> None:
    with TestClient(create_app(_settings(AuthRole.READ_ONLY))) as client:
        response = client.post("/api/v1/events", json={})
    assert response.status_code == 422
    assert response.json()["error"]["code"] != "AUTHENTICATION_REQUIRED"


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"params": {"access_token": _TOKENS[AuthRole.ADMIN]}},
        {"headers": {"X-Authorization": f"Bearer {_TOKENS[AuthRole.ADMIN]}"}},
    ],
)
def test_alternative_authentication_channels_do_not_bypass(
    request_kwargs: dict[str, Any],
) -> None:
    app = create_app(_settings(AuthRole.ADMIN))
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/status", **request_kwargs)
    assert response.status_code == 401


def test_body_actor_and_role_injection_are_rejected() -> None:
    with _client(AuthRole.EXECUTOR) as client:
        response = client.post(
            "/api/v1/actions/execute",
            json={
                "approval_id": "apr_abcdefghijklmnopqrstuvwx",
                "actor_id": "attacker",
                "role": "ADMIN",
            },
        )
    assert response.status_code == 422


def test_authentication_failure_rate_limit_is_process_local_and_bounded() -> None:
    app = create_app(_settings(AuthRole.ADMIN, auth_failure_limit=1))
    with TestClient(app) as client:
        assert client.get("/api/v1/admin/status").status_code == 401
        assert client.get("/api/v1/admin/status").status_code == 429


def test_mutation_rate_limit_precedes_business_operation() -> None:
    with _client(AuthRole.ADMIN, protected_mutation_limit=1) as client:
        assert client.post("/api/v1/approvals", json={}).status_code == 422
        assert client.post("/api/v1/approvals", json={}).status_code == 429


def test_mutation_rate_limit_also_bounds_denied_roles() -> None:
    with _client(AuthRole.READ_ONLY, protected_mutation_limit=1) as client:
        assert client.post("/api/v1/approvals", json={}).status_code == 403
        assert client.post("/api/v1/approvals", json={}).status_code == 429


def test_rate_limiter_uses_fixed_buckets() -> None:
    limiter = ProcessRateLimiter(1, 1)
    limiter.consume("authentication")
    with pytest.raises(RateLimitError):
        limiter.consume("authentication")


def test_security_events_use_hash_chain_and_exclude_tokens() -> None:
    with _client(AuthRole.APPROVER) as client:
        client.post(
            "/api/v1/approvals",
            json={},
            headers={"Authorization": "Bearer fake-invalid-audit-token"},
        )
        client.post("/api/v1/approvals", json={})
    repository = SecurityAuditRepository(Path("phase9.sqlite3"))
    assert repository.verify()
    database_bytes = Path("phase9.sqlite3").read_bytes()
    assert _TOKENS[AuthRole.APPROVER].encode() not in database_bytes
    with sqlite3.connect("phase9.sqlite3") as connection:
        event_types = {
            row[0] for row in connection.execute("SELECT event_type FROM security_audit_events")
        }
        actor, role = connection.execute(
            """SELECT actor_id, role FROM security_audit_events
            WHERE event_type = 'APPROVAL_AUTHORIZED'"""
        ).fetchone()
    assert "AUTHENTICATION_SUCCEEDED" in event_types
    assert "AUTHENTICATION_FAILED" in event_types
    assert "APPROVAL_AUTHORIZED" in event_types
    assert actor == "approver-actor"
    assert role == "APPROVER"
    with sqlite3.connect("phase9.sqlite3") as connection:
        connection.execute(
            """UPDATE security_audit_events SET previous_event_hash = ?
            WHERE sequence_number = 2""",
            ("f" * 64,),
        )
    assert not repository.verify()


def test_authentication_configuration_is_closed_and_complete() -> None:
    with pytest.raises(ValidationError):
        Settings(environment=Environment.TEST, auth_token_1=SecretStr("fake-incomplete-token"))
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.TEST,
            auth_token_1=SecretStr("fake-duplicate-token"),
            auth_actor_1="one",
            auth_role_1=AuthRole.READ_ONLY,
            auth_token_2=SecretStr("fake-duplicate-token"),
            auth_actor_2="two",
            auth_role_2=AuthRole.ADMIN,
        )


def test_json_redaction_removes_authorization_bearer_and_access_token() -> None:
    record = logging.LogRecord("test", 20, __file__, 1, "event", (), None)
    record.operation = "safe"
    rendered = JsonFormatter().format(record)
    assert json.loads(rendered)["operation"] == "safe"
    from ai_business_automation.logging import redact

    assert redact(
        {
            "Authorization": f"Bearer {_TOKENS[AuthRole.ADMIN]}",
            "access_token": _TOKENS[AuthRole.ADMIN],
            "Bearer": _TOKENS[AuthRole.ADMIN],
        }
    ) == {
        "Authorization": "[REDACTED]",
        "access_token": "[REDACTED]",
        "Bearer": "[REDACTED]",
    }
