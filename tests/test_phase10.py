"""Phase 10 production validation, deployment, and release-hardening tests."""

import secrets
import shutil
import socket
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from scripts.verify_release import (
    ROOT,
    artifact_findings,
    dockerfile_findings,
    repository_findings,
    secret_findings,
)

from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.services.approval_errors import SchemaCompatibilityError
from tests.production_helpers import production_settings, production_values


@pytest.fixture
def production_database() -> Iterator[tuple[Path, str]]:
    data = Path("tests") / f".phase10-{secrets.token_hex(12)}"
    data.mkdir()
    try:
        yield data, (data / "production.sqlite3").as_posix()
    finally:
        shutil.rmtree(data, ignore_errors=True)


@pytest.fixture
def verifier_directory() -> Iterator[Path]:
    path = Path("tests") / f".phase10-verifier-{secrets.token_hex(12)}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _invalid_production(database_path: str, **updates: Any) -> ValidationError:
    values = production_values(database_path)
    values.update(updates)
    with pytest.raises(ValidationError) as raised:
        Settings(**values)
    return raised.value


def test_production_rejects_missing_authentication(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    values = production_values(database)
    for field in ("auth_token_1", "auth_actor_1", "auth_role_1"):
        values.pop(field)
    with pytest.raises(ValidationError):
        Settings(**values)


@pytest.mark.parametrize(
    "credential",
    [
        "change-me-production-auth-material-0000",
        "example-production-auth-material-00000",
        "your-token-production-auth-material-000",
        "test-token-production-auth-material-0000",
        "placeholder-production-auth-material-00",
    ],
)
def test_production_rejects_placeholder_authentication(
    production_database: tuple[Path, str], credential: str
) -> None:
    _, database = production_database
    error = _invalid_production(database, auth_token_1=SecretStr(credential))
    assert credential not in str(error)


def test_production_rejects_weak_authentication(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    _invalid_production(database, auth_token_1=SecretStr("short-local-token"))


def test_production_rejects_missing_ghl_key(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    _invalid_production(database, ghl_api_key=None)


def test_production_rejects_placeholder_ghl_key(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    value = "placeholder-ghl-material-000000000"
    error = _invalid_production(database, ghl_api_key=SecretStr(value))
    assert value not in str(error)
    _invalid_production(
        database,
        ghl_api_key=SecretStr("operations ghl material " + "D1" * 8),
    )


def test_production_rejects_invalid_ghl_version(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    _invalid_production(database, ghl_api_version="v4")


def test_production_rejects_configurable_ghl_origin(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    _invalid_production(database, ghl_api_origin="https://example.invalid")


@pytest.mark.parametrize("timeout", [0.1, 31.0])
def test_production_rejects_invalid_ghl_timeout(
    production_database: tuple[Path, str], timeout: float
) -> None:
    _, database = production_database
    _invalid_production(database, ghl_timeout_seconds=timeout)


@pytest.mark.parametrize("updates", [{"debug": True}, {"log_level": "DEBUG"}])
def test_production_rejects_debug_configuration(
    production_database: tuple[Path, str], updates: dict[str, Any]
) -> None:
    _, database = production_database
    _invalid_production(database, **updates)


def test_production_rejects_unsafe_sqlite_path(production_database: tuple[Path, str]) -> None:
    _invalid_production("../unsafe.sqlite3")


def test_production_requires_explicit_sqlite_configuration() -> None:
    values = production_values()
    values.pop("approval_database_path")
    with pytest.raises(ValidationError):
        Settings(**values)


def test_production_requires_existing_sqlite_parent() -> None:
    database = "tests/missing-phase10-parent/production.sqlite3"
    _invalid_production(database)


def test_production_rejects_directory_as_sqlite_file(
    production_database: tuple[Path, str],
) -> None:
    data, _ = production_database
    database = data / "database.sqlite3"
    database.mkdir()
    _invalid_production(database.as_posix())


def test_production_rejects_development_fallback_identities(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    _invalid_production(database, approver_id="development-approver")


def test_production_rejects_invalid_policy_configuration(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    _invalid_production(database, policy_confidence_threshold=0.0)


def test_production_rejects_invalid_security_configuration(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    _invalid_production(database, auth_failure_limit=0)
    _invalid_production(database, max_request_body_bytes=2_000_000)


@pytest.mark.parametrize("model", ["gpt-4o", "custom-model"])
def test_production_openai_model_is_allowlisted(
    production_database: tuple[Path, str], model: str
) -> None:
    _, database = production_database
    _invalid_production(database, openai_model=model)


def test_production_rejects_missing_or_placeholder_openai_key(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    _invalid_production(database, openai_api_key=None)
    _invalid_production(
        database,
        openai_api_key=SecretStr("example-openai-material-000000000"),
    )


def test_startup_and_local_probes_never_contact_external_services(
    production_database: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, database = production_database
    original_connect = socket.socket.connect

    def blocked(instance: socket.socket, address: object) -> None:
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            original_connect(instance, address)
            return
        pytest.fail("production startup or local probe attempted network access")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    app = create_app(production_settings(database))
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200


def test_production_startup_rejects_incompatible_schema(
    production_database: tuple[Path, str],
) -> None:
    _, database = production_database
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (singleton INTEGER PRIMARY KEY, schema_version INTEGER)"
        )
        connection.execute("INSERT INTO schema_metadata VALUES (1, 999)")
    with pytest.raises(SchemaCompatibilityError):
        create_app(production_settings(database))


def test_readiness_fails_safely_when_local_probe_fails() -> None:
    app = create_app(Settings(environment=Environment.TEST))
    app.state.readiness_probe = lambda: (_ for _ in ()).throw(RuntimeError)
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert "RuntimeError" not in response.text


def test_admin_remains_protected_in_production(production_database: tuple[Path, str]) -> None:
    _, database = production_database
    app = create_app(production_settings(database))
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/status")
    assert response.status_code == 401


def test_security_headers_and_cors_defaults_remain_safe() -> None:
    with TestClient(create_app(Settings(environment=Environment.TEST))) as client:
        response = client.get("/health", headers={"Origin": "https://example.invalid"})
        preflight = client.options(
            "/api/v1/events",
            headers={
                "Origin": "https://example.invalid",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert "Access-Control-Allow-Origin" not in response.headers
    assert "Access-Control-Allow-Origin" not in preflight.headers


def test_body_size_limit_remains_before_parsing() -> None:
    app = create_app(Settings(environment=Environment.TEST, max_request_body_bytes=1024))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/events",
            content=b"x" * 1025,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413


def test_database_and_environment_artifacts_are_ignored() -> None:
    ignore = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert {".env", "*.db", "*.sqlite", "*.sqlite3"}.issubset(ignore)
    assert {
        "*.db-journal",
        "*.db-shm",
        "*.db-wal",
        "*.sqlite-journal",
        "*.sqlite-shm",
        "*.sqlite-wal",
        "*.sqlite3-shm",
        "*.sqlite3-wal",
    }.issubset(ignore)


def test_dockerfile_is_hardened_and_secret_free() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile_findings(dockerfile) == []
    assert "COPY . " not in dockerfile
    assert ".env" not in dockerfile
    assert "APP_AUTH_TOKEN" not in dockerfile
    assert "APP_GHL_API_KEY" not in dockerfile
    assert "APP_OPENAI_API_KEY" not in dockerfile


def test_dockerignore_excludes_secrets_databases_caches_and_tests() -> None:
    ignored = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    assert {
        ".git",
        ".env",
        ".env.*",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
        ".coverage",
        "tests",
    }.issubset(ignored)


def test_release_verifier_passes_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("release verifier attempted network access"),
    )
    assert repository_findings(ROOT) == []


def test_release_verifier_detects_environment_file(verifier_directory: Path) -> None:
    (verifier_directory / ".env").write_text("APP_ENVIRONMENT=production", encoding="utf-8")
    assert any("environment file" in finding for finding in artifact_findings(verifier_directory))


def test_release_verifier_detects_database_artifact(verifier_directory: Path) -> None:
    (verifier_directory / "generated.sqlite3").write_bytes(b"not-a-database")
    assert any("database artifact" in finding for finding in artifact_findings(verifier_directory))


def test_release_verifier_detects_obvious_secret(verifier_directory: Path) -> None:
    (verifier_directory / "unsafe.py").write_text(
        'OPENAI_API_KEY = "' + "sk-" + "live-" + 'abcdefghijklmnopqrstuvwx"',
        encoding="utf-8",
    )
    assert any("secret material" in finding for finding in secret_findings(verifier_directory))


def test_runtime_lock_contains_only_exact_pins() -> None:
    lines = (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines()
    assert lines
    assert all(line.count("==") == 1 for line in lines)
