"""Production configuration, deployment, and release-boundary tests."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from scripts.verify_release import (
    GHL_ORIGIN,
    dockerfile_findings,
    repository_findings,
    secret_findings,
    source_findings,
)

from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from ai_business_automation.models import AuthRole, ExecutionAction
from ai_business_automation.repositories.security_audit import SecurityAuditRepository
from tests.auth_helpers import FAKE_ADMIN_TOKEN

ROOT = Path(__file__).resolve().parents[1]
VALID_AUTH = "release-auth-material-" + "A7" * 8
VALID_GHL = "release-ghl-material-" + "B8" * 8
VALID_AI = "release-ai-material-" + "C9" * 8


def production_settings(**updates: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "approval_database_path": "data/production.sqlite3",
        "approver_id": "production-approver",
        "auth_token_1": SecretStr(VALID_AUTH),
        "auth_actor_1": "production-admin",
        "auth_role_1": AuthRole.ADMIN,
        "ghl_api_key": SecretStr(VALID_GHL),
        "openai_api_key": SecretStr(VALID_AI),
    }
    values.update(updates)
    return Settings(**values)


@pytest.fixture
def production_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"auth_token_1": None, "auth_actor_1": None, "auth_role_1": None}, "authentication"),
        ({"auth_token_1": SecretStr("short-production-token")}, "authentication"),
        ({"auth_token_1": SecretStr("change-me-" + "A" * 40)}, "authentication"),
        ({"debug": True}, "debug"),
        ({"log_level": "DEBUG"}, "debug"),
        ({"ghl_api_key": None}, "GHL"),
        ({"ghl_api_key": SecretStr("placeholder-" + "B" * 30)}, "GHL"),
        ({"openai_api_key": None}, "AI provider"),
        ({"openai_api_key": SecretStr("your-token-" + "C" * 30)}, "AI"),
        ({"openai_model": "gpt-example"}, "model"),
        ({"policy_confidence_threshold": 0.25}, "policy"),
        ({"approver_id": "development-approver"}, "fallback"),
    ],
)
def test_production_rejects_unsafe_configuration(
    production_directory: Path, updates: dict[str, Any], message: str
) -> None:
    del production_directory
    with pytest.raises(ValidationError, match=message):
        production_settings(**updates)


def test_production_requires_explicit_sqlite_configuration(
    production_directory: Path,
) -> None:
    del production_directory
    with pytest.raises(ValidationError, match="explicit SQLite"):
        Settings.model_validate(
            {
                key: value
                for key, value in production_settings().model_dump().items()
                if key != "approval_database_path"
            }
        )


@pytest.mark.parametrize(
    "path",
    ["data/../production.sqlite3", ".hidden/production.sqlite3"],
)
def test_production_rejects_untrusted_sqlite_paths(production_directory: Path, path: str) -> None:
    del production_directory
    with pytest.raises(ValidationError):
        production_settings(approval_database_path=path)


def test_production_requires_existing_sqlite_parent(production_directory: Path) -> None:
    del production_directory
    with pytest.raises(ValidationError, match="parent directory"):
        production_settings(approval_database_path="missing/production.sqlite3")


def test_production_rejects_directory_as_database(production_directory: Path) -> None:
    (production_directory / "data" / "production.sqlite3").mkdir()
    with pytest.raises(ValidationError, match="regular file"):
        production_settings()


def test_production_rejects_client_configurable_provider_origin(
    production_directory: Path,
) -> None:
    del production_directory
    with pytest.raises(ValidationError):
        production_settings(ghl_origin="https://attacker.invalid")


def test_valid_production_configuration_is_secret_safe(production_directory: Path) -> None:
    del production_directory
    settings = production_settings()
    assert settings.environment is Environment.PRODUCTION
    assert "release-auth-material" not in repr(settings)
    assert settings.openai_model == "gpt-5-mini"
    assert settings.ghl_api_version == "v3"


def test_startup_fails_safely_when_local_persistence_is_unavailable(
    production_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del production_directory
    monkeypatch.setattr(SecurityAuditRepository, "is_ready", lambda self: False)
    with (
        pytest.raises(RuntimeError, match="local persistence is unavailable"),
        TestClient(create_app(production_settings())),
    ):
        pass


def test_startup_makes_no_provider_calls(
    production_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del production_directory

    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("provider construction or request during startup")

    monkeypatch.setattr("ai_business_automation.providers.ghl.GHLClient.__init__", forbidden)
    monkeypatch.setattr(
        "ai_business_automation.providers.openai.OpenAIAnalysisProvider.__init__", forbidden
    )
    with TestClient(create_app(production_settings())) as client:
        assert client.get("/health").json() == {"status": "ok"}


def test_shutdown_releases_persistence_state(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[SecurityAuditRepository] = []
    original = SecurityAuditRepository.close

    def observed(repository: SecurityAuditRepository) -> None:
        closed.append(repository)
        original(repository)

    monkeypatch.setattr(SecurityAuditRepository, "close", observed)
    settings = Settings(
        environment=Environment.TEST,
        auth_token_1=SecretStr(FAKE_ADMIN_TOKEN),
        auth_actor_1="test-admin",
        auth_role_1=AuthRole.ADMIN,
    )
    with TestClient(create_app(settings)):
        pass
    assert len(closed) == 1


def test_dockerfile_is_statically_hardened() -> None:
    content = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile_findings(content) == []
    assert "FROM python:3.12.10-slim-bookworm" in content
    assert "USER 10001:10001" in content
    assert "HEALTHCHECK" in content and "/health" in content
    assert 'CMD ["uvicorn"' in content
    assert "COPY . " not in content


def test_release_verifier_accepts_the_project_without_mutation() -> None:
    before = {path: path.stat().st_mtime_ns for path in ROOT.rglob("*") if path.is_file()}
    assert repository_findings(ROOT) == []
    after = {path: path.stat().st_mtime_ns for path in ROOT.rglob("*") if path.is_file()}
    assert before == after


def test_release_verifier_rejects_unsafe_docker_configuration() -> None:
    assert dockerfile_findings("FROM python:latest\nUSER root\nCMD uvicorn app:app")


def test_release_verifier_detects_forbidden_provider_origin(tmp_path: Path) -> None:
    provider = tmp_path / "ai_business_automation" / "providers"
    provider.mkdir(parents=True)
    (provider / "ghl.py").write_text(
        'GHL_API_ORIGIN = "https://attacker.invalid"\n', encoding="utf-8"
    )
    findings = source_findings(tmp_path)
    assert "GHL provider origin is not exactly fixed" in findings


def test_release_verifier_detects_obvious_secret(tmp_path: Path) -> None:
    (tmp_path / "unsafe.md").write_text(
        "api_" + 'key = "' + "sk_" + 'live_AAAAAAAAAAAAAAAAAAAAAAAA"',
        encoding="utf-8",
    )
    assert secret_findings(tmp_path) == ["obvious secret material present: unsafe.md"]


def test_security_headers_and_cors_remain_closed() -> None:
    settings = Settings(
        environment=Environment.TEST,
        auth_token_1=SecretStr(FAKE_ADMIN_TOKEN),
        auth_actor_1="test-admin",
        auth_role_1=AuthRole.ADMIN,
    )
    with TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {FAKE_ADMIN_TOKEN}"}
    ) as client:
        response = client.get("/api/v1/admin/status", headers={"Origin": "https://invalid.test"})
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert "Access-Control-Allow-Origin" not in response.headers


def test_provider_and_action_boundaries_remain_fixed() -> None:
    ghl_source = (ROOT / "src/ai_business_automation/providers/ghl.py").read_text(encoding="utf-8")
    ai_source = (ROOT / "src/ai_business_automation/providers/openai.py").read_text(
        encoding="utf-8"
    )
    assert GHL_ORIGIN in ghl_source
    assert "/contacts/{trusted.contact_id}/tags" in ghl_source
    assert "client.post(" in ghl_source
    assert 'GHL_API_VERSION = "v3"' in ghl_source
    assert set(ExecutionAction) == {ExecutionAction.ADD_CONTACT_TAG}
    assert "store=False" in ai_source
    assert "tools=" not in ai_source


def test_production_logging_cannot_enable_debug(
    production_directory: Path, caplog: pytest.LogCaptureFixture
) -> None:
    del production_directory
    with pytest.raises(ValidationError):
        production_settings(log_level="DEBUG")
    for record in caplog.records:
        assert VALID_AUTH not in record.getMessage()
        assert VALID_GHL not in record.getMessage()
        assert VALID_AI not in record.getMessage()
