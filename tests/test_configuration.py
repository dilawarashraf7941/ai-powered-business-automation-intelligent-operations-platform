"""Tests for strict server-owned configuration."""

import pytest
from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings, get_settings
from ai_business_automation.models import AuthRole


def _production_values() -> dict[str, object]:
    return {
        "approval_database_path": "tests/configuration.sqlite3",
        "approver_id": "configuration-approver",
        "auth_token_1": SecretStr("fake-production-auth-" + "A" * 16),
        "auth_actor_1": "configuration-admin",
        "auth_role_1": AuthRole.ADMIN,
        "ghl_api_key": SecretStr("fake-production-ghl-" + "B" * 16),
        "openai_api_key": SecretStr("fake-production-ai-" + "C" * 16),
    }


@pytest.mark.parametrize("environment", list(Environment))
def test_supported_environments(environment: Environment) -> None:
    values: dict[str, object] = {"environment": environment}
    if environment is Environment.PRODUCTION:
        values.update(_production_values())
    assert Settings(**values).environment is environment  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment", "staging"),
        ("log_level", "VERBOSE"),
        ("max_request_body_bytes", 100),
        ("max_request_body_bytes", 2_000_000),
    ],
)
def test_invalid_configuration_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})  # type: ignore[arg-type]


def test_settings_load_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENVIRONMENT", "production")
    monkeypatch.setenv("APP_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("APP_APPROVAL_DATABASE_PATH", "tests/configuration.sqlite3")
    monkeypatch.setenv("APP_APPROVER_ID", "configuration-approver")
    monkeypatch.setenv("APP_AUTH_TOKEN_1", "fake-production-auth-" + "A" * 16)
    monkeypatch.setenv("APP_AUTH_ACTOR_1", "configuration-admin")
    monkeypatch.setenv("APP_AUTH_ROLE_1", "ADMIN")
    monkeypatch.setenv("APP_GHL_API_KEY", "fake-production-ghl-" + "B" * 16)
    monkeypatch.setenv("APP_OPENAI_API_KEY", "fake-production-ai-" + "C" * 16)
    settings = Settings()
    assert settings.environment is Environment.PRODUCTION
    assert settings.log_level == "WARNING"
    assert "fake-production-auth" not in repr(settings)
    assert "fake-production-ghl" not in repr(settings)
    assert "fake-production-ai" not in repr(settings)


def test_production_requires_provider_credentials() -> None:
    with pytest.raises(ValidationError):
        Settings(environment=Environment.PRODUCTION)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("openai_model", "https://provider.invalid"),
        ("ai_timeout_seconds", 0),
        ("ai_timeout_seconds", 61),
        ("ai_max_input_bytes", 100),
        ("ai_max_output_tokens", 10_000),
        ("policy_confidence_threshold", -0.01),
        ("policy_confidence_threshold", 1.01),
    ],
)
def test_invalid_ai_configuration_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})  # type: ignore[arg-type]


def test_settings_cache_returns_same_instance() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
