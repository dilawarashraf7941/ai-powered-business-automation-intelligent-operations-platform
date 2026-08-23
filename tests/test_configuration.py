"""Tests for strict server-owned configuration."""

import pytest
from pydantic import SecretStr, ValidationError

from ai_business_automation.config import Environment, Settings, get_settings


@pytest.mark.parametrize("environment", list(Environment))
def test_supported_environments(environment: Environment) -> None:
    values: dict[str, object] = {"environment": environment}
    if environment is Environment.PRODUCTION:
        values["openai_api_key"] = SecretStr("unit-test-placeholder")
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
    monkeypatch.setenv("APP_OPENAI_API_KEY", "unit-test-placeholder")
    settings = Settings()
    assert settings.environment is Environment.PRODUCTION
    assert settings.log_level == "WARNING"
    assert "unit-test-placeholder" not in repr(settings)


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
