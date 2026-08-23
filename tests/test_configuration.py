"""Tests for strict server-owned configuration."""

import pytest
from pydantic import ValidationError

from ai_business_automation.config import Environment, Settings, get_settings


@pytest.mark.parametrize("environment", list(Environment))
def test_supported_environments(environment: Environment) -> None:
    assert Settings(environment=environment).environment is environment


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
    settings = Settings()
    assert settings.environment is Environment.PRODUCTION
    assert settings.log_level == "WARNING"


def test_settings_cache_returns_same_instance() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
