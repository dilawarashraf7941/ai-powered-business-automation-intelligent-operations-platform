"""Strict settings loaded only from server-owned environment variables."""

import hmac
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ai_business_automation.models.auth import AuthRole

PRODUCTION_OPENAI_MODELS = frozenset({"gpt-5-mini"})
_PRODUCTION_AUTH_TOKEN_MIN_LENGTH = 32
_PROVIDER_SECRET_MIN_LENGTH = 24
_PLACEHOLDER_FRAGMENTS = (
    "change-me",
    "example",
    "placeholder",
    "test-token",
    "your-token",
)


class Environment(StrEnum):
    """Supported deployment modes."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings with bounded, safe defaults."""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        case_sensitive=False,
        extra="forbid",
    )

    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    max_request_body_bytes: int = Field(default=16_384, ge=1_024, le=1_048_576)
    openai_api_key: SecretStr | None = None
    openai_model: str = Field(default="gpt-5-mini", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    ai_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    ai_max_input_bytes: int = Field(default=8_192, ge=1_024, le=16_384)
    ai_max_output_tokens: int = Field(default=800, ge=128, le=2_048)
    policy_confidence_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    approval_database_path: str = Field(
        default="approvals.sqlite3",
        min_length=9,
        max_length=240,
        pattern=r"^[A-Za-z0-9.][A-Za-z0-9_.\\/-]*\.sqlite3$",
    )
    approval_ttl_seconds: int = Field(default=1_800, ge=60, le=86_400)
    approver_id: str = Field(
        default="development-approver",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    auth_token_1: SecretStr | None = None
    auth_actor_1: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    auth_role_1: AuthRole | None = None
    auth_token_2: SecretStr | None = None
    auth_actor_2: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    auth_role_2: AuthRole | None = None
    auth_token_3: SecretStr | None = None
    auth_actor_3: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    auth_role_3: AuthRole | None = None
    auth_failure_limit: int = Field(default=20, ge=1, le=1_000)
    protected_mutation_limit: int = Field(default=60, ge=1, le=10_000)
    ghl_api_key: SecretStr | None = None
    ghl_api_version: Literal["v3"] = "v3"
    ghl_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)

    @model_validator(mode="after")
    def validate_configuration(self) -> "Settings":
        database_parts = self.approval_database_path.replace("\\", "/").split("/")
        if ".." in database_parts:
            raise ValueError("approval database path cannot traverse parent directories")
        if database_parts[0].startswith(".") and not (
            self.environment is Environment.TEST and database_parts[0] == ".test-data"
        ):
            raise ValueError("hidden approval database paths are restricted to test data")
        slots = (
            (self.auth_token_1, self.auth_actor_1, self.auth_role_1),
            (self.auth_token_2, self.auth_actor_2, self.auth_role_2),
            (self.auth_token_3, self.auth_actor_3, self.auth_role_3),
        )
        configured_tokens: list[str] = []
        for token, actor, role in slots:
            if any(value is not None for value in (token, actor, role)) and not all(
                value is not None for value in (token, actor, role)
            ):
                raise ValueError("authentication credential slots must be complete")
            if token is not None:
                secret = token.get_secret_value()
                if not 16 <= len(secret) <= 256 or any(character.isspace() for character in secret):
                    raise ValueError("authentication token does not meet bounded requirements")
                configured_tokens.append(secret)
        for index, candidate in enumerate(configured_tokens):
            if any(
                hmac.compare_digest(candidate, other) for other in configured_tokens[index + 1 :]
            ):
                raise ValueError("authentication tokens must be unique")
        if self.environment is Environment.PRODUCTION:
            self._validate_production(configured_tokens)
        return self

    def _validate_production(self, configured_tokens: list[str]) -> None:
        if self.debug or self.log_level == "DEBUG":
            raise ValueError("production debug configuration is prohibited")
        if not configured_tokens:
            raise ValueError("production requires authentication credentials")
        if any(
            len(token) < _PRODUCTION_AUTH_TOKEN_MIN_LENGTH or _is_placeholder_secret(token)
            for token in configured_tokens
        ):
            raise ValueError("production authentication credentials are not acceptable")
        if self.ghl_api_key is None:
            raise ValueError("production requires GHL credentials")
        if _is_weak_provider_secret(self.ghl_api_key):
            raise ValueError("production GHL credentials are not acceptable")
        if self.openai_api_key is None:
            raise ValueError("production requires AI provider credentials")
        if _is_weak_provider_secret(self.openai_api_key):
            raise ValueError("production AI credentials are not acceptable")
        if self.openai_model not in PRODUCTION_OPENAI_MODELS:
            raise ValueError("production AI model is not allowlisted")
        if not 0.5 <= self.policy_confidence_threshold <= 0.99:
            raise ValueError("production policy configuration is outside the safe range")
        if "approval_database_path" not in self.model_fields_set:
            raise ValueError("production requires explicit SQLite configuration")
        database_path = Path(self.approval_database_path)
        if database_path.is_absolute():
            raise ValueError("production SQLite path must be relative to the application root")
        if not database_path.parent.exists() or not database_path.parent.is_dir():
            raise ValueError("production SQLite parent directory is unavailable")
        if database_path.exists() and not database_path.is_file():
            raise ValueError("production SQLite path is not a regular file")
        if self.approver_id == "development-approver":
            raise ValueError("production development fallback identities are prohibited")


def _is_placeholder_secret(value: str) -> bool:
    normalized = value.strip().lower().replace("_", "-")
    return normalized.startswith("secret") or any(
        fragment in normalized for fragment in _PLACEHOLDER_FRAGMENTS
    )


def _is_weak_provider_secret(value: SecretStr) -> bool:
    secret = value.get_secret_value()
    return (
        len(secret) < _PROVIDER_SECRET_MIN_LENGTH
        or any(character.isspace() for character in secret)
        or _is_placeholder_secret(secret)
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process settings without exposing their values through an API."""

    return Settings()
