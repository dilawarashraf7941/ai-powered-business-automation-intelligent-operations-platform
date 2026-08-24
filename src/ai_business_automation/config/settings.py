"""Strict settings loaded only from server-owned environment variables."""

import hmac
from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ai_business_automation.models.auth import AuthRole


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
    def require_production_ai_credentials(self) -> "Settings":
        if self.environment is Environment.PRODUCTION and self.openai_api_key is None:
            raise ValueError("production requires AI provider credentials")
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
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process settings without exposing their values through an API."""

    return Settings()
