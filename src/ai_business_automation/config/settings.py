"""Strict settings loaded only from server-owned environment variables."""

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.\\/-]*\.sqlite3$",
    )
    approval_ttl_seconds: int = Field(default=1_800, ge=60, le=86_400)
    approver_id: str = Field(
        default="development-approver",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    ghl_api_key: SecretStr | None = None
    ghl_api_version: Literal["v3"] = "v3"
    ghl_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)

    @model_validator(mode="after")
    def require_production_ai_credentials(self) -> "Settings":
        if self.environment is Environment.PRODUCTION and self.openai_api_key is None:
            raise ValueError("production requires AI provider credentials")
        if ".." in self.approval_database_path.replace("\\", "/").split("/"):
            raise ValueError("approval database path cannot traverse parent directories")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process settings without exposing their values through an API."""

    return Settings()
