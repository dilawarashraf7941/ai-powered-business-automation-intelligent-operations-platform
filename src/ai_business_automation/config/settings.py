"""Strict settings loaded only from server-owned environment variables."""

from enum import StrEnum
from functools import lru_cache

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

    @model_validator(mode="after")
    def require_production_ai_credentials(self) -> "Settings":
        if self.environment is Environment.PRODUCTION and self.openai_api_key is None:
            raise ValueError("production requires AI provider credentials")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process settings without exposing their values through an API."""

    return Settings()
