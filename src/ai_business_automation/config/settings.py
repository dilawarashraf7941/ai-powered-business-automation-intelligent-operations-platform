"""Strict settings loaded only from server-owned environment variables."""

from enum import StrEnum
from functools import lru_cache

from pydantic import Field
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


@lru_cache
def get_settings() -> Settings:
    """Return the process settings without exposing their values through an API."""

    return Settings()
