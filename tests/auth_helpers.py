"""Explicit fake authenticated clients for regression tests."""

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_business_automation.config import Environment, Settings
from ai_business_automation.models import AuthRole

FAKE_ADMIN_TOKEN = "fake-test-admin-token"


def auth_settings(**updates: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": Environment.TEST,
        "auth_token_1": SecretStr(FAKE_ADMIN_TOKEN),
        "auth_actor_1": "test-admin",
        "auth_role_1": AuthRole.ADMIN,
    }
    values.update(updates)
    return Settings(**values)


def authenticated_client(app: FastAPI, **kwargs: Any) -> TestClient:
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {FAKE_ADMIN_TOKEN}"
    return TestClient(app, headers=headers, **kwargs)
