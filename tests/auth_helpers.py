"""Explicit fake authenticated clients for pre-Phase-9 regression tests."""

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_business_automation.config import Environment, Settings
from ai_business_automation.security.auth import BearerAuthenticator

FAKE_ADMIN_TOKEN = "fake-test-admin-token"


class _NullAudit:
    def append(self, *_args: Any, **_kwargs: Any) -> None:
        pass


def authenticated_client(app: FastAPI, **kwargs: Any) -> TestClient:
    settings = Settings(
        environment=Environment.TEST,
        auth_token_1=SecretStr(FAKE_ADMIN_TOKEN),
        auth_actor_1="test-admin",
        auth_role_1="ADMIN",
    )
    app.state.authenticator = BearerAuthenticator(settings)
    app.state.security_audit = _NullAudit()
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {FAKE_ADMIN_TOKEN}"
    return TestClient(app, headers=headers, **kwargs)
