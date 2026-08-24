"""Shared API test fixtures."""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app
from tests.auth_helpers import authenticated_client


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(
        environment=Environment.TEST,
        log_level="INFO",
        auth_token_1=SecretStr("fake-test-admin-token"),
        auth_actor_1="test-admin",
        auth_role_1="ADMIN",
    )
    with authenticated_client(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def valid_event() -> dict[str, object]:
    return {
        "event_type": "CUSTOMER_REQUEST",
        "source": "WEB_FORM",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {"request_type": "demo"},
    }
