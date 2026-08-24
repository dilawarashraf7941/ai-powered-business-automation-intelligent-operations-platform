"""Shared API test fixtures."""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from ai_business_automation.main import create_app
from tests.auth_helpers import auth_settings, authenticated_client


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = auth_settings(log_level="INFO")
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
