"""Shared API test fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from ai_business_automation.config import Environment, Settings
from ai_business_automation.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(environment=Environment.TEST, log_level="INFO")
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def valid_event() -> dict[str, object]:
    return {
        "event_type": "customer_request",
        "source": "web_form",
        "payload": {"request_type": "demo"},
    }
