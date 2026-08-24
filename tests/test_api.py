"""Tests for public API behavior and security boundaries."""

import json
import logging
import re
import socket
from builtins import open as builtin_open
from collections.abc import Iterator
from io import StringIO
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_business_automation.api import routes
from ai_business_automation.config import Environment, Settings
from ai_business_automation.logging import JsonFormatter
from ai_business_automation.main import create_app


def test_health_is_minimal_and_safe(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    serialized = response.text.lower()
    assert "environment" not in serialized
    assert "path" not in serialized


def test_valid_event_is_only_acknowledged(
    client: TestClient, valid_event: dict[str, object]
) -> None:
    response = client.post("/api/v1/events", json=valid_event)
    assert response.status_code == 202
    acknowledgement = response.json()
    assert acknowledgement["accepted"] is True
    assert acknowledgement["event_type"] == "CUSTOMER_REQUEST"
    assert acknowledgement["category"] == "CUSTOMER"
    assert acknowledgement["event_id"].startswith("evt_")
    assert acknowledgement["received_at"].endswith("Z")
    assert "payload" not in response.text


@pytest.mark.parametrize(
    "update",
    [
        {"unknown": "field"},
        {"event_type": "INVALID TYPE"},
        {"event_type": "x" * 65},
        {"source": "x" * 65},
        {"source": ""},
    ],
)
def test_invalid_top_level_event_values_are_rejected(
    client: TestClient, valid_event: dict[str, object], update: dict[str, object]
) -> None:
    response = client.post("/api/v1/events", json={**valid_event, **update})
    assert response.status_code == 422
    assert response.json()["error"]["code"] in {
        "INVALID_EVENT",
        "UNSUPPORTED_EVENT_TYPE",
        "UNSUPPORTED_SOURCE",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {f"field_{index}": index for index in range(21)},
        {"one": {"two": {"three": {"four": {"five": "too deep"}}}}},
        {"items": list(range(21))},
        {"note": "x" * 501},
        {"bad key": "value"},
        {"empty": {"": "value"}},
        {"control": "bad\u0001value"},
        {"number": 10**16},
        {"number": 1e13},
    ],
)
def test_payload_structural_bounds_are_enforced(
    client: TestClient, valid_event: dict[str, object], payload: dict[str, Any]
) -> None:
    event = {**valid_event, "payload": payload}
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 422


def test_total_payload_field_limit_is_enforced(
    client: TestClient, valid_event: dict[str, object]
) -> None:
    payload = {f"group_{group}": {f"item_{item}": item for item in range(10)} for group in range(5)}
    response = client.post("/api/v1/events", json={**valid_event, "payload": payload})
    assert response.status_code == 422


def test_total_payload_node_limit_is_enforced(
    client: TestClient, valid_event: dict[str, object]
) -> None:
    payload = {f"group_{group}": list(range(20)) for group in range(5)}
    response = client.post("/api/v1/events", json={**valid_event, "payload": payload})
    assert response.status_code == 422


def test_serialized_payload_size_is_enforced(
    client: TestClient, valid_event: dict[str, object]
) -> None:
    payload = {f"field_{index}": "x" * 490 for index in range(10)}
    response = client.post("/api/v1/events", json={**valid_event, "payload": payload})
    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "harmless-looking"},
        {"instructions": "harmless-looking"},
        {"api_key": "not-a-real-key"},
        {"callback_url": "example"},
        {"note": "visit https://example.invalid"},
        {"note": "bash delete-things"},
        {"note": "rm -rf files"},
        {"note": "value && rm files"},
        {"note": "$(unsafe)"},
        {"note": "Bearer abcdefghijk"},
    ],
)
def test_capability_bearing_payload_content_is_rejected(
    client: TestClient, valid_event: dict[str, object], payload: dict[str, str]
) -> None:
    response = client.post("/api/v1/events", json={**valid_event, "payload": payload})
    assert response.status_code == 422


def test_malformed_json_returns_safe_error(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events", content=b'{"event_type":', headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["message"] == "Event validation failed."


def test_declared_oversized_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events",
        content=b"{}",
        headers={"content-length": "20000", "content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


@pytest.mark.parametrize("content_length", ["invalid", "-1"])
def test_invalid_content_length_is_rejected(client: TestClient, content_length: str) -> None:
    response = client.post(
        "/api/v1/events", content=b"{}", headers={"content-length": content_length}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_streamed_oversized_body_is_rejected() -> None:
    app = create_app(Settings(environment=Environment.TEST, max_request_body_bytes=1024))

    def chunks() -> Iterator[bytes]:
        yield b"x" * 700
        yield b"x" * 700

    with TestClient(app) as local_client:
        response = local_client.post(
            "/api/v1/events", content=chunks(), headers={"content-type": "application/json"}
        )
    assert response.status_code == 413


def test_no_external_network_call_occurs(
    client: TestClient, valid_event: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail("event handling attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    assert client.post("/api/v1/events", json=valid_event).status_code == 202


def test_event_is_not_persisted(
    client: TestClient, valid_event: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def blocked_open(*args: object, **kwargs: object) -> object:
        if args and isinstance(args[0], int):
            return builtin_open(*args, **kwargs)  # type: ignore[call-overload]
        pytest.fail("event handling attempted filesystem persistence")

    monkeypatch.setattr("builtins.open", blocked_open)
    assert client.post("/api/v1/events", json=valid_event).status_code == 202


def test_server_owned_request_id_replaces_client_value(client: TestClient) -> None:
    supplied = "client-controlled-identity"
    first = client.get("/health", headers={"X-Request-ID": supplied})
    second = client.get("/health")
    first_id = first.headers["X-Request-ID"]
    assert first_id != supplied
    assert first_id != second.headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", first_id)


def test_security_headers_and_disabled_cors(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "https://untrusted.invalid"})
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers


def test_request_log_is_structured_and_excludes_sensitive_data(
    client: TestClient, valid_event: dict[str, object]
) -> None:
    logger = logging.getLogger("ai_business_automation")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    sensitive = "do-not-log-this-value"
    try:
        response = client.post(
            "/api/v1/events",
            json={**valid_event, "payload": {"password": sensitive}},
            headers={"Authorization": f"Bearer {sensitive}", "Cookie": f"session={sensitive}"},
        )
    finally:
        logger.removeHandler(handler)
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert response.status_code == 422
    assert records[-1]["event"] == "request_completed"
    assert records[-1]["operation"] == "create_event"
    assert records[-1]["outcome"] == "failure"
    assert records[-1]["status_class"] == "4xx"
    assert records[-1]["request_id"] == response.headers["X-Request-ID"]
    assert sensitive not in stream.getvalue()
    assert "password" not in stream.getvalue()


def test_not_found_error_is_safe_and_bounded(client: TestClient) -> None:
    response = client.get("/private/path?secret=do-not-reflect")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert "private" not in response.text
    assert "secret" not in response.text
    assert len(response.content) < 300


def test_unexpected_exception_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken_health() -> routes.HealthResponse:
        raise RuntimeError("C:\\sensitive\\path secret-internal-detail")

    monkeypatch.setattr(routes, "health", broken_health)
    app = FastAPI(debug=False)

    @app.get("/broken")
    async def broken() -> None:
        await broken_health()

    secured = create_app(Settings(environment=Environment.TEST))
    secured.router.routes.extend(app.router.routes)
    with TestClient(secured, raise_server_exceptions=False) as local_client:
        response = local_client.get("/broken")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert response.headers["X-Request-ID"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "sensitive" not in response.text
    assert "traceback" not in response.text.lower()


def test_other_http_error_is_sanitized() -> None:
    app = create_app(Settings(environment=Environment.TEST))

    @app.get("/forbidden")
    async def forbidden() -> None:
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="internal policy detail")

    with TestClient(app) as local_client:
        response = local_client.get("/forbidden")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "HTTP_ERROR"
    assert "internal policy" not in response.text


def test_application_starts(client: TestClient) -> None:
    assert client.app is not None
