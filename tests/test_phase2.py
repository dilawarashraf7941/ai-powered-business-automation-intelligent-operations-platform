"""Phase 2 normalization, classification, canonicalization, and logging tests."""

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta, timezone
from io import StringIO

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.requests import Request

from ai_business_automation.logging import JsonFormatter
from ai_business_automation.main import (
    _http_error_adapter,
    _normalization_error_adapter,
    _validation_error_adapter,
)
from ai_business_automation.models import EventCategory, EventSource, EventType, ExternalEvent
from ai_business_automation.services.canonicalization import canonical_event_bytes
from ai_business_automation.services.classification import EventClassifier
from ai_business_automation.services.events import EventIngestionService
from ai_business_automation.services.normalization import (
    EventNormalizationError,
    EventNormalizer,
    InvalidTimestampError,
)

FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def external_event(**updates: object) -> ExternalEvent:
    values: dict[str, object] = {
        "event_type": EventType.CUSTOMER_REQUEST,
        "source": EventSource.API,
        "occurred_at": FIXED_NOW - timedelta(minutes=1),
        "payload": {"request_type": "demo", "count": 2},
    }
    values.update(updates)
    return ExternalEvent(**values)  # type: ignore[arg-type]


def api_event(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "event_type": "CUSTOMER_REQUEST",
        "source": "API",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {"request_type": "demo"},
    }
    values.update(updates)
    return values


@pytest.mark.parametrize("event_type", list(EventType))
def test_all_supported_event_types_are_accepted(client: TestClient, event_type: EventType) -> None:
    updates: dict[str, object] = {"event_type": event_type.value}
    if event_type is EventType.GHL_CONTACT_TAG_REQUEST:
        updates.update(source="INTERNAL", payload={"contact_id": "contact_123", "tags": ["vip"]})
    response = client.post("/api/v1/events", json=api_event(**updates))
    assert response.status_code == 202
    assert response.json()["event_type"] == event_type.value


@pytest.mark.parametrize("source", list(EventSource))
def test_all_supported_sources_are_accepted(client: TestClient, source: EventSource) -> None:
    response = client.post("/api/v1/events", json=api_event(source=source.value))
    assert response.status_code == 202


def test_unsupported_taxonomy_values_have_stable_errors(client: TestClient) -> None:
    event_type = client.post("/api/v1/events", json=api_event(event_type="CLIENT_DEFINED"))
    source = client.post("/api/v1/events", json=api_event(source="UNTRUSTED"))
    assert event_type.json()["error"]["code"] == "UNSUPPORTED_EVENT_TYPE"
    assert source.json()["error"]["code"] == "UNSUPPORTED_SOURCE"


@pytest.mark.parametrize("field", ["event_id", "received_at", "metadata", "category"])
def test_client_cannot_supply_internal_fields(client: TestClient, field: str) -> None:
    response = client.post("/api/v1/events", json=api_event(**{field: "client-controlled"}))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EVENT"


def test_external_reference_is_bounded_and_not_authoritative(client: TestClient) -> None:
    supplied = "partner:order-123"
    response = client.post("/api/v1/events", json=api_event(external_event_reference=supplied))
    assert response.status_code == 202
    assert response.json()["event_id"] != supplied
    invalid = client.post(
        "/api/v1/events", json=api_event(external_event_reference="unsafe reference!")
    )
    assert invalid.status_code == 422
    credential_like = client.post(
        "/api/v1/events", json=api_event(external_event_reference="sk-abcdefghijkl")
    )
    assert credential_like.status_code == 422


def test_server_event_ids_are_unique(client: TestClient) -> None:
    first = client.post("/api/v1/events", json=api_event()).json()["event_id"]
    second = client.post("/api/v1/events", json=api_event()).json()["event_id"]
    assert first != second
    assert 20 <= len(first) <= 40


def test_naive_and_malformed_timestamps_are_rejected(client: TestClient) -> None:
    naive = client.post("/api/v1/events", json=api_event(occurred_at="2026-08-23T12:00:00"))
    malformed = client.post("/api/v1/events", json=api_event(occurred_at="not-a-time"))
    assert naive.json()["error"]["code"] == "INVALID_TIMESTAMP"
    assert malformed.json()["error"]["code"] == "INVALID_TIMESTAMP"


def test_empty_and_excessively_long_timestamps_are_rejected(client: TestClient) -> None:
    for value in ("", "2" * 65):
        response = client.post("/api/v1/events", json=api_event(occurred_at=value))
        assert response.json()["error"]["code"] == "INVALID_TIMESTAMP"


def test_timestamp_skew_is_bounded() -> None:
    normalizer = EventNormalizer(clock=lambda: FIXED_NOW)
    with pytest.raises(InvalidTimestampError):
        normalizer.normalize(external_event(occurred_at=FIXED_NOW - timedelta(days=366)))
    with pytest.raises(InvalidTimestampError):
        normalizer.normalize(external_event(occurred_at=FIXED_NOW + timedelta(minutes=6)))


def test_timestamp_skew_has_a_stable_api_error(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events",
        json=api_event(occurred_at=(datetime.now(UTC) - timedelta(days=366)).isoformat()),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_TIMESTAMP"


def test_timestamp_and_received_time_are_server_normalized() -> None:
    offset = timezone(timedelta(hours=5))
    occurred = datetime(2026, 8, 23, 16, 59, tzinfo=offset)
    canonical = EventNormalizer(
        clock=lambda: FIXED_NOW, event_id_factory=lambda: "evt_fixed_server_identity"
    ).normalize(external_event(occurred_at=occurred))
    assert canonical.occurred_at == datetime(2026, 8, 23, 11, 59, tzinfo=UTC)
    assert canonical.occurred_at.tzinfo is UTC
    assert canonical.received_at == FIXED_NOW


def test_invalid_internal_clock_fails_closed() -> None:
    normalizer = EventNormalizer(clock=lambda: datetime(2026, 8, 23, 12, 0))
    with pytest.raises(EventNormalizationError):
        normalizer.normalize(external_event())


def test_deterministic_classification_is_complete() -> None:
    expected = {
        EventType.CUSTOMER_REQUEST: EventCategory.CUSTOMER,
        EventType.CUSTOMER_MESSAGE: EventCategory.CUSTOMER,
        EventType.CUSTOMER_CREATED: EventCategory.CUSTOMER,
        EventType.CUSTOMER_UPDATED: EventCategory.CUSTOMER,
        EventType.ORDER_CREATED: EventCategory.COMMERCE,
        EventType.ORDER_UPDATED: EventCategory.COMMERCE,
        EventType.PAYMENT_RECEIVED: EventCategory.COMMERCE,
        EventType.SUPPORT_REQUEST: EventCategory.SUPPORT,
        EventType.INTERNAL_TASK: EventCategory.INTERNAL,
        EventType.SYSTEM_ALERT: EventCategory.SYSTEM,
        EventType.GHL_CONTACT_TAG_REQUEST: EventCategory.INTERNAL,
    }
    classifier = EventClassifier()
    assert {event_type: classifier.classify(event_type) for event_type in EventType} == expected


def test_canonical_serialization_is_deterministic_and_safe() -> None:
    normalizer = EventNormalizer(
        clock=lambda: FIXED_NOW, event_id_factory=lambda: "evt_fixed_server_identity"
    )
    canonical = normalizer.normalize(
        external_event(
            payload={"z_value": 1, "a_value": "safe"}, external_event_reference="partner-123"
        )
    )
    first = canonical_event_bytes(canonical)
    second = canonical_event_bytes(canonical)
    decoded = first.decode("utf-8")
    assert first == second
    assert decoded.index('"a_value"') < decoded.index('"z_value"')
    assert '"event_type":"CUSTOMER_REQUEST"' in decoded
    assert "+00:00" not in decoded
    assert "password" not in decoded.lower()


def test_canonical_serialization_has_an_output_ceiling() -> None:
    canonical = EventNormalizer(
        clock=lambda: FIXED_NOW, event_id_factory=lambda: "evt_fixed_server_identity"
    ).normalize(external_event())
    oversized = canonical.model_copy(update={"payload": {"value": "x" * 9_000}})
    with pytest.raises(EventNormalizationError):
        canonical_event_bytes(oversized)


def test_invalid_server_generated_id_fails_closed() -> None:
    normalizer = EventNormalizer(clock=lambda: FIXED_NOW, event_id_factory=lambda: "bad")
    with pytest.raises(EventNormalizationError):
        normalizer.normalize(external_event())


def test_non_string_taxonomy_and_timestamp_inputs_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ExternalEvent(
            event_type=123,  # type: ignore[arg-type]
            source=456,  # type: ignore[arg-type]
            occurred_at=789,  # type: ignore[arg-type]
            payload={},
        )


def test_non_finite_payload_number_is_rejected() -> None:
    with pytest.raises(ValidationError):
        external_event(payload={"number": float("nan")})


def test_non_mapping_payload_uses_safe_payload_error(client: TestClient) -> None:
    response = client.post("/api/v1/events", json=api_event(payload="not-an-object"))
    assert response.json()["error"]["code"] == "UNSAFE_PAYLOAD"


def test_exception_adapter_fallbacks_are_sanitized() -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/unit-test",
            "headers": [],
            "query_string": b"",
            "state": {"request_id": "unit-request-id"},
        }
    )
    for adapter in (_validation_error_adapter, _http_error_adapter):
        response = asyncio.run(adapter(request, RuntimeError("must not leak")))
        assert response.status_code == 500
        assert b"must not leak" not in response.body
    normalization = asyncio.run(_normalization_error_adapter(request, EventNormalizationError()))
    fallback = asyncio.run(_normalization_error_adapter(request, RuntimeError("must not leak")))
    assert normalization.status_code == 422
    assert fallback.status_code == 500


def test_ingestion_service_has_no_payload_side_effects() -> None:
    payload = {"nested": {"value": "original"}}
    event = external_event(payload=payload)
    result = EventIngestionService(
        normalizer=EventNormalizer(
            clock=lambda: FIXED_NOW, event_id_factory=lambda: "evt_fixed_server_identity"
        )
    ).ingest(event)
    payload["nested"]["value"] = "changed"
    canonical_nested = result.event.payload["nested"]
    assert isinstance(canonical_nested, dict)
    assert canonical_nested["value"] == "original"
    assert result.acknowledgement().model_dump().get("payload") is None


def test_safe_accepted_event_logging(client: TestClient) -> None:
    stream, handler = _capture_event_logs()
    marker = "customer-message-must-not-be-logged"
    try:
        response = client.post("/api/v1/events", json=api_event(payload={"message_text": marker}))
    finally:
        logging.getLogger("ai_business_automation").removeHandler(handler)
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    accepted = next(record for record in records if record["event"] == "event_accepted")
    assert accepted["event_id"] == response.json()["event_id"]
    assert accepted["event_type"] == "CUSTOMER_REQUEST"
    assert accepted["source"] == "API"
    assert accepted["category"] == "CUSTOMER"
    assert marker not in stream.getvalue()


def test_safe_rejected_event_logging(client: TestClient) -> None:
    stream, handler = _capture_event_logs()
    marker = "rejected-message-must-not-be-logged"
    try:
        response = client.post("/api/v1/events", json=api_event(payload={"password": marker}))
    finally:
        logging.getLogger("ai_business_automation").removeHandler(handler)
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    rejected = next(record for record in records if record["event"] == "event_rejected")
    assert rejected["request_id"] == response.headers["X-Request-ID"]
    assert rejected["error_category"] == "UNSAFE_PAYLOAD"
    assert rejected["outcome"] == "rejected"
    assert marker not in stream.getvalue()


def _capture_event_logs() -> tuple[StringIO, logging.Handler]:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logging.getLogger("ai_business_automation").addHandler(handler)
    return stream, handler


def test_strict_external_model_rejects_arbitrary_metadata() -> None:
    with pytest.raises(ValidationError):
        external_event(metadata={"category": "CLIENT_DEFINED"})
