"""Phase 4 deterministic policy engine and decision API tests."""

import json
import logging
import socket
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta, timezone
from io import StringIO
from typing import cast

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from pydantic import ValidationError

from ai_business_automation.api.routes import get_intelligence_service, get_policy_service
from ai_business_automation.config import Environment, Settings
from ai_business_automation.logging import JsonFormatter
from ai_business_automation.main import create_app
from ai_business_automation.models import (
    POLICY_VERSION,
    BusinessIntelligenceResult,
    CanonicalBusinessEvent,
    DecisionOutcome,
    EventCategory,
    EventSource,
    EventType,
    EvidenceCode,
    EvidenceSource,
    ExternalEvent,
    Intent,
    PolicyDecision,
    PolicyEvidence,
    Priority,
    RecommendedAction,
    RecommendedNextStep,
    RiskLevel,
    Urgency,
)
from ai_business_automation.providers import AIAnalysisRequest, AITimeoutError
from ai_business_automation.services.intelligence import BusinessIntelligenceService
from ai_business_automation.services.normalization import EventNormalizer
from ai_business_automation.services.policy import (
    DeterministicPolicyEngine,
    PolicyDecisionService,
    PolicyEvaluation,
)
from tests.auth_helpers import authenticated_client

FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
EVENT_ID = "evt_fixed_server_identity"


class PolicyFakeProvider:
    def __init__(
        self,
        output: Mapping[str, object] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.output = output or provider_output()
        self.error = error
        self.requests: list[AIAnalysisRequest] = []

    @property
    def name(self) -> str:
        return "fake"

    async def analyze(self, request: AIAnalysisRequest) -> Mapping[str, object]:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.output


def provider_output(**updates: object) -> dict[str, object]:
    result: dict[str, object] = {
        "priority": "LOW",
        "urgency": "LOW",
        "intent": "SUPPORT",
        "confidence": 0.95,
        "summary": "A bounded advisory summary.",
        "reasons": ["Validated event facts support this recommendation."],
        "recommended_next_step": "REVIEW",
    }
    result.update(updates)
    return result


def canonical_event() -> CanonicalBusinessEvent:
    return EventNormalizer(clock=lambda: FIXED_NOW, event_id_factory=lambda: EVENT_ID).normalize(
        _external_event_model()
    )


def intelligence(**updates: object) -> BusinessIntelligenceResult:
    values: dict[str, object] = {
        "event_id": EVENT_ID,
        "category": EventCategory.CUSTOMER,
        "priority": Priority.LOW,
        "urgency": Urgency.LOW,
        "intent": Intent.SUPPORT,
        "confidence": 0.95,
        "summary": "A bounded advisory summary.",
        "reasons": ["Validated event facts support this recommendation."],
        "recommended_next_step": RecommendedNextStep.REVIEW,
    }
    values.update(updates)
    return BusinessIntelligenceResult(**values)  # type: ignore[arg-type]


def api_event(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "event_type": "CUSTOMER_REQUEST",
        "source": "WEB_FORM",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {"request_type": "demo"},
    }
    values.update(updates)
    return values


@pytest.fixture
def decision_client() -> Iterator[tuple[TestClient, PolicyFakeProvider, datetime]]:
    generated_at = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)
    provider = PolicyFakeProvider()
    intelligence_service = BusinessIntelligenceService(
        provider=provider, max_input_bytes=8_192, max_output_tokens=800
    )
    policy_service = PolicyDecisionService(
        engine=DeterministicPolicyEngine(0.85), clock=lambda: generated_at
    )
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_intelligence_service] = lambda: intelligence_service
    app.dependency_overrides[get_policy_service] = lambda: policy_service
    with authenticated_client(app) as client:
        yield client, provider, generated_at


def test_none_recommendation_allows_no_action() -> None:
    result = _evaluate(recommended_next_step=RecommendedNextStep.NO_ACTION)
    assert result.decision is DecisionOutcome.ALLOW
    assert result.action is RecommendedAction.NONE
    assert result.risk is RiskLevel.LOW


def test_high_confidence_low_risk_review_is_allowed_but_not_executed() -> None:
    result = _evaluate(confidence=0.95, recommended_next_step=RecommendedNextStep.REVIEW)
    assert (result.decision, result.action, result.risk) == (
        DecisionOutcome.ALLOW,
        RecommendedAction.REVIEW,
        RiskLevel.LOW,
    )


@pytest.mark.parametrize("confidence", [0.0, 0.72, 0.849999])
def test_low_confidence_requires_human_approval(confidence: float) -> None:
    result = _evaluate(confidence=confidence)
    assert result.decision is DecisionOutcome.REQUIRE_HUMAN_APPROVAL
    assert "LOW_CONFIDENCE" in _evidence_codes(result)


def test_confidence_threshold_is_inclusive() -> None:
    result = _evaluate(confidence=0.85)
    assert result.decision is DecisionOutcome.ALLOW
    assert "LOW_CONFIDENCE" not in _evidence_codes(result)


@pytest.mark.parametrize("priority", [Priority.HIGH, Priority.CRITICAL])
def test_elevated_priority_requires_human_approval(priority: Priority) -> None:
    result = _evaluate(priority=priority)
    assert result.decision is DecisionOutcome.REQUIRE_HUMAN_APPROVAL
    assert result.risk is (RiskLevel.CRITICAL if priority is Priority.CRITICAL else RiskLevel.HIGH)


def test_high_urgency_requires_human_approval() -> None:
    result = _evaluate(urgency=Urgency.HIGH)
    assert result.decision is DecisionOutcome.REQUIRE_HUMAN_APPROVAL
    assert result.risk is RiskLevel.HIGH


def test_unknown_intent_requires_human_approval() -> None:
    result = _evaluate(intent=Intent.UNKNOWN)
    assert result.decision is DecisionOutcome.REQUIRE_HUMAN_APPROVAL
    assert result.risk is RiskLevel.MEDIUM


@pytest.mark.parametrize(
    "recommendation",
    [
        RecommendedNextStep.CONTACT_HUMAN,
        RecommendedNextStep.REQUEST_INFORMATION,
        RecommendedNextStep.ESCALATE,
        RecommendedNextStep.SCHEDULE_CONSULTATION,
        RecommendedNextStep.NURTURE,
    ],
)
def test_actionable_recommendations_require_human_approval(
    recommendation: RecommendedNextStep,
) -> None:
    result = _evaluate(recommended_next_step=recommendation)
    assert result.decision is DecisionOutcome.REQUIRE_HUMAN_APPROVAL
    assert result.action.value == recommendation.value
    expected_risk = (
        RiskLevel.HIGH if recommendation is RecommendedNextStep.ESCALATE else RiskLevel.MEDIUM
    )
    assert result.risk is expected_risk


@pytest.mark.parametrize("priority", [Priority.HIGH, Priority.CRITICAL])
def test_no_action_with_high_risk_signal_is_denied(priority: Priority) -> None:
    result = _evaluate(priority=priority, recommended_next_step=RecommendedNextStep.NO_ACTION)
    assert result.decision is DecisionOutcome.DENY
    assert result.action is RecommendedAction.NONE
    assert "CONFLICTING_NO_ACTION_SIGNALS" in _evidence_codes(result)


def test_no_action_with_high_urgency_is_denied() -> None:
    result = _evaluate(
        urgency=Urgency.HIGH,
        recommended_next_step=RecommendedNextStep.NO_ACTION,
    )
    assert result.decision is DecisionOutcome.DENY
    assert result.risk is RiskLevel.HIGH


def test_mismatched_identity_fails_closed() -> None:
    mismatched = intelligence().model_copy(update={"event_id": "evt_different_server_identity"})
    result = DeterministicPolicyEngine().evaluate(canonical_event(), mismatched)
    assert result.decision is DecisionOutcome.DENY
    assert _evidence_codes(result) == {"IDENTITY_MISMATCH"}


def test_mismatched_category_fails_closed() -> None:
    mismatched = intelligence().model_copy(update={"category": EventCategory.COMMERCE})
    result = DeterministicPolicyEngine().evaluate(canonical_event(), mismatched)
    assert result.decision is DecisionOutcome.DENY
    assert _evidence_codes(result) == {"CATEGORY_MISMATCH"}


def test_missing_identity_is_rejected_by_strict_intelligence_model() -> None:
    values = intelligence().model_dump()
    del values["event_id"]
    with pytest.raises(ValidationError):
        BusinessIntelligenceResult.model_validate(values)


def test_missing_ai_reasons_fails_closed() -> None:
    result = _evaluate(reasons=[])
    assert result.decision is DecisionOutcome.DENY
    assert _evidence_codes(result) == {"MISSING_AI_EVIDENCE"}


def test_invalid_policy_version_fails_closed() -> None:
    result = DeterministicPolicyEngine().evaluate(
        canonical_event(),
        intelligence(),
        policy_version="2.0",
    )
    assert result.decision is DecisionOutcome.DENY
    assert result.action is RecommendedAction.NONE
    assert _evidence_codes(result) == {"INVALID_POLICY_VERSION"}


def test_policy_evaluation_is_deterministic_and_evidence_is_bounded() -> None:
    engine = DeterministicPolicyEngine()
    event = canonical_event()
    analysis = intelligence(
        confidence=0.4,
        priority=Priority.CRITICAL,
        urgency=Urgency.HIGH,
        intent=Intent.UNKNOWN,
        recommended_next_step=RecommendedNextStep.ESCALATE,
    )
    first = engine.evaluate(event, analysis)
    second = engine.evaluate(event, analysis)
    assert first == second
    assert len(first.evidence) <= 8


def test_policy_evidence_excludes_payload_reasons_and_secrets() -> None:
    marker = "private-customer-value"
    event = canonical_event()
    event = event.model_copy(update={"payload": {"message_text": marker}})
    analysis = intelligence(reasons=["another-private-value"])
    serialized = json.dumps(
        [
            entry.model_dump(mode="json")
            for entry in DeterministicPolicyEngine().evaluate(event, analysis).evidence
        ]
    )
    assert marker not in serialized
    assert "another-private-value" not in serialized
    assert "secret" not in serialized.lower()
    assert "http" not in serialized.lower()


@pytest.mark.parametrize("value", ["https://untrusted.invalid", "X" * 65])
def test_policy_evidence_rejects_unbounded_or_url_values(value: str) -> None:
    with pytest.raises(ValidationError):
        PolicyEvidence(
            code=EvidenceCode.POLICY_CONDITIONS_SATISFIED,
            source=EvidenceSource.POLICY,
            value=value,
        )


def test_policy_engine_makes_no_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail("policy evaluation attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    assert _evaluate().decision is DecisionOutcome.ALLOW


@pytest.mark.parametrize("threshold", [-0.01, 1.01])
def test_policy_threshold_is_bounded(threshold: float) -> None:
    with pytest.raises(ValueError):
        DeterministicPolicyEngine(threshold)
    with pytest.raises(ValidationError):
        Settings(policy_confidence_threshold=threshold)


def test_decide_endpoint_returns_only_server_owned_policy_result(
    decision_client: tuple[TestClient, PolicyFakeProvider, datetime],
) -> None:
    client, provider, generated_at = decision_client
    response = client.post("/api/v1/events/decide", json=api_event())
    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "ALLOW"
    assert result["action"] == "REVIEW"
    assert result["risk"] == "LOW"
    assert result["policy_version"] == POLICY_VERSION
    assert result["confidence_threshold"] == 0.85
    assert result["generated_at"] == generated_at.isoformat().replace("+00:00", "Z")
    assert result["event_id"].startswith("evt_")
    assert response.headers["X-Request-ID"]
    assert len(provider.requests) == 1
    for forbidden in ("payload", "summary", "reasons", "prompt", "provider", "api_key"):
        assert forbidden not in result


@pytest.mark.parametrize(
    "field",
    ["policy_version", "confidence_threshold", "decision", "action", "risk", "evidence"],
)
def test_client_policy_override_is_rejected_before_ai_call(
    decision_client: tuple[TestClient, PolicyFakeProvider, datetime], field: str
) -> None:
    client, provider, _generated_at = decision_client
    response = client.post("/api/v1/events/decide", json=api_event(**{field: "client-controlled"}))
    assert response.status_code == 422
    assert provider.requests == []


def test_ai_failure_prevents_policy_decision() -> None:
    response = _decision_response(PolicyFakeProvider(error=AITimeoutError()))
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "AI_TIMEOUT"
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]
    assert "decision" not in response.json()


def test_invalid_ai_output_prevents_policy_decision() -> None:
    response = _decision_response(PolicyFakeProvider(provider_output(priority="CLIENT_DEFINED")))
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "AI_INVALID_OUTPUT"
    assert "decision" not in response.json()


def test_decide_endpoint_does_not_execute_or_log_sensitive_content(
    decision_client: tuple[TestClient, PolicyFakeProvider, datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _provider, _generated_at = decision_client

    def blocked_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail("decision endpoint attempted an external connection")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("ai_business_automation")
    logger.addHandler(handler)
    marker = "customer-text-must-not-be-logged"
    try:
        response = client.post(
            "/api/v1/events/decide",
            json=api_event(payload={"message_text": marker}),
            headers={"Authorization": "Bearer fake-test-admin-token"},
        )
    finally:
        logger.removeHandler(handler)
    assert response.status_code == 200
    logs = stream.getvalue()
    assert marker not in logs
    assert "fake-test-admin-token" not in logs
    assert '"decision":"ALLOW"' in logs
    assert '"policy_version":"1.0"' in logs


def test_policy_decision_model_rejects_client_shaped_unknown_fields() -> None:
    valid = PolicyDecision(
        decision=DecisionOutcome.ALLOW,
        action=RecommendedAction.NONE,
        risk=RiskLevel.LOW,
        policy_version=POLICY_VERSION,
        confidence_threshold=0.85,
        evidence=list(
            DeterministicPolicyEngine()
            .evaluate(
                canonical_event(),
                intelligence(recommended_next_step=RecommendedNextStep.NO_ACTION),
            )
            .evidence
        ),
        event_id=EVENT_ID,
        generated_at=FIXED_NOW,
    )
    with pytest.raises(ValidationError):
        PolicyDecision.model_validate({**valid.model_dump(), "override": True})


def test_policy_decision_rejects_non_utc_generated_timestamp() -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(
            decision=DecisionOutcome.ALLOW,
            action=RecommendedAction.NONE,
            risk=RiskLevel.LOW,
            policy_version=POLICY_VERSION,
            confidence_threshold=0.85,
            evidence=[
                PolicyEvidence(
                    code=EvidenceCode.NO_ACTION_RECOMMENDED,
                    source=EvidenceSource.POLICY,
                )
            ],
            event_id=EVENT_ID,
            generated_at=FIXED_NOW.astimezone(timezone(timedelta(hours=5))),
        )


def _evaluate(**updates: object) -> PolicyEvaluation:
    return DeterministicPolicyEngine().evaluate(canonical_event(), intelligence(**updates))


def _evidence_codes(result: PolicyEvaluation) -> set[str]:
    return {entry.code.value for entry in result.evidence}


def _external_event_model() -> ExternalEvent:
    return ExternalEvent(
        event_type=EventType.CUSTOMER_REQUEST,
        source=EventSource.API,
        occurred_at=FIXED_NOW - timedelta(minutes=1),
        payload={"request_type": "demo"},
    )


def _decision_response(provider: PolicyFakeProvider) -> Response:
    app = create_app(Settings(environment=Environment.TEST))
    app.dependency_overrides[get_intelligence_service] = lambda: BusinessIntelligenceService(
        provider=provider, max_input_bytes=8_192, max_output_tokens=800
    )
    app.dependency_overrides[get_policy_service] = lambda: PolicyDecisionService(
        DeterministicPolicyEngine()
    )
    with authenticated_client(app) as client:
        return cast(Response, client.post("/api/v1/events/decide", json=api_event()))
