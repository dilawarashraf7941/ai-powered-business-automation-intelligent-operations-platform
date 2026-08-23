"""Versioned API and health routes."""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict

from ai_business_automation.models import BusinessIntelligenceResult, PolicyDecision
from ai_business_automation.models.events import EventAcknowledgement, ExternalEvent
from ai_business_automation.services.events import EventIngestionService
from ai_business_automation.services.intelligence import BusinessIntelligenceService
from ai_business_automation.services.intelligence_factory import (
    get_intelligence_service as _get_intelligence_service,
)
from ai_business_automation.services.policy import PolicyDecisionService
from ai_business_automation.services.policy_factory import (
    get_policy_service as _get_policy_service,
)

router = APIRouter()
_LOGGER = logging.getLogger("ai_business_automation.events")
_INGESTION_SERVICE = EventIngestionService()


def get_ingestion_service() -> EventIngestionService:
    return _INGESTION_SERVICE


def get_intelligence_service() -> BusinessIntelligenceService:
    return _get_intelligence_service()


def get_policy_service() -> PolicyDecisionService:
    return _get_policy_service()


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok"]


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health() -> HealthResponse:
    """Return process health without consulting external resources."""

    return HealthResponse(status="ok")


@router.post(
    "/api/v1/events",
    response_model=EventAcknowledgement,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["events"],
)
async def create_event(
    event: ExternalEvent,
    request: Request,
    service: Annotated[EventIngestionService, Depends(get_ingestion_service)],
) -> EventAcknowledgement:
    """Normalize, classify, and acknowledge an untrusted event without side effects."""

    result = service.ingest(event)
    _LOGGER.info(
        "event_accepted",
        extra={
            "request_id": str(request.state.request_id),
            "event_id": result.event.event_id,
            "event_type": result.event.event_type.value,
            "source": result.event.source.value,
            "category": result.category.value,
            "outcome": "accepted",
        },
    )
    return result.acknowledgement()


@router.post(
    "/api/v1/events/analyze",
    response_model=BusinessIntelligenceResult,
    status_code=status.HTTP_200_OK,
    tags=["intelligence"],
)
async def analyze_event(
    event: ExternalEvent,
    intelligence: Annotated[BusinessIntelligenceService, Depends(get_intelligence_service)],
    ingestion: Annotated[EventIngestionService, Depends(get_ingestion_service)],
) -> BusinessIntelligenceResult:
    """Normalize and analyze an event without persistence, tools, or action execution."""

    normalized = ingestion.ingest(event)
    return await intelligence.analyze(normalized.event, normalized.category)


@router.post(
    "/api/v1/events/decide",
    response_model=PolicyDecision,
    status_code=status.HTTP_200_OK,
    tags=["policy"],
)
async def decide_event(
    event: ExternalEvent,
    request: Request,
    intelligence: Annotated[BusinessIntelligenceService, Depends(get_intelligence_service)],
    policy: Annotated[PolicyDecisionService, Depends(get_policy_service)],
    ingestion: Annotated[EventIngestionService, Depends(get_ingestion_service)],
) -> PolicyDecision:
    """Analyze and decide without executing the authoritative recommended action."""

    normalized = ingestion.ingest(event)
    analysis = await intelligence.analyze(normalized.event, normalized.category)
    result = policy.decide(normalized.event, analysis)
    _LOGGER.info(
        "policy_decision_returned",
        extra={
            "request_id": str(request.state.request_id),
            "event_id": result.event_id,
            "decision": result.decision.value,
            "action": result.action.value,
            "risk": result.risk.value,
            "policy_version": result.policy_version,
            "outcome": "success",
        },
    )
    return result
