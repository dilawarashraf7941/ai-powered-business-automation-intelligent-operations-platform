"""Versioned API and health routes."""

from typing import Literal

from fastapi import APIRouter, status
from pydantic import BaseModel, ConfigDict

from ai_business_automation.models.events import BusinessEvent, EventAcknowledgement
from ai_business_automation.services.events import acknowledge_event

router = APIRouter()


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
async def create_event(event: BusinessEvent) -> EventAcknowledgement:
    """Validate and acknowledge an untrusted event without side effects."""

    return acknowledge_event(event)
