"""Side-effect-free event acknowledgement service."""

from ai_business_automation.models.events import BusinessEvent, EventAcknowledgement


def acknowledge_event(event: BusinessEvent) -> EventAcknowledgement:
    """Acknowledge validated data without storing, forwarding, or executing it."""

    return EventAcknowledgement(accepted=True, event_type=event.event_type)
