"""Deterministic server-owned event classification."""

from ai_business_automation.models import EventCategory, EventType

_CATEGORY_BY_EVENT_TYPE: dict[EventType, EventCategory] = {
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


class EventClassifier:
    """Classify an enum value through a complete immutable-by-convention mapping."""

    def classify(self, event_type: EventType) -> EventCategory:
        return _CATEGORY_BY_EVENT_TYPE[event_type]
