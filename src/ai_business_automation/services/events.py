"""Side-effect-free ingestion orchestration."""

from dataclasses import dataclass, field

from ai_business_automation.models import (
    CanonicalBusinessEvent,
    EventAcknowledgement,
    EventCategory,
    ExternalEvent,
)
from ai_business_automation.services.canonicalization import canonical_event_bytes
from ai_business_automation.services.classification import EventClassifier
from ai_business_automation.services.normalization import EventNormalizer


@dataclass(frozen=True, slots=True)
class IngestionResult:
    event: CanonicalBusinessEvent
    category: EventCategory

    def acknowledgement(self) -> EventAcknowledgement:
        return EventAcknowledgement(
            accepted=True,
            event_id=self.event.event_id,
            event_type=self.event.event_type,
            category=self.category,
            received_at=self.event.received_at,
        )


@dataclass(frozen=True, slots=True)
class EventIngestionService:
    """Normalize and classify without persistence, networking, or execution."""

    normalizer: EventNormalizer = field(default_factory=EventNormalizer)
    classifier: EventClassifier = field(default_factory=EventClassifier)

    def ingest(self, external: ExternalEvent) -> IngestionResult:
        canonical = self.normalizer.normalize(external)
        category = self.classifier.classify(canonical.event_type)
        canonical_event_bytes(canonical)
        return IngestionResult(event=canonical, category=category)
