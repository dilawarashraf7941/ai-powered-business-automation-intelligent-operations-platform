"""Build the advisory service from validated server configuration."""

from functools import lru_cache

from ai_business_automation.config import get_settings
from ai_business_automation.providers.factory import create_ai_provider
from ai_business_automation.services.intelligence import BusinessIntelligenceService


@lru_cache
def get_intelligence_service() -> BusinessIntelligenceService:
    settings = get_settings()
    return BusinessIntelligenceService(
        provider=create_ai_provider(settings),
        max_input_bytes=settings.ai_max_input_bytes,
        max_output_tokens=settings.ai_max_output_tokens,
    )
