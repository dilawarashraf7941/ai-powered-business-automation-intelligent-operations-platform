"""Construct the configured provider without leaking SDK types into services."""

from ai_business_automation.config import Settings
from ai_business_automation.providers.base import AIAnalysisProvider, UnavailableAIProvider
from ai_business_automation.providers.openai import OpenAIAnalysisProvider


def create_ai_provider(settings: Settings) -> AIAnalysisProvider:
    if settings.openai_api_key is None:
        return UnavailableAIProvider()
    return OpenAIAnalysisProvider(
        api_key=settings.openai_api_key,
        model=settings.openai_model,
        timeout_seconds=settings.ai_timeout_seconds,
    )
