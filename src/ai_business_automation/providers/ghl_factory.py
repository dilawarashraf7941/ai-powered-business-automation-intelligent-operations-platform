"""Construct the fixed HighLevel provider without exposing transport types to services."""

from ai_business_automation.config import Settings
from ai_business_automation.providers.ghl import GHLClient, GHLProvider, UnavailableGHLProvider


def create_ghl_provider(settings: Settings) -> GHLProvider:
    if settings.ghl_api_key is None:
        return UnavailableGHLProvider()
    return GHLClient(
        api_key=settings.ghl_api_key,
        api_version=settings.ghl_api_version,
        timeout_seconds=settings.ghl_timeout_seconds,
    )
