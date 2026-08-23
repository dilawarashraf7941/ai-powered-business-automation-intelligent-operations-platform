"""Build the server-owned deterministic policy service."""

from functools import lru_cache

from ai_business_automation.config import get_settings
from ai_business_automation.services.policy import DeterministicPolicyEngine, PolicyDecisionService


@lru_cache
def get_policy_service() -> PolicyDecisionService:
    settings = get_settings()
    return PolicyDecisionService(
        engine=DeterministicPolicyEngine(
            confidence_threshold=settings.policy_confidence_threshold,
        )
    )
