"""Provider-neutral AI analysis boundary."""

from ai_business_automation.providers.base import (
    AIAnalysisError,
    AIAnalysisProvider,
    AIAnalysisRequest,
    AIAuthenticationError,
    AIConfigurationError,
    AIInvalidOutputError,
    AIProviderError,
    AIRateLimitError,
    AITimeoutError,
    AIUnavailableError,
)

__all__ = [
    "AIAnalysisError",
    "AIAnalysisProvider",
    "AIAnalysisRequest",
    "AIAuthenticationError",
    "AIConfigurationError",
    "AIInvalidOutputError",
    "AIProviderError",
    "AIRateLimitError",
    "AITimeoutError",
    "AIUnavailableError",
]
