"""Provider-neutral types and stable AI failure categories."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class AIAnalysisRequest:
    """Bounded server-owned instructions plus delimited untrusted event data."""

    system_instruction: str
    untrusted_event_data: str
    max_output_tokens: int


@runtime_checkable
class AIAnalysisProvider(Protocol):
    @property
    def name(self) -> str: ...

    async def analyze(self, request: AIAnalysisRequest) -> Mapping[str, object]: ...


class AIAnalysisError(Exception):
    code = "AI_PROVIDER_ERROR"
    safe_message = "AI analysis is temporarily unavailable."


class AITimeoutError(AIAnalysisError):
    code = "AI_TIMEOUT"


class AIRateLimitError(AIAnalysisError):
    code = "AI_RATE_LIMIT"


class AIAuthenticationError(AIAnalysisError):
    code = "AI_AUTHENTICATION"


class AIProviderError(AIAnalysisError):
    code = "AI_PROVIDER_ERROR"


class AIInvalidOutputError(AIAnalysisError):
    code = "AI_INVALID_OUTPUT"
    safe_message = "AI analysis returned an invalid result."


class AIConfigurationError(AIAnalysisError):
    code = "AI_CONFIGURATION"
    safe_message = "AI analysis is not configured."


class AIUnavailableError(AIAnalysisError):
    code = "AI_UNAVAILABLE"


class UnavailableAIProvider:
    """Deterministic no-network fallback when provider configuration is absent."""

    @property
    def name(self) -> str:
        return "unavailable"

    async def analyze(self, request: AIAnalysisRequest) -> Mapping[str, object]:
        del request
        raise AIConfigurationError
