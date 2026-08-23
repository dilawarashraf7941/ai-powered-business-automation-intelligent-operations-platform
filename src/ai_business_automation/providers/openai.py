"""The only OpenAI SDK integration and outbound AI network boundary."""

import json
from collections.abc import Mapping
from typing import Any, cast

from openai import (
    APIError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    RateLimitError,
)
from pydantic import SecretStr

from ai_business_automation.models import MAX_AI_OUTPUT_BYTES, ProviderAnalysisOutput
from ai_business_automation.providers.base import (
    AIAnalysisRequest,
    AIAuthenticationError,
    AIInvalidOutputError,
    AIProviderError,
    AIRateLimitError,
    AITimeoutError,
)


class OpenAIAnalysisProvider:
    """Use Responses structured output without tools, state, or retries."""

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model: str,
        timeout_seconds: float,
    ) -> None:
        self._model = model
        self._client = AsyncOpenAI(
            api_key=api_key.get_secret_value(),
            timeout=timeout_seconds,
            max_retries=0,
        )

    @property
    def name(self) -> str:
        return "openai"

    async def analyze(self, request: AIAnalysisRequest) -> Mapping[str, object]:
        try:
            response = await self._client.responses.create(
                model=self._model,
                instructions=request.system_instruction,
                input=request.untrusted_event_data,
                max_output_tokens=request.max_output_tokens,
                store=False,
                text=cast(
                    Any,
                    {
                        "format": {
                            "type": "json_schema",
                            "name": "business_intelligence",
                            "strict": True,
                            "schema": ProviderAnalysisOutput.model_json_schema(),
                        }
                    },
                ),
            )
        except APITimeoutError as exc:
            raise AITimeoutError from exc
        except RateLimitError as exc:
            raise AIRateLimitError from exc
        except AuthenticationError as exc:
            raise AIAuthenticationError from exc
        except APIError as exc:
            raise AIProviderError from exc

        output_text = response.output_text
        if not output_text or len(output_text.encode("utf-8")) > MAX_AI_OUTPUT_BYTES:
            raise AIInvalidOutputError
        try:
            decoded = json.loads(output_text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise AIInvalidOutputError from exc
        if not isinstance(decoded, dict):
            raise AIInvalidOutputError
        return cast(dict[str, object], decoded)
