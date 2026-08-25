"""Dedicated HighLevel adapter for exactly one fixed contact-tag mutation."""

from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

import httpx
from pydantic import SecretStr, ValidationError

from ai_business_automation.models import (
    GHLAddContactTagParameters,
    GHLAddTagsRequest,
    GHLAddTagsResponse,
)

GHL_API_ORIGIN = "https://services.leadconnectorhq.com"
GHL_API_VERSION = "v3"
MAX_GHL_RESPONSE_BYTES = 4_096


class GHLOutcomeCertainty(StrEnum):
    DEFINITIVE = "DEFINITIVE"
    UNKNOWN = "UNKNOWN"


class GHLFailureCategory(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    RATE_LIMIT = "RATE_LIMIT"
    BAD_REQUEST = "BAD_REQUEST"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    UNKNOWN = "UNKNOWN"


class GHLProviderError(Exception):
    """Safe classified failure with no response body or transport detail."""

    def __init__(self, category: GHLFailureCategory, certainty: GHLOutcomeCertainty) -> None:
        self.category = category
        self.certainty = certainty
        super().__init__(category.value)


@runtime_checkable
class GHLProvider(Protocol):
    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None: ...


class UnavailableGHLProvider:
    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        del parameters
        raise GHLProviderError(GHLFailureCategory.AUTHENTICATION, GHLOutcomeCertainty.DEFINITIVE)


class GHLClient:
    """Fixed-origin adapter exposing only POST /contacts/{contactId}/tags."""

    def __init__(
        self,
        api_key: SecretStr,
        api_version: Literal["v3"],
        timeout_seconds: float,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if api_version != GHL_API_VERSION:
            raise ValueError("unsupported GHL API version")
        if not 1.0 <= timeout_seconds <= 30.0:
            raise ValueError("GHL timeout is outside the supported range")
        self._api_key = api_key
        self._api_version = api_version
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        trusted = GHLAddContactTagParameters.model_validate(parameters)
        endpoint = f"{GHL_API_ORIGIN}/contacts/{trusted.contact_id}/tags"
        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Version": self._api_version,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            with httpx.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.post(
                    endpoint,
                    headers=headers,
                    json=GHLAddTagsRequest(tags=(trusted.tag,)).model_dump(mode="json"),
                )
        except httpx.TimeoutException as exc:
            raise GHLProviderError(GHLFailureCategory.TIMEOUT, GHLOutcomeCertainty.UNKNOWN) from exc
        except httpx.ConnectError as exc:
            raise GHLProviderError(
                GHLFailureCategory.UNAVAILABLE, GHLOutcomeCertainty.DEFINITIVE
            ) from exc
        except httpx.RequestError as exc:
            raise GHLProviderError(GHLFailureCategory.UNKNOWN, GHLOutcomeCertainty.UNKNOWN) from exc

        if response.status_code == 201:
            self._validate_success(response, trusted.tag)
            return
        if response.status_code in {400, 404, 422}:
            category = GHLFailureCategory.BAD_REQUEST
        elif response.status_code in {401, 403}:
            category = GHLFailureCategory.AUTHENTICATION
        elif response.status_code == 429:
            category = GHLFailureCategory.RATE_LIMIT
        elif 500 <= response.status_code <= 599:
            category = GHLFailureCategory.PROVIDER_ERROR
        else:
            category = GHLFailureCategory.PROVIDER_ERROR
        raise GHLProviderError(category, GHLOutcomeCertainty.DEFINITIVE)

    @staticmethod
    def _validate_success(response: httpx.Response, requested_tag: str) -> None:
        if len(response.content) > MAX_GHL_RESPONSE_BYTES:
            raise GHLProviderError(GHLFailureCategory.UNKNOWN, GHLOutcomeCertainty.UNKNOWN)
        try:
            parsed = GHLAddTagsResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise GHLProviderError(GHLFailureCategory.UNKNOWN, GHLOutcomeCertainty.UNKNOWN) from exc
        if requested_tag not in parsed.tags:
            raise GHLProviderError(GHLFailureCategory.UNKNOWN, GHLOutcomeCertainty.UNKNOWN)
