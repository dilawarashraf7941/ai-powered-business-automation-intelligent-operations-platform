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
    AUTHENTICATION = "GHL_AUTHENTICATION"
    AUTHORIZATION = "GHL_AUTHORIZATION"
    RATE_LIMIT = "GHL_RATE_LIMIT"
    VALIDATION = "GHL_VALIDATION"
    NOT_FOUND = "GHL_NOT_FOUND"
    TIMEOUT = "GHL_TIMEOUT"
    NETWORK = "GHL_NETWORK"
    SERVER_ERROR = "GHL_SERVER_ERROR"
    UNKNOWN = "GHL_UNKNOWN"


class GHLProviderError(Exception):
    """Safe classified failure with no provider body or transport detail."""

    def __init__(self, category: GHLFailureCategory, certainty: GHLOutcomeCertainty) -> None:
        self.category = category
        self.certainty = certainty
        super().__init__(category.value)


@runtime_checkable
class GHLProvider(Protocol):
    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None: ...


class UnavailableGHLProvider:
    """No-network fallback used when the server secret is not configured."""

    def add_contact_tag(self, parameters: GHLAddContactTagParameters) -> None:
        del parameters
        raise GHLProviderError(
            GHLFailureCategory.AUTHENTICATION,
            GHLOutcomeCertainty.DEFINITIVE,
        )


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
        body = GHLAddTagsRequest(tags=trusted.tags)
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
                    json=body.model_dump(mode="json"),
                )
        except httpx.TimeoutException as exc:
            raise GHLProviderError(
                GHLFailureCategory.TIMEOUT,
                GHLOutcomeCertainty.UNKNOWN,
            ) from exc
        except httpx.ConnectError as exc:
            raise GHLProviderError(
                GHLFailureCategory.NETWORK,
                GHLOutcomeCertainty.DEFINITIVE,
            ) from exc
        except httpx.RequestError as exc:
            raise GHLProviderError(
                GHLFailureCategory.NETWORK,
                GHLOutcomeCertainty.UNKNOWN,
            ) from exc

        if response.status_code == 201:
            self._validate_success(response, trusted)
            return
        category = {
            400: GHLFailureCategory.VALIDATION,
            401: GHLFailureCategory.AUTHENTICATION,
            403: GHLFailureCategory.AUTHORIZATION,
            404: GHLFailureCategory.NOT_FOUND,
            422: GHLFailureCategory.VALIDATION,
            429: GHLFailureCategory.RATE_LIMIT,
        }.get(response.status_code)
        if category is not None:
            raise GHLProviderError(category, GHLOutcomeCertainty.DEFINITIVE)
        if 500 <= response.status_code <= 599:
            raise GHLProviderError(
                GHLFailureCategory.SERVER_ERROR,
                GHLOutcomeCertainty.DEFINITIVE,
            )
        raise GHLProviderError(
            GHLFailureCategory.UNKNOWN,
            GHLOutcomeCertainty.UNKNOWN,
        )

    @staticmethod
    def _validate_success(
        response: httpx.Response,
        requested: GHLAddContactTagParameters,
    ) -> None:
        if len(response.content) > MAX_GHL_RESPONSE_BYTES:
            raise GHLProviderError(
                GHLFailureCategory.UNKNOWN,
                GHLOutcomeCertainty.UNKNOWN,
            )
        try:
            parsed = GHLAddTagsResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise GHLProviderError(
                GHLFailureCategory.UNKNOWN,
                GHLOutcomeCertainty.UNKNOWN,
            ) from exc
        if not set(requested.tags).issubset(set(parsed.tags)):
            raise GHLProviderError(
                GHLFailureCategory.UNKNOWN,
                GHLOutcomeCertainty.UNKNOWN,
            )
