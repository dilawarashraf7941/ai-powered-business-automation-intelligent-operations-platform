"""Stable, sanitized API error responses."""

import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from ai_business_automation.models.events import PayloadLimitError, UnsafePayloadError
from ai_business_automation.services.normalization import EventNormalizationError

_LOGGER = logging.getLogger("ai_business_automation.events")
_ERROR_MESSAGES = {
    "INVALID_EVENT": "Event validation failed.",
    "UNSUPPORTED_EVENT_TYPE": "Event type is not supported.",
    "UNSUPPORTED_SOURCE": "Event source is not supported.",
    "INVALID_TIMESTAMP": "Event timestamp is invalid.",
    "PAYLOAD_LIMIT_EXCEEDED": "Event payload exceeds an allowed limit.",
    "UNSAFE_PAYLOAD": "Event payload contains prohibited content.",
    "NORMALIZATION_ERROR": "Event normalization failed.",
}


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))


def error_response(request: Request, status: int, code: str, message: str) -> JSONResponse:
    if request.method == "POST" and request.scope.get("path") == "/api/v1/events":
        _LOGGER.info(
            "event_rejected",
            extra={
                "request_id": _request_id(request),
                "operation": "create_event",
                "error_category": code,
                "outcome": "rejected",
            },
        )
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": _request_id(request)}},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    code = _validation_error_code(exc)
    return error_response(request, 422, code, _ERROR_MESSAGES[code])


def _validation_error_code(exc: RequestValidationError) -> str:
    errors = exc.errors()
    locations = {str(component) for error in errors for component in error.get("loc", ())}
    if "event_type" in locations:
        return "UNSUPPORTED_EVENT_TYPE"
    if "source" in locations:
        return "UNSUPPORTED_SOURCE"
    if "occurred_at" in locations:
        return "INVALID_TIMESTAMP"
    for error in errors:
        cause = error.get("ctx", {}).get("error")
        if isinstance(cause, PayloadLimitError):
            return "PAYLOAD_LIMIT_EXCEEDED"
        if isinstance(cause, UnsafePayloadError):
            return "UNSAFE_PAYLOAD"
    if "payload" in locations:
        return "UNSAFE_PAYLOAD"
    return "INVALID_EVENT"


async def normalization_error_handler(
    request: Request, exc: EventNormalizationError
) -> JSONResponse:
    return error_response(request, 422, exc.code, _ERROR_MESSAGES[exc.code])


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return error_response(request, 404, "NOT_FOUND", "Resource not found.")
    return error_response(request, exc.status_code, "HTTP_ERROR", "Request could not be completed.")


async def unexpected_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    return error_response(request, 500, "INTERNAL_ERROR", "An internal error occurred.")
