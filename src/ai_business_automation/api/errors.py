"""Stable, sanitized API error responses."""

import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from ai_business_automation.models.events import PayloadLimitError, UnsafePayloadError
from ai_business_automation.providers import AIAnalysisError
from ai_business_automation.security.auth import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
)
from ai_business_automation.services.approval_errors import ApprovalError
from ai_business_automation.services.execution_errors import ExecutionBoundaryError
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
    operation_by_path = {
        "/api/v1/events": "create_event",
        "/api/v1/events/analyze": "analyze_event",
        "/api/v1/events/decide": "decide_event",
    }
    operation = operation_by_path.get(str(request.scope.get("path", "")))
    path = str(request.scope.get("path", ""))
    if operation is None and path.startswith("/api/v1/approvals"):
        operation = "approval_operation"
    if operation is None and path.startswith("/api/v1/actions"):
        operation = "execution_operation"
    if request.method == "POST" and operation is not None:
        _LOGGER.info(
            "event_rejected",
            extra={
                "request_id": _request_id(request),
                "operation": operation,
                "error_category": code,
                "outcome": "rejected",
            },
        )
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": _request_id(request)}},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    if str(request.scope.get("path", "")).startswith("/api/v1/actions"):
        return error_response(
            request,
            422,
            "ACTION_VALIDATION_ERROR",
            "Execution input is invalid.",
        )
    if str(request.scope.get("path", "")).startswith("/api/v1/approvals"):
        return error_response(
            request,
            422,
            "APPROVAL_VALIDATION_ERROR",
            "Approval input is invalid.",
        )
    code = _validation_error_code(exc)
    return error_response(request, 422, code, _ERROR_MESSAGES[code])


async def authentication_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
    response = error_response(request, 401, exc.code, "Authentication is required.")
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


async def authorization_error_handler(request: Request, _exc: AuthorizationError) -> JSONResponse:
    return error_response(request, 403, "FORBIDDEN", "Authorization was denied.")


async def rate_limit_error_handler(request: Request, _exc: RateLimitError) -> JSONResponse:
    return error_response(request, 429, "RATE_LIMITED", "Request rate limit exceeded.")


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


async def ai_analysis_error_handler(request: Request, exc: AIAnalysisError) -> JSONResponse:
    status_by_code = {
        "AI_TIMEOUT": 504,
        "AI_RATE_LIMIT": 503,
        "AI_AUTHENTICATION": 503,
        "AI_PROVIDER_ERROR": 503,
        "AI_INVALID_OUTPUT": 502,
        "AI_CONFIGURATION": 503,
        "AI_UNAVAILABLE": 503,
    }
    return error_response(request, status_by_code[exc.code], exc.code, exc.safe_message)


async def approval_error_handler(request: Request, exc: ApprovalError) -> JSONResponse:
    return error_response(request, exc.status_code, exc.code, exc.safe_message)


async def execution_error_handler(request: Request, exc: ExecutionBoundaryError) -> JSONResponse:
    return error_response(request, exc.status_code, exc.code, exc.safe_message)


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return error_response(request, 404, "NOT_FOUND", "Resource not found.")
    return error_response(request, exc.status_code, "HTTP_ERROR", "Request could not be completed.")


async def unexpected_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    return error_response(request, 500, "INTERNAL_ERROR", "An internal error occurred.")
