"""Stable, sanitized API error responses."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))


def error_response(request: Request, status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": _request_id(request)}},
    )


async def validation_error_handler(request: Request, _exc: RequestValidationError) -> JSONResponse:
    return error_response(request, 422, "VALIDATION_ERROR", "Request validation failed.")


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return error_response(request, 404, "NOT_FOUND", "Resource not found.")
    return error_response(request, exc.status_code, "HTTP_ERROR", "Request could not be completed.")


async def unexpected_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    return error_response(request, 500, "INTERNAL_ERROR", "An internal error occurred.")
