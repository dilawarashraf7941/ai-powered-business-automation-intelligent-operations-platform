"""FastAPI application factory and ASGI entrypoint."""

from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

from ai_business_automation.api.errors import (
    ai_analysis_error_handler,
    approval_error_handler,
    authentication_error_handler,
    authorization_error_handler,
    execution_error_handler,
    http_error_handler,
    normalization_error_handler,
    rate_limit_error_handler,
    unexpected_error_handler,
    validation_error_handler,
)
from ai_business_automation.api.routes import router
from ai_business_automation.config import Settings, get_settings
from ai_business_automation.logging import configure_logging
from ai_business_automation.providers import AIAnalysisError
from ai_business_automation.repositories.security_audit import SecurityAuditRepository
from ai_business_automation.security.auth import (
    AuthenticationError,
    AuthorizationError,
    BearerAuthenticator,
    ProcessRateLimiter,
    RateLimitError,
)
from ai_business_automation.security.middleware import (
    RequestBodyLimitMiddleware,
    RequestContextMiddleware,
    SafeExceptionMiddleware,
)
from ai_business_automation.services.approval_errors import ApprovalError
from ai_business_automation.services.execution_errors import ExecutionBoundaryError
from ai_business_automation.services.normalization import EventNormalizationError


async def _validation_error_adapter(request: Request, exc: Exception) -> Response:
    """Bridge Starlette's broad handler type to FastAPI's validation exception."""

    if not isinstance(exc, RequestValidationError):
        return await unexpected_error_handler(request, exc)
    return await validation_error_handler(request, exc)


async def _http_error_adapter(request: Request, exc: Exception) -> Response:
    """Bridge Starlette's broad handler type to its HTTP exception."""

    if not isinstance(exc, HTTPException):
        return await unexpected_error_handler(request, exc)
    return await http_error_handler(request, exc)


async def _normalization_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, EventNormalizationError):
        return await unexpected_error_handler(request, exc)
    return await normalization_error_handler(request, exc)


async def _ai_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, AIAnalysisError):
        return await unexpected_error_handler(request, exc)
    return await ai_analysis_error_handler(request, exc)


async def _approval_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, ApprovalError):
        return await unexpected_error_handler(request, exc)
    return await approval_error_handler(request, exc)


async def _execution_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, ExecutionBoundaryError):
        return await unexpected_error_handler(request, exc)
    return await execution_error_handler(request, exc)


async def _authentication_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, AuthenticationError):
        return await unexpected_error_handler(request, exc)
    return await authentication_error_handler(request, exc)


async def _authorization_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, AuthorizationError):
        return await unexpected_error_handler(request, exc)
    return await authorization_error_handler(request, exc)


async def _rate_limit_error_adapter(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, RateLimitError):
        return await unexpected_error_handler(request, exc)
    return await rate_limit_error_handler(request, exc)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build an application using validated, server-owned settings."""

    active_settings = settings or get_settings()
    configure_logging(active_settings.log_level)
    application = FastAPI(
        title="AI Business Automation Platform",
        version="0.1.0",
        debug=False,
    )
    application.add_exception_handler(RequestValidationError, _validation_error_adapter)
    application.add_exception_handler(HTTPException, _http_error_adapter)
    application.add_exception_handler(EventNormalizationError, _normalization_error_adapter)
    application.add_exception_handler(AIAnalysisError, _ai_error_adapter)
    application.add_exception_handler(ApprovalError, _approval_error_adapter)
    application.add_exception_handler(ExecutionBoundaryError, _execution_error_adapter)
    application.add_exception_handler(AuthenticationError, _authentication_error_adapter)
    application.add_exception_handler(AuthorizationError, _authorization_error_adapter)
    application.add_exception_handler(RateLimitError, _rate_limit_error_adapter)
    application.add_exception_handler(Exception, unexpected_error_handler)
    application.state.authenticator = BearerAuthenticator(active_settings)
    application.state.rate_limiter = ProcessRateLimiter(
        active_settings.auth_failure_limit, active_settings.protected_mutation_limit
    )
    application.state.security_audit = SecurityAuditRepository(
        Path(active_settings.approval_database_path)
    )
    application.include_router(router)
    application.add_middleware(SafeExceptionMiddleware)
    application.add_middleware(
        RequestBodyLimitMiddleware, max_bytes=active_settings.max_request_body_bytes
    )
    application.add_middleware(RequestContextMiddleware)
    return application


app = create_app()
