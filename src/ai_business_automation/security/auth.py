"""Fail-closed bearer authentication, authorization, and bounded local limiting."""

import hmac
import threading
import time
from dataclasses import dataclass

from fastapi import Request

from ai_business_automation.config import Settings
from ai_business_automation.models import AuthenticatedActor, AuthRole, SecurityAuditEventType

_MAX_TOKEN_LENGTH = 256


class AuthenticationError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Authentication could not be completed.")


class AuthorizationError(Exception):
    pass


class RateLimitError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _Credential:
    token: str
    actor: AuthenticatedActor


class BearerAuthenticator:
    """Validate one strict header while comparing every configured fixed slot."""

    def __init__(self, settings: Settings) -> None:
        raw_slots = (
            (settings.auth_token_1, settings.auth_actor_1, settings.auth_role_1),
            (settings.auth_token_2, settings.auth_actor_2, settings.auth_role_2),
            (settings.auth_token_3, settings.auth_actor_3, settings.auth_role_3),
        )
        self._credentials = tuple(
            _Credential(
                token.get_secret_value(),
                AuthenticatedActor(actor_id=actor, role=role),
            )
            for token, actor, role in raw_slots
            if token is not None and actor is not None and role is not None
        )

    @property
    def configured_slots(self) -> int:
        return len(self._credentials)

    def authenticate(self, authorization_headers: list[str]) -> AuthenticatedActor:
        if not authorization_headers:
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        if len(authorization_headers) != 1:
            raise AuthenticationError("AUTHENTICATION_FAILED")
        value = authorization_headers[0]
        parts = value.split(" ")
        if (
            len(parts) != 2
            or parts[0] != "Bearer"
            or not parts[1]
            or len(parts[1]) > _MAX_TOKEN_LENGTH
            or any(character.isspace() for character in parts[1])
        ):
            raise AuthenticationError("AUTHENTICATION_FAILED")
        supplied = parts[1]
        matched_index = -1
        matched_count = 0
        for index, credential in enumerate(self._credentials):
            matched = hmac.compare_digest(supplied, credential.token)
            matched_count += int(matched)
            if matched:
                matched_index = index
        if matched_count != 1:
            raise AuthenticationError("AUTHENTICATION_FAILED")
        return self._credentials[matched_index].actor


class ProcessRateLimiter:
    """Small fixed-window process-local limiter with only fixed bucket names."""

    def __init__(self, authentication_limit: int, mutation_limit: int) -> None:
        self._limits = {"authentication": authentication_limit, "mutation": mutation_limit}
        self._state = {"authentication": (time.monotonic(), 0), "mutation": (time.monotonic(), 0)}
        self._lock = threading.Lock()

    def consume(self, bucket: str) -> None:
        now = time.monotonic()
        with self._lock:
            started, count = self._state[bucket]
            if now - started >= 60:
                started, count = now, 0
            count += 1
            self._state[bucket] = (started, count)
            if count > self._limits[bucket]:
                raise RateLimitError

    @property
    def bucket_count(self) -> int:
        """Expose only the fixed bucket count, never identities or request data."""

        return len(self._state)


_ROLE_PERMISSIONS = {
    AuthRole.READ_ONLY: frozenset({"read", "analysis"}),
    AuthRole.APPROVER: frozenset({"read", "analysis", "approval"}),
    AuthRole.EXECUTOR: frozenset({"read", "analysis", "execution", "reconciliation"}),
    AuthRole.ADMIN: frozenset(
        {"read", "analysis", "approval", "execution", "reconciliation", "admin"}
    ),
}


def require_permission(permission: str):  # type: ignore[no-untyped-def]
    async def dependency(request: Request) -> AuthenticatedActor:
        authenticator: BearerAuthenticator = request.app.state.authenticator
        limiter: ProcessRateLimiter = request.app.state.rate_limiter
        audit = request.app.state.security_audit
        request_id = str(request.state.request_id)
        operation = _operation(request)
        try:
            actor = authenticator.authenticate(request.headers.getlist("authorization"))
        except AuthenticationError:
            limiter.consume("authentication")
            audit.append(
                SecurityAuditEventType.AUTHENTICATION_FAILED,
                request_id=request_id,
                operation=operation,
                outcome="failure",
            )
            raise
        audit.append(
            SecurityAuditEventType.AUTHENTICATION_SUCCEEDED,
            actor=actor,
            request_id=request_id,
            operation=operation,
            outcome="success",
        )
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            limiter.consume("mutation")
        event_types = {
            "approval": (
                SecurityAuditEventType.APPROVAL_AUTHORIZED,
                SecurityAuditEventType.APPROVAL_REJECTED_BY_AUTHZ,
            ),
            "execution": (
                SecurityAuditEventType.ACTION_EXECUTION_AUTHORIZED,
                SecurityAuditEventType.ACTION_EXECUTION_REJECTED_BY_AUTHZ,
            ),
            "reconciliation": (
                SecurityAuditEventType.EXECUTION_RECONCILIATION_AUTHORIZED,
                SecurityAuditEventType.EXECUTION_RECONCILIATION_REJECTED_BY_AUTHZ,
            ),
        }
        allowed = permission in _ROLE_PERMISSIONS[actor.role]
        if permission in event_types:
            audit.append(
                event_types[permission][0 if allowed else 1],
                actor=actor,
                request_id=request_id,
                operation=operation,
                outcome="authorized" if allowed else "rejected",
            )
        if not allowed:
            raise AuthorizationError
        request.state.authenticated_actor = actor
        return actor

    return dependency


def _operation(request: Request) -> str:
    return f"{request.method}_{request.url.path}"[:128]
