"""Async-safe request context containing no credential material."""

from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(slots=True)
class RequestContext:
    request_id: str
    actor_id: str | None = None
    role: str | None = None


_CURRENT_CONTEXT: ContextVar[RequestContext | None] = ContextVar(
    "safe_request_context", default=None
)


def set_request_context(context: RequestContext) -> Token[RequestContext | None]:
    return _CURRENT_CONTEXT.set(context)


def reset_request_context(token: Token[RequestContext | None]) -> None:
    _CURRENT_CONTEXT.reset(token)


def current_request_context() -> RequestContext | None:
    return _CURRENT_CONTEXT.get()


def bind_authenticated_actor(context: RequestContext, actor_id: str, role: str) -> None:
    context.actor_id = actor_id
    context.role = role
