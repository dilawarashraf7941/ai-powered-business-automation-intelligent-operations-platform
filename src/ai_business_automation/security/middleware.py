"""Pure ASGI middleware for body limits, correlation, headers, and access logs."""

import json
import logging
import secrets
import time
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ai_business_automation.logging import (
    RequestContext,
    reset_request_context,
    set_request_context,
)
from ai_business_automation.models import FailureCategory, MetricName
from ai_business_automation.services.observability import OperationalMetrics

_LOGGER = logging.getLogger("ai_business_automation.requests")
_REQUEST_ID_BYTES = 16


def _error_body(code: str, message: str, request_id: str) -> bytes:
    return json.dumps(
        {"error": {"code": code, "message": message, "request_id": request_id}},
        separators=(",", ":"),
    ).encode("utf-8")


async def _send_json_error(
    send: Send, status: int, code: str, message: str, request_id: str
) -> None:
    body = _error_body(code, message, request_id)
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class RequestBodyLimitMiddleware:
    """Reject declared or streamed bodies before unbounded buffering can occur."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(scope.get("state", {}).get("request_id", "unavailable"))
        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
                if declared_size < 0:
                    raise ValueError
                if declared_size > self.max_bytes:
                    await _send_json_error(
                        send,
                        413,
                        "REQUEST_TOO_LARGE",
                        "Request body exceeds the allowed size.",
                        request_id,
                    )
                    return
            except ValueError:
                await _send_json_error(
                    send, 400, "INVALID_REQUEST", "Request metadata is invalid.", request_id
                )
                return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await _send_json_error(
                    send,
                    413,
                    "REQUEST_TOO_LARGE",
                    "Request body exceeds the allowed size.",
                    request_id,
                )
                return
            more_body = bool(message.get("more_body", False))

        replayed = False

        async def bounded_receive() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)


class SafeExceptionMiddleware:
    """Convert unexpected application failures into a sanitized inner response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await self.app(scope, receive, send)
        except Exception:
            if scope["type"] != "http":
                raise
            request_id = str(scope.get("state", {}).get("request_id", "unavailable"))
            _LOGGER.info(
                "event_rejected",
                extra={
                    "request_id": request_id,
                    "operation": _operation_name(
                        str(scope.get("method", "")), str(scope.get("path", ""))
                    ),
                    "error_category": "INTERNAL_ERROR",
                    "failure_category": FailureCategory.INTERNAL_FAILURE.value,
                    "outcome": "rejected",
                },
            )
            await _send_json_error(
                send, 500, "INTERNAL_ERROR", "An internal error occurred.", request_id
            )


class RequestContextMiddleware:
    """Assign a server-owned request ID and emit a bounded completion record."""

    def __init__(self, app: ASGIApp, metrics: OperationalMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = secrets.token_hex(_REQUEST_ID_BYTES)
        started = time.monotonic()
        state: MutableMapping[str, Any] = scope.setdefault("state", {})
        state["request_id"] = request_id
        context = RequestContext(request_id=request_id)
        state["request_context"] = context
        context_token = set_request_context(context)
        status = 500

        async def secure_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                headers.append((b"x-content-type-options", b"nosniff"))
                if _protected_path(str(scope.get("path", ""))):
                    headers.append((b"cache-control", b"no-store"))
                    headers.append((b"pragma", b"no-cache"))
                message = {**message, "headers": headers}
            await send(message)

        operation = _operation_name(str(scope.get("method", "")), str(scope.get("path", "")))
        try:
            await self.app(scope, receive, secure_send)
        finally:
            duration_ms = min(max(int((time.monotonic() - started) * 1_000), 0), 3_600_000)
            self.metrics.increment(MetricName.REQUESTS_TOTAL)
            if status >= 400:
                self.metrics.increment(MetricName.REQUESTS_FAILED)
            self.metrics.observe_request_latency(duration_ms)
            _LOGGER.info(
                "request_completed",
                extra={
                    "request_id": request_id,
                    "operation": operation,
                    "endpoint_category": _endpoint_category(operation),
                    "outcome": "success" if status < 400 else "failure",
                    "status_class": f"{status // 100}xx",
                    "duration_ms": duration_ms,
                },
            )
            reset_request_context(context_token)


def _operation_name(method: str, path: str) -> str:
    known = {
        ("GET", "/health"): "health_check",
        ("GET", "/ready"): "readiness_check",
        ("GET", "/api/v1/admin/status"): "admin_status",
        ("POST", "/api/v1/events"): "create_event",
        ("POST", "/api/v1/events/analyze"): "analyze_event",
        ("POST", "/api/v1/events/decide"): "decide_event",
    }
    operation = known.get((method, path))
    if operation is not None:
        return operation
    if path == "/api/v1/approvals" and method == "POST":
        return "create_approval"
    if path.startswith("/api/v1/approvals/"):
        if method == "GET":
            return "read_approval"
        if method == "POST" and path.endswith("/approve"):
            return "approve_approval"
        if method == "POST" and path.endswith("/reject"):
            return "reject_approval"
    if path == "/api/v1/actions/contact-tag" and method == "POST":
        return "execute_action"
    if path.startswith("/api/v1/actions/executions/") and method == "GET":
        return "read_execution"
    return "unmatched_route"


def _protected_path(path: str) -> bool:
    return path.startswith(("/api/v1/approvals", "/api/v1/actions", "/api/v1/admin"))


def _endpoint_category(operation: str) -> str:
    if operation in {"health_check", "readiness_check"}:
        return "operational"
    if operation == "admin_status":
        return "admin"
    if "approval" in operation:
        return "approval"
    if operation in {"execute_action", "read_execution"}:
        return "execution"
    if operation in {"analyze_event", "decide_event", "create_event"}:
        return "event"
    return "other"
