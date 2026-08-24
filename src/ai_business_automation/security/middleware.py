"""Pure ASGI middleware for body limits, correlation, headers, and access logs."""

import json
import logging
import secrets
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_LOGGER = logging.getLogger("ai_business_automation.requests")
_REQUEST_ID_BYTES = 18


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
                    "outcome": "rejected",
                },
            )
            await _send_json_error(
                send, 500, "INTERNAL_ERROR", "An internal error occurred.", request_id
            )


class RequestContextMiddleware:
    """Assign a server-owned request ID and emit a bounded completion record."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = secrets.token_urlsafe(_REQUEST_ID_BYTES)
        state: MutableMapping[str, Any] = scope.setdefault("state", {})
        state["request_id"] = request_id
        status = 500

        async def secure_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                headers.append((b"x-content-type-options", b"nosniff"))
                message = {**message, "headers": headers}
            await send(message)

        operation = _operation_name(str(scope.get("method", "")), str(scope.get("path", "")))
        try:
            await self.app(scope, receive, secure_send)
        finally:
            _LOGGER.info(
                "request_completed",
                extra={
                    "request_id": request_id,
                    "operation": operation,
                    "outcome": "success" if status < 400 else "failure",
                    "status_class": f"{status // 100}xx",
                },
            )


def _operation_name(method: str, path: str) -> str:
    known = {
        ("GET", "/health"): "health_check",
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
    return "unmatched_route"
