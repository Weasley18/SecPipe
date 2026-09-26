"""HTTP hardening: security headers, request context/access log, body limits,
and error handlers that never leak stack traces."""

from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secnotes.metrics import HTTP_LATENCY, HTTP_REQUESTS
from secnotes.requestctx import CONTEXT_KEY

access_log = logging.getLogger("secnotes.access")
error_log = logging.getLogger("secnotes.error")

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: "
    "https://fastapi.tiangolo.com; frame-ancestors 'none'"
)
DOCS_PATHS = ("/docs", "/docs/oauth2-redirect")
SENSITIVE_QUERY_KEYS = {"token", "access_token", "refresh_token", "password", "code", "secret"}
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class SecurityHeadersMiddleware:
    """Adds the security headers ZAP's baseline scan checks for to every response."""

    def __init__(self, app: ASGIApp, docs_enabled: bool = False) -> None:
        self.app = app
        self.docs_enabled = docs_enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = DOCS_CSP if self.docs_enabled and scope["path"] in DOCS_PATHS else API_CSP

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() not in {b"server", b"x-powered-by"}
                ]
                headers += [
                    (b"content-security-policy", csp.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (b"permissions-policy", b"geolocation=(), camera=(), microphone=(), payment=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"cross-origin-embedder-policy", b"require-corp"),
                    (b"cache-control", b"no-store"),
                ]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class _BodyTooLarge(Exception):
    pass


def _redact_query(query: str) -> str:
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    return urlencode([(k, "REDACTED" if k.lower() in SENSITIVE_QUERY_KEYS else v[:512]) for k, v in pairs])


class RequestContextMiddleware:
    """Assigns a request id, enforces a body-size cap, converts unhandled
    exceptions into a generic 500 and writes one structured access-log line
    per request (including the authenticated user and token id)."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = 1024 * 1024) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        incoming_id = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming_id if _REQUEST_ID.match(incoming_id) else secrets.token_hex(8)
        ctx: dict[str, Any] = {"request_id": request_id}
        scope[CONTEXT_KEY] = ctx
        started = time.perf_counter()
        status_holder = {"status": 500, "started": False}

        received = 0
        overflow = False

        async def send_wrapper(message: Message) -> None:
            if overflow and not status_holder["started"] and message["type"] == "http.response.start":
                # The app may have turned the aborted read into a 400; answer 413 instead.
                status_holder["started"] = True
                status_holder["status"] = 413
                await _send_json(send, 413, {"detail": "request body too large"}, request_id)
                return
            if overflow and status_holder["status"] == 413:
                return  # drop the app's own response body
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                status_holder["started"] = True
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
            await send(message)

        async def receive_wrapper() -> Message:
            nonlocal received, overflow
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    overflow = True
                    raise _BodyTooLarge
            return message

        try:
            declared = int(headers.get(b"content-length", b"0") or b"0")
        except ValueError:
            declared = 0
        try:
            if declared > self.max_body_bytes:
                overflow = True
                raise _BodyTooLarge
            await self.app(scope, receive_wrapper, send_wrapper)
        except _BodyTooLarge:
            if not status_holder["started"]:
                status_holder["started"] = True
                status_holder["status"] = 413
                await _send_json(send, 413, {"detail": "request body too large"}, request_id)
        except Exception:
            error_log.exception("unhandled error", extra={"event": "unhandled_error", "request_id": request_id})
            if not status_holder["started"]:
                status_holder["started"] = True
                status_holder["status"] = 500
                await _send_json(send, 500, {"detail": "internal server error", "request_id": request_id}, request_id)
        finally:
            duration = time.perf_counter() - started
            route = scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            method = scope.get("method", "")
            status_code = int(status_holder["status"])
            HTTP_REQUESTS.labels(method, route_path, str(status_code)).inc()
            HTTP_LATENCY.labels(method, route_path).observe(duration)
            client = scope.get("client")
            access_log.info(
                "request",
                extra={
                    "event": "http_request",
                    "method": method,
                    "path": scope.get("path", ""),
                    "route": route_path,
                    "query": _redact_query(scope.get("query_string", b"").decode("latin-1")),
                    "status": status_code,
                    "duration_ms": round(duration * 1000, 2),
                    "client_ip": client[0] if client else "unknown",
                    "user_agent": headers.get(b"user-agent", b"").decode("latin-1")[:200],
                    **ctx,
                },
            )


async def _send_json(send: Send, status: int, body: dict[str, Any], request_id: str) -> None:
    payload = JSONResponse(body, status_code=status)
    headers = [*payload.raw_headers, (b"x-request-id", request_id.encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload.body})


def _validation_handler(_request: Request, exc: Exception) -> JSONResponse:
    """422 without echoing submitted values (which may include passwords)."""
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    cleaned = [{"loc": err.get("loc"), "msg": err.get("msg"), "type": err.get("type")} for err in errors]
    return JSONResponse({"detail": jsonable_encoder(cleaned)}, status_code=422)


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _validation_handler)
