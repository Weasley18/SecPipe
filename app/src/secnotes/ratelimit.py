"""Rate limiting with slowapi.

Limits are per client IP and route (``key_style="endpoint"``: ``/notes/1`` and
``/notes/2`` share one budget) and held in process memory, so each replica
counts separately; a production deployment would point slowapi at Redis.
"""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from secnotes.config import Settings
from secnotes.metrics import LOGIN_ATTEMPTS, RATE_LIMITED
from secnotes.requestctx import client_ip

security_log = logging.getLogger("secnotes.security")

_limits = {"login": "5/minute", "default": "120/minute"}


def login_limit() -> str:
    return _limits["login"]


def default_limit() -> str:
    return _limits["default"]


limiter = Limiter(key_func=get_remote_address, default_limits=[default_limit], key_style="endpoint")


def enforce_default_limit(request: Request) -> None:
    """Apply the default limit to the matched route (an app-wide dependency).

    slowapi's middleware looks the endpoint up in ``app.routes``, where FastAPI
    wraps each included router without an ``endpoint``; it matched nothing and
    let every router route through unthrottled. A dependency runs after routing,
    on the endpoint FastAPI actually matched, and before authentication.
    Exempt routes (the probes) are skipped by slowapi itself.
    """
    limiter._check_request_limit(request, request.scope.get("endpoint"), in_middleware=True)


def configure(settings: Settings) -> None:
    _limits["login"] = settings.login_rate_limit
    _limits["default"] = settings.default_rate_limit
    limiter.reset()


def rate_limit_exceeded_handler(request: Request, exc: Exception) -> Response:
    detail = exc.detail if isinstance(exc, RateLimitExceeded) else "rate limit exceeded"
    path = request.url.path
    security_log.warning(
        "rate limit exceeded",
        extra={"event": "rate_limited", "path": path, "client_ip": client_ip(request), "limit": detail},
    )
    RATE_LIMITED.labels(getattr(request.scope.get("route"), "path", "unmatched")).inc()
    if path == "/auth/login":
        LOGIN_ATTEMPTS.labels("rate_limited").inc()
    return JSONResponse({"detail": "too many requests"}, status_code=429, headers={"Retry-After": "60"})
