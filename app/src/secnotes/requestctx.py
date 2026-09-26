"""Per-request context shared between auth dependencies and the access log."""

from __future__ import annotations

from typing import Any

from starlette.requests import HTTPConnection

CONTEXT_KEY = "secnotes.ctx"


def client_ip(conn: HTTPConnection) -> str:
    return conn.client.host if conn.client else "unknown"


def set_context(conn: HTTPConnection, **values: Any) -> None:
    ctx = conn.scope.get(CONTEXT_KEY)
    if isinstance(ctx, dict):
        ctx.update(values)
