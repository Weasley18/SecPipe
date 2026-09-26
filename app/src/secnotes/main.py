"""FastAPI application factory.

``uvicorn secnotes.main:app`` works as usual: ``app`` is created lazily on
first access (PEP 562), so importing this module in tests does not require
production configuration.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIASGIMiddleware
from sqlalchemy import text

from secnotes import __version__, ratelimit
from secnotes.auth import TokenService
from secnotes.config import Settings
from secnotes.db import Database
from secnotes.logging_config import configure_logging
from secnotes.metrics import start_metrics_server
from secnotes.routes import admin, imports, notes, preview, users
from secnotes.security import RequestContextMiddleware, SecurityHeadersMiddleware, install_exception_handlers
from secnotes.ssrf import PreviewFetcher


def create_app(settings: Settings | None = None, *, preview_fetcher: PreviewFetcher | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    ratelimit.configure(settings)
    database = Database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        database.create_all()
        start_metrics_server(settings.metrics_port)
        yield
        database.engine.dispose()

    app = FastAPI(
        title="SecNotes API",
        version=__version__,
        debug=False,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.settings = settings
    app.state.db = database
    app.state.tokens = TokenService(settings)
    app.state.preview_fetcher = preview_fetcher or PreviewFetcher(settings.preview_allowed_hosts)
    app.state.limiter = ratelimit.limiter

    # add_middleware wraps outward: the last one added runs first.
    app.add_middleware(SlowAPIASGIMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )
    app.add_middleware(RequestContextMiddleware, max_body_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware, docs_enabled=settings.enable_docs)
    install_exception_handlers(app)
    app.add_exception_handler(RateLimitExceeded, ratelimit.rate_limit_exceeded_handler)

    app.include_router(users.router)
    app.include_router(imports.router)
    app.include_router(notes.router)
    app.include_router(preview.router)
    app.include_router(admin.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz(request: Request) -> Any:
        try:
            with database.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ok"}

    # Probes must never be throttled (slowapi exempts by function name).
    ratelimit.limiter.exempt(healthz)  # type: ignore[no-untyped-call]  # slowapi API is untyped
    ratelimit.limiter.exempt(readyz)  # type: ignore[no-untyped-call]
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> FastAPI:
    if name == "app":
        global _app  # noqa: PLW0603 -- one lazily-built app per process
        if _app is None:
            settings = Settings.from_env()
            configure_logging(settings.log_level)
            _app = create_app(settings)
        return _app
    raise AttributeError(name)
