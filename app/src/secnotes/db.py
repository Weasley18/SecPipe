"""Database engine and session handling (SQLAlchemy 2.x)."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from typing import Any

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("secnotes.db")


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Database:
    """Owns the engine and hands out sessions."""

    def __init__(self, url: str) -> None:
        kwargs: dict[str, Any] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            kwargs = {"connect_args": {"check_same_thread": False}}
            if ":memory:" in url or url.rstrip("/") in {"sqlite:", "sqlite+pysqlite:"}:
                kwargs["poolclass"] = StaticPool
        self.engine: Engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _enable_sqlite_foreign_keys)
        self.sessionmaker = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_all(self, attempts: int = 10, delay: float = 2.0) -> None:
        """Create tables, retrying while Postgres is still starting up.

        Callers import :mod:`secnotes.models` first so the tables are registered.
        Demo-grade schema management; a production service would use Alembic
        migrations run as a separate Job.
        """
        for attempt in range(1, attempts + 1):
            try:
                Base.metadata.create_all(self.engine)
                return
            except (OperationalError, ProgrammingError) as exc:
                if attempt == attempts:
                    raise
                logger.warning(
                    "database not ready, retrying",
                    extra={"event": "db_retry", "attempt": attempt, "error": type(exc).__name__},
                )
                time.sleep(delay)

    def session(self) -> Iterator[Session]:
        db = self.sessionmaker()
        try:
            yield db
        finally:
            db.close()


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    database: Database = request.app.state.db
    yield from database.session()
