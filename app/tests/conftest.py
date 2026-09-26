from __future__ import annotations

import secrets
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from secnotes.config import Settings
from secnotes.main import create_app
from secnotes.ssrf import PreviewFetcher

ALLOWED_ORIGIN = "https://app.secnotes.test"
PASSWORD = "correct horse battery staple"


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "sqlite://",
        "jwt_secret": secrets.token_urlsafe(48),
        "cors_origins": (ALLOWED_ORIGIN,),
        "preview_allowed_hosts": ("example.com", "*.example.org"),
        "login_rate_limit": "5/minute",
        "default_rate_limit": "1000/minute",
        "metrics_port": 0,
        "environment": "test",
    }
    values.update(overrides)
    return Settings(**values)


def fake_resolver(table: dict[str, list[str]]) -> Any:
    def resolve(host: str, _port: int) -> list[str]:
        if host not in table:
            raise OSError("unknown host")
        return table[host]

    return resolve


def html_transport(pages: dict[str, httpx.Response]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return pages.get(str(request.url), httpx.Response(404))

    return httpx.MockTransport(handler)


DEFAULT_PAGES = {
    "https://example.com/": httpx.Response(
        200,
        headers={"content-type": "text/html; charset=utf-8"},
        text='<html><head><title>Example Domain</title><meta name="description" content="Demo page"></head></html>',
    ),
    "https://example.com/redirect-internal": httpx.Response(
        302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
    ),
    "https://example.com/redirect-ok": httpx.Response(302, headers={"location": "/"}),
}
DEFAULT_DNS = {
    "example.com": ["93.184.215.14"],
    "docs.example.org": ["93.184.215.15"],
    "evil.example.org": ["10.0.0.5"],
}


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    fetcher = PreviewFetcher(
        settings.preview_allowed_hosts,
        resolver=fake_resolver(DEFAULT_DNS),
        transport=html_transport(DEFAULT_PAGES),
    )
    app = create_app(settings, preview_fetcher=fetcher)
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient, username: str, password: str = PASSWORD) -> dict[str, Any]:
    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def login(client: TestClient, username: str, password: str = PASSWORD, **extra: Any) -> dict[str, Any]:
    response = client.post("/auth/login", json={"username": username, "password": password, **extra})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def auth_headers(tokens: dict[str, Any]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def make_user(client: TestClient, username: str) -> dict[str, str]:
    register(client, username)
    return auth_headers(login(client, username))


def make_admin(client: TestClient, username: str = "admin") -> dict[str, str]:
    from secnotes.auth import hash_password
    from secnotes.models import User

    database = client.app.state.db  # type: ignore[attr-defined]
    with database.sessionmaker() as db:
        db.add(User(username=username, password_hash=hash_password(PASSWORD), role="admin"))
        db.commit()
    return auth_headers(login(client, username))
