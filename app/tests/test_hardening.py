"""Flaw #10 (CORS, tracebacks, headers) plus health, metrics and body limits."""

from __future__ import annotations

import json
import logging

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from conftest import ALLOWED_ORIGIN, make_settings, make_user
from secnotes.logging_config import JsonFormatter, configure_logging
from secnotes.main import create_app

EXPECTED_HEADERS = {
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


@pytest.mark.parametrize("path", ["/healthz", "/openapi.json", "/does-not-exist", "/notes"])
def test_security_headers_on_every_response(client: TestClient, path: str) -> None:
    response = client.get(path)
    for header, value in EXPECTED_HEADERS.items():
        assert response.headers[header] == value
    assert "server" not in response.headers
    assert len(response.headers["x-request-id"]) >= 8


def test_request_id_propagated(client: TestClient) -> None:
    assert (
        client.get("/healthz", headers={"X-Request-ID": "trace-12345678"}).headers["x-request-id"] == "trace-12345678"
    )
    assert client.get("/healthz", headers={"X-Request-ID": "bad id!"}).headers["x-request-id"] != "bad id!"


def test_cors_only_for_explicit_origins(client: TestClient) -> None:
    allowed = client.get("/healthz", headers={"Origin": ALLOWED_ORIGIN})
    assert allowed.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert allowed.headers["access-control-allow-credentials"] == "true"
    evil = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
    preflight = client.options(
        "/notes", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_unhandled_errors_are_generic(settings: object) -> None:
    app = create_app(make_settings())
    router = APIRouter()

    @router.get("/boom")
    def boom() -> None:
        raise RuntimeError("database password is hunter2")

    app.include_router(router)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
    assert response.status_code == 500
    assert set(response.json()) == {"detail", "request_id"}
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_docs_disabled_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    with TestClient(create_app(make_settings(enable_docs=True))) as docs_client:
        page = docs_client.get("/docs")
        assert page.status_code == 200
        assert "cdn.jsdelivr.net" in page.headers["content-security-policy"]


def test_body_size_limit(client: TestClient) -> None:
    headers = make_user(client, "alice")
    big = {"title": "x", "body": "a" * (2 * 1024 * 1024)}
    assert client.post("/notes", json=big, headers=headers).status_code == 413

    def chunks():  # type: ignore[no-untyped-def]
        for _ in range(3):
            yield b"a" * (512 * 1024)

    streamed = client.post("/notes", content=chunks(), headers={**headers, "Content-Type": "application/json"})
    assert streamed.status_code == 413


def test_health_and_readiness(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ok"}


def test_readiness_fails_without_database() -> None:
    app = create_app(make_settings(database_url="sqlite:////nonexistent-dir/x.db"))
    client = TestClient(app)  # no lifespan: tables are never created
    assert client.get("/readyz").status_code == 503


def test_metrics_recorded(client: TestClient) -> None:
    client.post("/auth/login", json={"username": "nobody", "password": "wrong password!!"})
    value = REGISTRY.get_sample_value("secnotes_login_attempts_total", {"outcome": "failure"})
    assert value is not None and value >= 1
    assert REGISTRY.get_sample_value(
        "secnotes_http_requests_total", {"method": "POST", "route": "/auth/login", "status": "401"}
    )


def test_access_log_includes_user_and_redacts_query(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    headers = make_user(client, "logged")
    caplog.set_level(logging.INFO, logger="secnotes.access")
    client.get("/notes/search", params={"q": "x", "token": "abc"}, headers=headers)
    record = next(r for r in caplog.records if r.__dict__.get("route") == "/notes/search")
    assert record.__dict__["event"] == "http_request"
    assert record.__dict__["user_id"] == 1
    assert record.__dict__["jti"]
    assert "token=REDACTED" in record.__dict__["query"]


def test_json_formatter_and_configure_logging(capsys: pytest.CaptureFixture[str]) -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord("secnotes.security", logging.WARNING, __file__, 1, "login failed", None, None)
    record.event = "login_failed"
    record.client_ip = "10.0.0.1"
    line = json.loads(formatter.format(record))
    assert line["event"] == "login_failed"
    assert line["level"] == "warning"
    assert line["service"] == "secnotes-api"
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging("INFO")
        logging.getLogger("secnotes.test").info("hello", extra={"event": "x"})
        assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["msg"] == "hello"
    finally:
        root.handlers[:], level = saved
        root.setLevel(level)
