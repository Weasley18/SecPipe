"""Rate limiting (flaw #11): the default limit must cover every API route, not only login."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from conftest import make_settings, make_user
from secnotes.main import create_app


@pytest.fixture
def throttled() -> Iterator[TestClient]:
    with TestClient(create_app(make_settings(default_rate_limit="3/minute"))) as test_client:
        yield test_client


def _rate_limited(route: str) -> float:
    return REGISTRY.get_sample_value("secnotes_rate_limited_total", {"route": route}) or 0.0


def test_default_limit_applies_to_router_routes(throttled: TestClient) -> None:
    headers = make_user(throttled, "rita")
    responses = [throttled.get("/notes", headers=headers) for _ in range(4)]
    assert [r.status_code for r in responses] == [200, 200, 200, 429]
    assert responses[-1].headers["retry-after"] == "60"
    assert responses[-1].json() == {"detail": "too many requests"}


def test_default_limit_is_per_route_not_per_url(throttled: TestClient) -> None:
    headers = make_user(throttled, "ivan")
    statuses = [throttled.get(f"/notes/{note_id}", headers=headers).status_code for note_id in range(1, 5)]
    assert statuses == [404, 404, 404, 429], "enumerating ids must not get a fresh budget per id"


def test_throttled_before_authentication(throttled: TestClient) -> None:
    assert [throttled.get("/notes").status_code for _ in range(4)] == [401, 401, 401, 429]


def test_probes_are_never_throttled(throttled: TestClient) -> None:
    for _ in range(10):
        assert throttled.get("/healthz").status_code == 200
        assert throttled.get("/readyz").status_code == 200


def test_rate_limited_is_logged_and_counted(throttled: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="secnotes.security")
    headers = make_user(throttled, "lena")
    before = _rate_limited("/notes/{note_id}")
    for note_id in range(1, 5):
        throttled.get(f"/notes/{note_id}", headers=headers)
    event = next(r for r in caplog.records if r.__dict__.get("event") == "rate_limited")
    assert event.__dict__["path"] == "/notes/4"
    assert event.__dict__["client_ip"] == "testclient"
    # Labelled by route template, so probing many ids cannot grow the metric without bound.
    assert _rate_limited("/notes/{note_id}") == before + 1
