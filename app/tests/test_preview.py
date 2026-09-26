"""Preview: flaw #6 (SSRF) regression tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import make_user
from secnotes.ssrf import PreviewBlocked, classify_address, host_allowed, system_resolver, validate_url


def test_preview_allowed_host(client: TestClient) -> None:
    headers = make_user(client, "alice")
    response = client.get("/preview", params={"url": "https://example.com/"}, headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "url": "https://example.com/",
        "title": "Example Domain",
        "description": "Demo page",
    }
    followed = client.get("/preview", params={"url": "https://example.com/redirect-ok"}, headers=headers)
    assert followed.json()["title"] == "Example Domain"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://127.0.0.1:8000/admin/export",
        "http://localhost/",
        "http://10.0.0.5/",
        "http://postgres:5432/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https://user:pass@example.com/",
        "https://example.com:8443/",
        "https://evil.example.org/",
        "https://not-allowed.test/",
        "https://example.com/redirect-internal",
    ],
)
def test_preview_blocks_ssrf_targets(client: TestClient, url: str) -> None:
    headers = make_user(client, "bob")
    response = client.get("/preview", params={"url": url}, headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "URL not allowed"}


def test_preview_unavailable_upstream(client: TestClient) -> None:
    headers = make_user(client, "carol")
    response = client.get("/preview", params={"url": "https://docs.example.org/missing"}, headers=headers)
    assert response.status_code == 502


@pytest.mark.parametrize(
    ("address", "kind"),
    [
        ("8.8.8.8", "public"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link_local"),
        ("192.168.1.10", "private"),
        ("100.64.0.1", "reserved"),
        ("::1", "loopback"),
        ("::ffff:10.1.2.3", "private"),
        ("0.0.0.0", "reserved"),
    ],
)
def test_classify_address(address: str, kind: str) -> None:
    assert classify_address(address) == kind


def test_host_allowed_wildcards() -> None:
    allowed = ("example.com", "*.example.org")
    assert host_allowed("example.com", allowed)
    assert host_allowed("a.example.org", allowed)
    assert not host_allowed("example.org.evil.com", allowed)
    assert not host_allowed("badexample.com", allowed)


def test_validate_url_edge_cases() -> None:
    def resolver(host: str, port: int) -> list[str]:
        return []

    with pytest.raises(PreviewBlocked, match="unresolvable"):
        validate_url("https://example.com/", ("example.com",), resolver)
    with pytest.raises(PreviewBlocked, match="too_long"):
        validate_url("https://example.com/" + "a" * 3000, ("example.com",), resolver)
    with pytest.raises(PreviewBlocked, match="no_host"):
        validate_url("https:///path", ("example.com",), resolver)
    with pytest.raises(PreviewBlocked, match="bad_port"):
        validate_url("https://example.com:99999/", ("example.com",), resolver)


def test_system_resolver_localhost() -> None:
    assert "127.0.0.1" in system_resolver("localhost", 80) or "::1" in system_resolver("localhost", 80)
