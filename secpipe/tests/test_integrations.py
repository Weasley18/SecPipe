"""GitHub, DefectDojo and HTTP client, against in-memory fakes and a local server."""

from __future__ import annotations

import datetime as dt
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from secpipe.aggregator.models import Severity
from secpipe.http import HttpError, check_url, request_json
from secpipe.reporters.defectdojo import import_reports
from secpipe.reporters.github import GitHubClient
from secpipe.tests.conftest import copy_reports, make_finding


class FakeGitHub:
    """Minimal in-memory GitHub REST API for comments and issues."""

    def __init__(self) -> None:
        self.comments: dict[int, dict[str, Any]] = {}
        self.issues: dict[int, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self._next = 100

    def __call__(self, method: str, url: str, body: Any = None, headers: dict[str, str] | None = None) -> Any:
        assert headers and headers["Authorization"] == "Bearer t0ken"
        path = url.split("https://api.github.com", 1)[1]
        self.calls.append((method, path))
        route, _, query = path.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        page = int(params.get("page", "1"))
        rest = route.strip("/").split("/")[3:]  # after repos/<owner>/<repo>
        if rest[:1] != ["issues"]:
            raise AssertionError(f"unexpected {method} {path}")
        if len(rest) == 1 and method == "GET":
            state = params.get("state", "open")
            items = [i for i in self.issues.values() if state == "all" or i["state"] == "open"]
            return items if page == 1 else []
        if len(rest) == 1 and method == "POST":
            self._next += 1
            issue = {
                "number": self._next,
                "title": body["title"],
                "body": body["body"],
                "labels": [{"name": n} for n in body["labels"]],
                "state": "open",
                "created_at": "2026-08-01T00:00:00Z",
            }
            self.issues[self._next] = issue
            return issue
        if rest[1] == "comments" and method == "PATCH":
            self.comments[int(rest[2])]["body"] = body["body"]
            return {}
        number = int(rest[1])
        if len(rest) == 3 and rest[2] == "comments" and method == "GET":
            return list(self.comments.values()) if page == 1 else []
        if len(rest) == 3 and rest[2] == "comments" and method == "POST":
            if number in self.issues:
                self.issues[number].setdefault("comments", []).append(body["body"])
                return {}
            self._next += 1
            self.comments[self._next] = {"id": self._next, "body": body["body"]}
            return self.comments[self._next]
        if len(rest) == 3 and rest[2] == "labels" and method == "POST":
            self.issues[number]["labels"] += [{"name": n} for n in body["labels"]]
            return {}
        if len(rest) == 2 and method == "PATCH":
            self.issues[number].update(body)
            if body.get("state") == "closed":
                self.issues[number]["closed_at"] = "2026-09-20T00:00:00Z"
            return {}
        raise AssertionError(f"unexpected {method} {path}")


@pytest.fixture
def gh() -> FakeGitHub:
    return FakeGitHub()


def client(gh: FakeGitHub) -> GitHubClient:
    return GitHubClient("t0ken", "Weasley18/SecPipe", request=gh)


def test_sticky_comment_created_then_updated(gh: FakeGitHub) -> None:
    c = client(gh)
    assert c.upsert_comment(7, "<!-- m -->\nfirst", "<!-- m -->")[0] == "created"
    action, cid = c.upsert_comment(7, "<!-- m -->\nsecond", "<!-- m -->")
    assert action == "updated" and gh.comments[cid]["body"].endswith("second")
    assert len(gh.comments) == 1


def test_issue_sync_lifecycle(gh: FakeGitHub) -> None:
    c = client(gh)
    today = dt.date(2026, 9, 26)
    high = make_finding(decision="block", severity=Severity.HIGH, due_date="2026-09-01", first_seen="2026-08-01")
    critical = make_finding(
        rule_id="kev",
        decision="warn",
        severity=Severity.CRITICAL,
        fix_available=False,
        category="sca",
        package="x",
    )
    medium = make_finding(rule_id="med", decision="block", severity=Severity.MEDIUM)
    os_nofix = [
        make_finding(
            rule_id=f"CVE-2026-{i}",
            cve=f"CVE-2026-{i}",
            category="container",
            pkg_type="os",
            fix_available=False,
            decision="warn",
            severity=Severity.HIGH,
            location=f"libx@{i}",
            file=None,
            line=None,
        )
        for i in range(5)
    ]
    report = c.sync_issues(
        [high, critical, medium, *os_nofix], sha="abc123", branch="main", today=today, run_url="https://run"
    )
    assert len(report.opened) == 3, "two findings + one OS rollup; medium is below the Issue threshold"
    titles = {i["title"] for i in gh.issues.values()}
    assert any("5 unfixed high/critical OS CVEs" in t for t in titles)
    first = next(i for i in gh.issues.values() if high.fingerprint in i["body"])
    labels = {label["name"] for label in first["labels"]}
    assert {"security", "secpipe", "sev:high", "tool:semgrep", "sla-breached"} <= labels
    nofix = next(i for i in gh.issues.values() if critical.fingerprint in i["body"])
    assert "no-fix-available" in {label["name"] for label in nofix["labels"]}

    again = c.sync_issues([high, critical, *os_nofix[:2]], sha="def456", branch="main", today=today)
    assert again.opened == [] and len(again.updated) == 1, "no duplicates; rollup updated in place"

    closed = c.sync_issues([critical], sha="fff999", branch="main", today=today)
    assert len(closed.closed) == 2
    done = next(i for i in gh.issues.values() if high.fingerprint in i["body"])
    assert done["state"] == "closed" and done["comments"][0].startswith("Fixed in fff999")
    names = {m[0] for m in closed.metrics}
    assert {"secpipe_issue_age_days", "secpipe_mttr_days", "secpipe_sla_breached_issues"} <= names


def test_issue_cap(gh: FakeGitHub) -> None:
    findings = [make_finding(rule_id=f"r{i}", decision="block") for i in range(5)]
    report = client(gh).sync_issues(findings, sha="a", branch="main", today=dt.date(2026, 9, 26), max_new=2)
    assert len(report.opened) == 2 and report.skipped == 3


def test_defectdojo_import(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path, "gitleaks.sarif", "bandit.json", "licenses.json", "trivy-image.json")
    sent: list[tuple[str, bytes, dict[str, str]]] = []

    def post(url: str, body: bytes, headers: dict[str, str]) -> int:
        sent.append((url, body, headers))
        return 500 if b"Trivy Scan" in body else 201

    report = import_reports(
        reports, url="https://dojo.example", token="t", engagement=3, commit="abc", branch="main", post=post
    )
    assert sorted(report.imported) == ["bandit.json", "gitleaks.sarif"]
    assert report.skipped == ["licenses.json"] and report.failed == ["trivy-image.json"]
    url, body, headers = sent[0]
    assert url == "https://dojo.example/api/v2/import-scan/"
    assert headers["Authorization"] == "Token t" and b'name="engagement"\r\n\r\n3' in body
    assert b'name="commit_hash"' in body


# ----------------------------------------------------------------------- http
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            self._send(200, b'{"hello": "world"}')
        elif self.path == "/empty":
            self._send(200, b"")
        elif self.path == "/garbage":
            self._send(200, b"<html>")
        else:
            self._send(404, b'{"message": "nope"}')

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self._send(200, json.dumps({"echo": json.loads(self.rfile.read(length))}).encode())

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


@pytest.fixture
def server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_request_json(server: str) -> None:
    assert request_json("GET", f"{server}/ok") == {"hello": "world"}
    assert request_json("GET", f"{server}/empty") is None
    assert request_json("POST", f"{server}/echo", body={"a": 1}) == {"echo": {"a": 1}}
    with pytest.raises(HttpError) as err:
        request_json("GET", f"{server}/missing")
    assert err.value.status == 404 and "nope" in err.value.body
    with pytest.raises(HttpError, match="invalid JSON"):
        request_json("GET", f"{server}/garbage")
    with pytest.raises(HttpError):
        request_json("GET", "http://localhost:1/unreachable", timeout=1)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "http://example.com/", "gopher://a"])
def test_check_url_rejects_unsafe_schemes(url: str) -> None:
    with pytest.raises(HttpError, match="non-HTTPS"):
        check_url(url)


def test_check_url_allows_https_and_cluster_services() -> None:
    check_url("https://api.first.org/data")
    check_url("http://loki.monitoring.svc:3100/x")
    check_url("http://alertmanager.monitoring.svc.cluster.local:9093")
    check_url("http://127.0.0.1:8080/")
