from __future__ import annotations

import datetime as dt
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from secpipe.aggregator import cli
from secpipe.correlator.cli import parse_duration
from secpipe.correlator.clients import AlertmanagerClient, LokiClient, explore_url, to_alertmanager
from secpipe.correlator.events import from_line, from_record, target_class
from secpipe.correlator.rules import evaluate
from secpipe.exporter import HistorySource, backfill, latest_samples, make_handler, parse_history
from secpipe.tests.conftest import FIXTURES, POLICY, VULNERABLE_REPORTS, copy_reports

DRILL = FIXTURES / "correlator" / "drill-events.jsonl"
STUFFING = FIXTURES / "correlator" / "stuffing-events.jsonl"


def load(path: Path) -> list[Any]:
    events = [from_record(json.loads(line)) for line in path.read_text().splitlines() if line.strip()]
    return sorted((e for e in events if e), key=lambda e: e.ts)


# ---------------------------------------------------------------- correlator
def test_recorded_drill_triggers_expected_rules() -> None:
    events = load(DRILL)
    now = max(e.ts for e in events) + dt.timedelta(minutes=1)
    alerts = {a.rule: a for a in evaluate(events, now)}
    assert set(alerts) == {
        "brute_force",
        "brute_force_then_success",
        "ssrf_probe",
        "post_exploitation_chain",
        "token_misuse",
    }
    assert alerts["brute_force"].labels == {"source_ip": "203.0.113.66"} and alerts["brute_force"].evidence == 15
    assert alerts["brute_force_then_success"].severity == "critical"
    assert alerts["brute_force_then_success"].labels["username"] == "alice"
    assert "169.254.169.254" in alerts["ssrf_probe"].summary
    assert alerts["post_exploitation_chain"].labels["pod"] == "secnotes-api-6d4b9c7f8d-x7k2p"
    assert "198.51.100.23" in alerts["token_misuse"].description


def test_rate_limit_prevents_credential_stuffing_but_is_still_brute_force() -> None:
    """Only three usernames reached the app before the limiter; that is not stuffing."""
    assert "credential_stuffing" not in {a.rule for a in evaluate(load(DRILL), dt.datetime.now(dt.UTC))}


def test_credential_stuffing_without_rate_limit() -> None:
    alerts = evaluate(load(STUFFING), dt.datetime.now(dt.UTC), ["credential_stuffing", "brute_force"])
    assert [(a.rule, a.evidence) for a in alerts] == [("credential_stuffing", 8)]


def test_ingress_logs_detect_brute_force_without_app_logging() -> None:
    """The vulnerable app logs no failed logins (flaw #11); ingress logs still show them."""
    base = dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.UTC)
    lines = [
        json.dumps(
            {
                "time": (base + dt.timedelta(seconds=i)).isoformat(),
                "remote_addr": "10.9.9.9",
                "request_uri": "/auth/login",
                "status": 401 if i < 11 else 200,
            }
        )
        for i in range(12)
    ]
    events = [from_line(line, {"namespace": "ingress-nginx"}) for line in lines]
    rules = {a.rule for a in evaluate([e for e in events if e], base + dt.timedelta(minutes=1))}
    assert {"brute_force", "brute_force_then_success"} <= rules


def test_traefik_access_logs_feed_the_rules() -> None:
    base = dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.UTC)
    lines = [
        json.dumps(
            {
                "StartUTC": (base + dt.timedelta(seconds=i)).isoformat(),
                "ClientHost": "10.8.8.8",
                "RequestMethod": "POST",
                "RequestPath": "/auth/login",
                "DownstreamStatus": 401 if i < 11 else 200,
            }
        )
        for i in range(12)
    ]
    lines.append(
        json.dumps(
            {
                "StartUTC": base.isoformat(),
                "ClientHost": "10.8.8.8",
                "RequestPath": "/preview?url=http://169.254.169.254/latest/meta-data/",
                "DownstreamStatus": 400,
            }
        )
    )
    events = [e for e in (from_line(line, {"namespace": "ingress", "app": "traefik"}) for line in lines) if e]
    assert {e.source for e in events} == {"ingress"}
    assert events[0].ip == "10.8.8.8" and events[0].status == 401 and events[0].path == "/auth/login"
    rules = {a.rule for a in evaluate(events, base + dt.timedelta(minutes=1))}
    assert {"brute_force", "brute_force_then_success", "ssrf_probe"} <= rules


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("169.254.169.254", "link_local"),
        ("127.0.0.1", "loopback"),
        ("10.1.1.1", "private"),
        ("postgres", "internal_name"),
        ("api.secnotes.svc.cluster.local", "internal_name"),
        ("[::ffff:127.0.0.1]", "loopback"),
        ("example.com", "public"),
        ("8.8.8.8", "public"),
        ("100.64.1.1", "private"),
    ],
)
def test_target_class(host: str, kind: str) -> None:
    assert target_class(host) == kind


def test_event_parsing_edge_cases() -> None:
    assert from_line("not json") is None
    assert from_line("[1, 2]") is None
    event = from_line('{"msg": "x"}', {}, "1758888000000000000")
    assert event is not None and event.ts.year == 2025 and event.source == "app"
    audit = from_line('{"kind": "Event", "auditID": "1", "stageTimestamp": "2026-09-26T10:00:00Z"}')
    assert audit is not None and audit.source == "audit"
    bare = from_record({"event": "login_failed", "client_ip": "1.2.3.4", "ts": "2026-09-26T10:00:00+00:00"})
    assert bare is not None and bare.is_failed_login() and bare.ip == "1.2.3.4"


def test_loki_and_alertmanager_clients() -> None:
    calls: list[tuple[str, str, Any]] = []

    def fake(method: str, url: str, body: Any = None, headers: Any = None) -> Any:
        calls.append((method, url, body))
        if method == "GET":
            return {
                "data": {
                    "result": [
                        {
                            "stream": {"namespace": "secnotes", "pod": "p1"},
                            "values": [
                                ["1758888000000000000", '{"event": "login_failed", "client_ip": "1.1.1.1"}'],
                                ["1758888000000000001", "garbage"],
                                ["x"],
                            ],
                        }
                    ]
                }
            }
        return None

    now = dt.datetime(2026, 9, 26, tzinfo=dt.UTC)
    events = LokiClient("http://loki.monitoring.svc:3100/", request=fake, tenant="t1").query_range(
        '{namespace="secnotes"}', now - dt.timedelta(minutes=5), now
    )
    assert len(events) == 1 and events[0].pod == "p1"
    assert "query_range?query=%7Bnamespace%3D%22secnotes%22%7D" in calls[0][1]
    alert = evaluate(load(DRILL), now + dt.timedelta(days=1), ["ssrf_probe"])[0]
    payload = to_alertmanager(alert, now, "http://grafana:3000")
    assert payload["labels"]["alertname"] == "SecNotesSsrfProbe"
    assert payload["annotations"]["runbook_url"].endswith("container-compromise.md")
    assert "explore?left=" in payload["annotations"]["grafana_explore_url"]
    AlertmanagerClient("http://am.monitoring.svc:9093", request=fake).send([payload])
    AlertmanagerClient("http://am.monitoring.svc:9093", request=fake).send([])
    assert calls[-1][0] == "POST" and calls[-1][1].endswith("/api/v2/alerts")
    assert explore_url("http://g", None, None).startswith("http://g/explore?left=")


def test_parse_duration() -> None:
    assert parse_duration("35m") == dt.timedelta(minutes=35)
    assert parse_duration("2h") == dt.timedelta(hours=2)
    with pytest.raises(Exception, match="invalid duration"):
        parse_duration("soon")


# ----------------------------------------------------------------------- cli
def test_cli_gate_blocks_and_writes_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reports = copy_reports(tmp_path / "reports", *VULNERABLE_REPORTS)
    summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Weasley18/SecPipe")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    code = cli.main(
        [
            "gate",
            "--reports",
            str(reports),
            "--expect",
            "gitleaks,trivy",
            "--policy",
            str(POLICY),
            "--out",
            str(tmp_path / "out"),
            "--offline",
            "--stage",
            "gate-1",
            "--step-summary",
            "--today",
            "2026-09-26",
            "--source-root",
            str(tmp_path / "nosuchdir"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 1 and "secpipe gate-1: BLOCK" in out and "BLOCK CRITICAL" in out
    assert "## SecPipe: BLOCKED" in summary.read_text()
    data = json.loads((tmp_path / "out" / "gate-1.json").read_text())
    assert data["branch"] == "main" and data["run_url"] == "https://github.com/Weasley18/SecPipe/actions/runs/42"


def test_cli_gate_fail_closed_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(
        [
            "gate",
            "--reports",
            str(tmp_path),
            "--expect",
            "zap",
            "--policy",
            str(POLICY),
            "--out",
            str(tmp_path / "o"),
            "--offline",
        ]
    )
    assert code == 2 and "FAILED CLOSED" in capsys.readouterr().err


def test_cli_policy_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["policy", "validate", str(POLICY)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ndefaults: {block_at_or_above: high, warn_at_or_above: low, typo: 1}\n")
    assert cli.main(["policy", "validate", str(bad)]) == 2
    expired = tmp_path / "expired.yaml"
    expired.write_text(
        POLICY.read_text().replace(
            "exceptions: []",
            "exceptions:\n  - fingerprint: '0123456789abcdef'\n    reason: temporary acceptance\n    owner: '@Weasley18'\n    expires: 2020-01-01\n",
        )
    )
    assert cli.main(["policy", "validate", str(expired)]) == 1
    assert cli.main(["policy", "schema"]) == 0
    assert '"$schema"' in capsys.readouterr().out


def test_cli_github_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from secpipe.tests.test_integrations import FakeGitHub

    fake = FakeGitHub()
    import secpipe.reporters.github as github_module

    monkeypatch.setattr(github_module, "request_json", fake)
    monkeypatch.setattr(github_module.GitHubClient.__init__, "__defaults__", ("https://api.github.com", fake))
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Weasley18/SecPipe")
    body = tmp_path / "comment.md"
    body.write_text("<!-- secpipe:sticky -->\nhi")
    assert cli.main(["github", "comment", "--pr", "5", "--body", str(body)]) == 0
    findings = tmp_path / "findings.json"
    from secpipe.tests.conftest import make_finding

    findings.write_text(json.dumps({"findings": [make_finding(decision="block").to_dict()]}))
    metrics = tmp_path / "issue-metrics.json"
    assert (
        cli.main(
            [
                "github",
                "issues",
                "--findings",
                str(findings),
                "--sha",
                "abc",
                "--branch",
                "main",
                "--metrics-out",
                str(metrics),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "created comment" in out and "issues: 1 opened" in out
    assert json.loads(metrics.read_text())
    monkeypatch.delenv("GITHUB_TOKEN")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["github", "comment", "--pr", "5", "--body", str(body)])


def test_cli_metrics_and_exporter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    reports = copy_reports(tmp_path / "reports", *VULNERABLE_REPORTS)
    cli.main(
        [
            "gate",
            "--reports",
            str(reports),
            "--policy",
            str(POLICY),
            "--out",
            str(tmp_path / "out"),
            "--offline",
            "--branch",
            "main",
            "--stage",
            "gate-2",
        ]
    )
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps([{"name": "secpipe_issue_age_days", "labels": {"severity": "high"}, "value": 3}]))
    history = tmp_path / "metrics" / "history.jsonl"
    for _ in range(2):
        assert (
            cli.main(
                [
                    "metrics",
                    "append",
                    "--record",
                    str(tmp_path / "out" / "metrics.json"),
                    "--history",
                    str(history),
                    "--extra",
                    str(extra),
                    "--extra",
                    str(tmp_path / "missing.json"),
                ]
            )
            == 0
        )
    history.write_text(history.read_text() + "{torn line\n")
    records = parse_history(history.read_text())
    assert len(records) == 2
    samples = latest_samples(records)
    assert any(name == "secpipe_issue_age_days" for name, _, _ in samples)
    assert all(labels["branch"] == "main" for _, labels, _ in samples)
    capsys.readouterr()
    assert cli.main(["metrics", "backfill", "--history", str(history)]) == 0
    om = capsys.readouterr().out
    assert om.rstrip().endswith("# EOF") and "# TYPE secpipe_gate_result gauge" in om
    assert backfill("") == "# EOF\n"

    source = HistorySource(str(history), refresh=3600)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(source))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert "secpipe_exporter_up 1" in body and 'secpipe_gate_result{branch="main",gate="gate-2"} 0' in body
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/other")
    finally:
        srv.shutdown()
    broken = HistorySource(str(tmp_path / "nope.jsonl"))
    assert broken.samples() == [] and broken.last_error


def test_cli_correlate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "alerts.json"
    code = cli.main(
        [
            "correlate",
            "--from-file",
            str(DRILL),
            "--now",
            "2026-09-26T18:05:00",
            "--dry-run",
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert "5 alerts" in capsys.readouterr().out
    assert len(json.loads(out.read_text())) == 5
    code = cli.main(["correlate", "--loki-url", "http://127.0.0.1:1", "--now", "2026-09-26T18:05:00+00:00"])
    assert code == 2


def test_cli_defectdojo_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["defectdojo", "--url", "https://dojo", "--engagement", "1"])
