from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from secpipe.aggregator.gate import GateOptions, GateResult, run_gate
from secpipe.aggregator.models import Severity
from secpipe.reporters import html, jsonout, markdown, prometheus, sarif
from secpipe.tests.conftest import POLICY, TODAY, VULNERABLE_REPORTS, copy_reports, make_finding


@pytest.fixture
def vulnerable(tmp_path: Path) -> GateResult:
    reports = copy_reports(tmp_path / "reports", *VULNERABLE_REPORTS)
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "requirements.txt").write_text("fastapi==1.0\npyyaml==5.3.1\nPyJWT[crypto]==2.3.0\n")
    (src / "app" / "Dockerfile").write_text("FROM python:3.11-bullseye\n")
    return run_gate(
        GateOptions(
            reports=reports,
            policy=POLICY,
            expect=["gitleaks"],
            branch="main",
            event="pull_request",
            stage="gate-2",
            offline=True,
            today=TODAY,
            source_root=src,
            repository="Weasley18/SecPipe",
            commit="0123456789abcdef0123456789abcdef01234567",
            run_url="https://github.com/Weasley18/SecPipe/actions/runs/1",
        )
    )


def test_comment_layout(vulnerable: GateResult) -> None:
    body = markdown.render_comment(vulnerable)
    assert body.startswith(markdown.MARKER)
    assert re.search(r"## SecPipe: BLOCKED \(\d+ critical, \d+ high, \d+ medium new\)", body)
    assert "| Stage | Result | New | Existing | Fixed |" in body
    assert "| Secrets | **fail** |" in body
    assert "| DAST | skipped | - | - | - |" in body, "gate-2 without ZAP reports shows DAST skipped"
    assert "### Blocking findings" in body
    assert "OS package CVEs across" in body, "OS CVEs are one summary row"
    assert "<details><summary>Warnings" in body
    assert "raw results -> " in body
    assert "Suppressions this PR: 0 of 3 allowed. Policy: `policy.yaml@" in body
    assert (
        "https://github.com/Weasley18/SecPipe/blob/0123456789abcdef0123456789abcdef01234567/app/src/secnotes/auth.py#L"
        in body
    )
    assert len(body) < markdown.MAX_CHARS


def test_blocking_rows_are_ordered_by_stage(vulnerable: GateResult) -> None:
    body = markdown.render_comment(vulnerable)
    table = body.split("### Blocking findings", 1)[1].split("<details>", 1)[0]
    tools = [line.split("|")[2].strip() for line in table.splitlines() if line.startswith("| ") and "Sev" not in line]
    assert tools[0] == "gitleaks"
    assert tools.index("semgrep") < tools.index("pip-audit" if "pip-audit" in tools else "trivy")


def test_summary_is_expanded(vulnerable: GateResult) -> None:
    summary = markdown.render_summary(vulnerable)
    assert markdown.MARKER not in summary
    assert "<details>" not in summary and "### Scanners" in summary


def test_comment_for_pass_and_error() -> None:
    from secpipe.tests.test_gate import options

    passing = run_gate(options(Path("/nonexistent"), expect=[]))
    body = markdown.render_comment(passing)
    assert "## SecPipe: ERROR (failed closed" in body and "### Failed closed" in body


def test_cells_are_escaped_and_long_comments_truncated(vulnerable: GateResult) -> None:
    assert markdown._cell("a|b\nc") == "a\\|b c"
    assert markdown._fit("x" * (markdown.MAX_CHARS + 10)).endswith("see the HTML report artifact for everything._\n")


def test_sarif(vulnerable: GateResult) -> None:
    log = sarif.render(vulnerable)
    assert log["version"] == "2.1.0" and len(log["runs"]) == 1
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecPipe"
    results = run["results"]
    assert results and all("secpipe/v1" in r["partialFingerprints"] for r in results)
    assert all(r["level"] in {"error", "warning"} for r in results)
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert "app/requirements.txt" in uris, "dependency findings anchor to the manifest"
    assert "app/Dockerfile" in uris
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in results} <= rule_ids
    assert not any("image:" in u for u in uris)
    pyjwt = next(r for r in results if "pyjwt" in r["message"]["text"].lower())
    assert pyjwt["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_html_escapes(vulnerable: GateResult) -> None:
    vulnerable.findings[0].title = "<script>alert(1)</script>"
    page = html.render(vulnerable)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "SecPipe security gate" in page


def test_prometheus_exposition(vulnerable: GateResult) -> None:
    text = prometheus.render(vulnerable)
    assert "# TYPE secpipe_findings gauge" in text
    assert 'secpipe_gate_result{branch="main",gate="gate-2"} 0' in text
    assert re.search(r'secpipe_findings\{branch="main",category="secret",severity="critical",status="new"\} \d+', text)
    assert 'secpipe_sla_days{severity="critical"} 7' in text
    for line in text.splitlines():
        assert line.startswith("#") or re.match(r"^[a-z_]+(\{.*\})? -?[\d.e+]+$", line), line
    record = prometheus.history_record(vulnerable)
    assert record["branch"] == "main" and record["outcome"] == "block" and record["samples"]
    assert prometheus._escape('a"b\\c\n') == 'a\\"b\\\\c\\n'


def test_findings_document(vulnerable: GateResult, tmp_path: Path) -> None:
    doc = jsonout.findings_document(vulnerable)
    assert doc["schema"] == "secpipe/findings/v1"
    path = jsonout.write(tmp_path / "f.json", doc)
    assert json.loads(path.read_text())["meta"]["stage"] == "gate-2"


def test_badges_and_fix_column() -> None:
    kev = make_finding(
        in_kev=True, epss=0.42, also_reported_by=["bandit"], category="sca", package="x", fix_version="2.0"
    )
    assert (
        "KEV" in markdown._badges(kev) and "EPSS 0.42" in markdown._badges(kev) and "+bandit" in markdown._badges(kev)
    )
    assert markdown._fix(kev) == ">= 2.0"
    assert markdown._fix(make_finding(category="secret")) == "Rotate + remove"
    assert markdown._fix(make_finding(fix_available=False)) == "no fix yet"
    assert markdown._fix(make_finding(help_url="https://x")) == "[guide](https://x)"
    assert markdown._fix(make_finding()) == "-"
    os_rows: list[Any] = [
        make_finding(pkg_type="os", package=f"p{i}", severity=Severity.HIGH, fix_available=False) for i in range(3)
    ]
    assert "3 OS package CVEs across 3 packages" in markdown._os_summary_row(os_rows)
