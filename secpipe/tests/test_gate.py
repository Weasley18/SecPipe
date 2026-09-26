"""End-to-end gate runs on real scanner reports, including every fail-closed path."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from secpipe.aggregator.enrich import ThreatIntel
from secpipe.aggregator.gate import (
    EXIT_BLOCK,
    EXIT_ERROR,
    EXIT_PASS,
    GateOptions,
    check_expected,
    collect,
    run_gate,
)
from secpipe.reporters import write_outputs
from secpipe.tests.conftest import POLICY, TODAY, VULNERABLE_REPORTS, FakeFetcher, copy_reports

EXPECT = ["gitleaks", "semgrep", "bandit", "pip-audit", "osv", "hadolint", "trivy", "checkov"]


def options(reports: Path, **kw: Any) -> GateOptions:
    values: dict[str, Any] = {
        "reports": reports,
        "policy": POLICY,
        "expect": EXPECT,
        "branch": "main",
        "event": "pull_request",
        "stage": "gate-1",
        "offline": True,
        "today": TODAY,
    }
    values.update(kw)
    return GateOptions(**values)


def test_vulnerable_branch_is_blocked(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", *VULNERABLE_REPORTS)
    result = run_gate(options(reports))
    assert (result.outcome, result.exit_code) == ("block", EXIT_BLOCK)
    blocking_rules = {f.rule_id for f in result.blocking}
    for planted in (
        "aws-access-token",  # 1 secrets
        "secnotes-sqlalchemy-raw-sql",  # 2 SQLi
        "secnotes-possible-idor",  # 3 IDOR
        "secnotes-jwt-verification-disabled",  # 4 JWT
        "secnotes-unsafe-yaml-load",  # 5 YAML
        "secnotes-ssrf-user-url",  # 6 SSRF
        "B602",  # 7 shell=True
        "CVE-2020-14343",  # 9 PyYAML
        "container-eol-base-image",  # 12 EOL base
        "DL3020",  # 12 ADD
    ):
        assert planted in blocking_rules, planted
    assert result.stages["Secrets"].result == "fail"
    assert result.stages["DAST"].result == "pending"
    assert result.dedupe.raw > result.dedupe.unique
    assert all(f.status == "new" for f in result.findings)


def test_clean_reports_pass(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    for name in ("gitleaks.sarif", "semgrep.sarif", "hadolint.sarif"):
        data = json.loads((copy_reports(tmp_path / "src", name) / name).read_text())
        data["runs"][0]["results"] = []
        (reports / name).write_text(json.dumps(data))
    result = run_gate(options(reports, expect=["gitleaks", "semgrep", "hadolint"]))
    assert (result.outcome, result.exit_code) == ("pass", EXIT_PASS)
    assert result.stages["SCA"].result == "skipped"


def test_missing_expected_scanner_fails_closed(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", "gitleaks.sarif")
    result = run_gate(options(reports, expect=["gitleaks", "kubescape"]))
    assert (result.outcome, result.exit_code) == ("error", EXIT_ERROR)
    assert "kubescape: expected but no report" in result.tool_errors[0]


def test_errored_and_truncated_reports_fail_closed(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", "gitleaks.sarif", "bandit.json")
    meta = json.loads((reports / "gitleaks.meta.json").read_text())
    meta.update(status="error", reason="scanned 0 of 12 commits")
    (reports / "gitleaks.meta.json").write_text(json.dumps(meta))
    (reports / "bandit.json").write_text('{"results": [')
    result = run_gate(options(reports, expect=["gitleaks", "bandit"]))
    assert result.exit_code == EXIT_ERROR
    joined = " ".join(result.tool_errors)
    assert "scanned 0 of 12 commits" in joined and "truncated" in joined
    assert result.stages["Secrets"].result == "error"


def test_skipped_expected_scanner_fails_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "snyk.meta.json").write_text(
        json.dumps({"tool": "snyk", "status": "skipped", "reason": "SNYK_TOKEN not set"})
    )
    result = run_gate(options(reports, expect=["snyk"]))
    assert result.exit_code == EXIT_ERROR and "SNYK_TOKEN not set" in result.tool_errors[0]
    ok = run_gate(options(reports, expect=[]))
    assert ok.exit_code == EXIT_PASS, "an optional scanner that was skipped is fine when not expected"


def test_meta_says_written_but_report_missing(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "zap-api.meta.json").write_text(
        json.dumps({"tool": "zap-api", "report": "zap-api.json", "status": "ok"})
    )
    runs, _ = collect(reports)
    assert runs[0].status == "error" and "missing" in runs[0].errors[0]
    assert check_expected(["zap"], runs)


def test_invalid_policy_and_missing_reports_dir(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\ndefaults: {block_at_or_above: high}\n")
    result = run_gate(options(tmp_path / "nope", policy=bad, expect=[]))
    assert result.exit_code == EXIT_ERROR
    assert any("does not exist" in e for e in result.tool_errors)
    assert any("schema validation" in e for e in result.tool_errors)


def test_baseline_makes_existing_findings_non_blocking_on_prs(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", "semgrep.sarif", "bandit.json")
    first = run_gate(options(reports, expect=["semgrep", "bandit"], out=tmp_path / "out"))
    write_outputs(first, tmp_path / "out")
    second = run_gate(options(reports, expect=["semgrep", "bandit"], baseline=tmp_path / "out" / "findings.json"))
    assert all(f.status == "existing" for f in second.findings)
    assert second.exit_code == EXIT_PASS, "nothing new on the PR"
    pushed = run_gate(
        options(reports, expect=["semgrep", "bandit"], event="push", baseline=tmp_path / "out" / "findings.json")
    )
    assert pushed.exit_code == EXIT_BLOCK, "on main every finding counts"


def test_fixed_findings_are_reported(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", "bandit.json")
    base = run_gate(options(reports, expect=["bandit"]))
    write_outputs(base, tmp_path / "base")
    data = json.loads((reports / "bandit.json").read_text())
    data["results"] = data["results"][:3]
    (reports / "bandit.json").write_text(json.dumps(data))
    result = run_gate(options(reports, expect=["bandit"], baseline=tmp_path / "base" / "findings.json"))
    assert len(result.fixed) == 7
    assert result.stages["SAST"].fixed == 7


def test_enrichment_escalates_kev(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", "pip-audit.json")
    intel = ThreatIntel(tmp_path / "cache", fetch=FakeFetcher(kev=["CVE-2024-3651"], epss={"CVE-2024-3651": 0.3}))
    result = run_gate(options(reports, expect=["pip-audit"], offline=False, intel=intel, branch="feature"))
    idna = next(f for f in result.findings if f.cve == "CVE-2024-3651")
    assert idna.in_kev and idna.severity.label == "critical" and idna.decision == "block"
    assert result.enrichment.in_kev == 1


def test_suppression_inventory_through_gate(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1  # nosec\n" * 4)
    reports = copy_reports(tmp_path / "reports", "hadolint.sarif")
    result = run_gate(options(reports, expect=["hadolint"], source_root=src, branch="feature"))
    assert result.evaluation.suppression_cap_exceeded
    assert sum(1 for f in result.findings if f.rule_id == "secpipe-unjustified-suppression") == 4


def test_outputs_are_written(tmp_path: Path) -> None:
    reports = copy_reports(tmp_path / "reports", *VULNERABLE_REPORTS)
    shutil.copy(POLICY, tmp_path / "policy.yaml")
    result = run_gate(
        options(reports, repository="Weasley18/SecPipe", commit="a" * 40, run_url="https://example/run/1")
    )
    written = write_outputs(result, tmp_path / "out")
    names = {p.name for p in written}
    assert names == {
        "findings.json",
        "gate-1.json",
        "comment.md",
        "summary.md",
        "secpipe.sarif",
        "report.html",
        "metrics.prom",
        "metrics.json",
    }
    summary = json.loads((tmp_path / "out" / "gate-1.json").read_text())
    assert summary["outcome"] == "block" and summary["counts"]["blocking"] == len(result.blocking)
    assert summary["policy"]["rules"]["block_at_or_above"] == "medium"
