from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
import yaml

from secpipe.aggregator.models import LicenceRecord, Severity
from secpipe.aggregator.policy import (
    APPROVAL_LABEL,
    Policy,
    PolicyError,
    evaluate,
    evaluate_licences,
    normalise_licence,
    validate,
)
from secpipe.aggregator.suppressions import scan, unjustified_findings
from secpipe.tests.conftest import POLICY, TODAY, make_finding


def policy(**extra: Any) -> Policy:
    data: dict[str, Any] = yaml.safe_load(POLICY.read_text())
    data.update(extra)
    return Policy.from_dict(data)


def decide(findings: list[Any], pol: Policy | None = None, **kw: Any):  # type: ignore[no-untyped-def]
    options: dict[str, Any] = {"branch": "feature/x", "event": "pull_request", "today": TODAY}
    options.update(kw)
    return evaluate(findings, pol or policy(), **options)


# ------------------------------------------------------------------ validation
def test_repository_policy_is_valid() -> None:
    loaded = Policy.load(POLICY)
    assert loaded.digest and loaded.source == "policy.yaml"
    assert loaded.rules_for("main").block_at_or_above == Severity.MEDIUM
    assert loaded.rules_for("feature/login").block_at_or_above == Severity.HIGH
    assert loaded.rules_for(None) == loaded.defaults


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda d: d["defaults"].update(block_at_or_abov="high"), "Additional properties"),
        (lambda d: d["defaults"].update(block_at_or_above="severe"), "is not one of"),
        (
            lambda d: d.update(
                exceptions=[{"fingerprint": "abc", "reason": "x", "owner": "@me", "expires": "2026-01-01"}]
            ),
            "does not match",
        ),
        (
            lambda d: d.update(
                exceptions=[{"fingerprint": "0123456789abcdef", "owner": "@me", "expires": "2026-01-01"}]
            ),
            "'reason' is a required property",
        ),
        (
            lambda d: d.update(
                exceptions=[
                    {
                        "fingerprint": "0123456789abcdef",
                        "reason": "long enough reason",
                        "owner": "@me",
                        "expires": "31/12/2026",
                    }
                ]
            ),
            "is not a 'date'",
        ),
        (lambda d: d.update(version=2), "was expected"),
        (lambda d: d["defaults"].update(warn_at_or_above="critical"), "warn_at_or_above must not be above"),
    ],
)
def test_schema_rejects_typos_and_incomplete_exceptions(mutation: Any, message: str) -> None:
    data = yaml.safe_load(POLICY.read_text())
    mutation(data)
    with pytest.raises(PolicyError, match=message):
        validate(data)


def test_load_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        Policy.load(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [1\n")
    with pytest.raises(PolicyError, match="not valid YAML"):
        Policy.load(bad)
    dated = tmp_path / "dated.yaml"
    dated.write_text(
        "version: 1\ndefaults: {block_at_or_above: high, warn_at_or_above: low}\n"
        "exceptions:\n  - rule: B608\n    path: 'app/*'\n    reason: reviewed and parameterised\n    owner: '@Weasley18'\n    expires: 2026-12-31\n"
    )
    assert Policy.load(dated).exceptions[0].expires == dt.date(2026, 12, 31)


# ------------------------------------------------------------------- decisions
def test_thresholds_and_categories() -> None:
    findings = [
        make_finding(severity=Severity.HIGH),
        make_finding(rule_id="m", severity=Severity.MEDIUM),
        make_finding(rule_id="l", severity=Severity.LOW),
        make_finding(rule_id="s", category="secret", severity=Severity.LOW, status="existing"),
    ]
    result = decide(findings)
    assert [f.decision for f in findings] == ["block", "warn", "info", "block"]
    assert "always blocks" in findings[3].reasons[0]
    assert not result.passed and len(result.blocking) == 2


def test_main_branch_is_stricter() -> None:
    finding = make_finding(severity=Severity.MEDIUM)
    decide([finding], branch="main")
    assert finding.decision == "block"


def test_only_new_findings_block_prs_but_not_pushes() -> None:
    finding = make_finding(status="existing")
    decide([finding])
    assert finding.decision == "warn" and "base branch" in finding.reasons[0]
    decide([finding], event="push")
    assert finding.decision == "block"


def test_no_fix_available_warns() -> None:
    finding = make_finding(category="container", pkg_type="os", fix_available=False)
    decide([finding])
    assert finding.decision == "warn" and "no fix" in finding.reasons[0]
    decide(
        [finding],
        pol=policy(defaults={"block_at_or_above": "high", "warn_at_or_above": "medium", "no_fix_available": "block"}),
    )
    assert finding.decision == "block"


def test_epss_bump_and_kev() -> None:
    bumped = make_finding(severity=Severity.MEDIUM, epss=0.5)
    kev = make_finding(rule_id="k", severity=Severity.LOW, in_kev=True, fix_available=False)
    decide([bumped, kev])
    assert bumped.severity == Severity.HIGH and bumped.decision == "block"
    assert "EPSS 0.500 > 0.1" in bumped.severity_reasons[0]
    assert kev.severity == Severity.CRITICAL and kev.decision == "block", "KEV blocks even without a fix"


def test_severity_overrides() -> None:
    finding = make_finding(rule_id="secnotes-jwt-verification-disabled", severity=Severity.HIGH)
    decide([finding])
    assert finding.severity == Severity.CRITICAL and "policy override" in finding.severity_reasons[0]


def test_exceptions_accept_expire_and_warn() -> None:
    target = make_finding()
    exceptions = [
        {
            "fingerprint": target.fingerprint,
            "reason": "accepted for the demo",
            "owner": "@Weasley18",
            "expires": "2026-10-01",
        },
        {
            "rule": "never-matches",
            "reason": "stale exception entry",
            "owner": "@Weasley18",
            "expires": "2027-01-01",
        },
        {
            "rule": "B105",
            "path": "app/*",
            "reason": "expired entry here",
            "owner": "@Weasley18",
            "expires": "2026-09-01",
        },
    ]
    result = decide([target], pol=policy(exceptions=exceptions))
    assert target.decision == "excepted" and target.exception is not None
    assert any("expired on 2026-09-01" in e for e in result.gate_errors), "an expired exception fails the gate"
    assert any("expires on 2026-10-01" in w for w in result.warnings)
    assert any("matched no finding" in w for w in result.warnings)
    assert not result.passed


def test_rule_and_path_exception() -> None:
    finding = make_finding(tool="bandit", rule_id="B608", file="app/src/n.py", location="app/src/n.py:5")
    other = make_finding(tool="bandit", rule_id="B608", file="lib/n.py", location="lib/n.py:5")
    exc = [
        {
            "rule": "B608",
            "path": "app/*",
            "reason": "reviewed: bound params",
            "owner": "@Weasley18",
            "expires": "2027-01-01",
        }
    ]
    decide([finding, other], pol=policy(exceptions=exc))
    assert (finding.decision, other.decision) == ("excepted", "block")


def test_tool_scoped_exception() -> None:
    # Grype runs only in the nightly scan. An exception scoped to it must not
    # cover another tool's finding, and must not tell every run where Grype did
    # not run to remove it; where Grype ran and nothing matched, it still does.
    location = {"category": "container", "rule_id": "CVE-2026-82049", "file": None, "location": "python@3.12.14"}
    grype = make_finding(tool="grype", **location)
    trivy = make_finding(tool="trivy", **location)
    exc = [
        {
            "rule": "CVE-2026-82049",
            "path": "python@3.12.*",
            "tool": "grype",
            "reason": "tarfile extraction is not reachable",
            "owner": "@Weasley18",
            "expires": "2027-01-01",
        }
    ]
    pol = policy(exceptions=exc)
    decide([grype, trivy], pol=pol)
    assert (grype.decision, trivy.decision) == ("excepted", "block")
    assert grype.exception is not None and grype.exception["tool"] == "grype"
    quiet = decide([], pol=pol, tools_run=frozenset({"semgrep", "trivy"}))
    assert not any("matched no finding" in w for w in quiet.warnings)
    stale = decide([], pol=pol, tools_run=frozenset({"grype"}))
    assert any("grype:CVE-2026-82049@python@3.12.* matched no finding" in w for w in stale.warnings)


def test_suppression_cap_and_approval_label() -> None:
    result = decide([], new_suppressions=4)
    assert result.suppression_cap_exceeded and not result.passed
    approved = decide([], new_suppressions=4, labels=(APPROVAL_LABEL,))
    assert approved.passed and any("approved" in w for w in approved.warnings)
    assert decide([], new_suppressions=9, event="push").passed, "the cap is per pull request"


# --------------------------------------------------------------------- licences
@pytest.mark.parametrize(
    ("licence", "rule"),
    [
        ("GNU Affero General Public License v3", "licence-denied:AGPL-3.0"),
        ("AGPL-3.0-only", "licence-denied:AGPL-3.0"),
        ("SSPL-1.0", "licence-denied:SSPL-1.0"),
        ("GPL-3.0 AND MIT", "licence-denied:GPL-3.0"),
        ("UNKNOWN", "licence-unknown"),
        ("Artistic-2.0", "licence-not-allowed:Artistic-2.0"),
    ],
)
def test_licence_violations(licence: str, rule: str) -> None:
    findings = evaluate_licences([LicenceRecord("pkg", "1.0", licence, "pip-licenses")], policy())
    assert [f.rule_id for f in findings] == [rule]


@pytest.mark.parametrize(
    "licence", ["MIT License", "Apache-2.0 OR BSD-2-Clause", "GPL-3.0 OR MIT", "LGPL-3.0-only", "BSD License"]
)
def test_licence_allowed(licence: str) -> None:
    assert evaluate_licences([LicenceRecord("pkg", "1.0", licence, "pip-licenses")], policy()) == []


def test_denied_licence_blocks_and_unknown_warns() -> None:
    records = [
        LicenceRecord("evil", "1", "AGPL-3.0", "snyk"),
        LicenceRecord("mystery", "2", "UNKNOWN", "pip-licenses"),
    ]
    findings = evaluate_licences(records, policy())
    decide(findings, branch="main")
    assert [(f.rule_id, f.decision) for f in findings] == [
        ("licence-denied:AGPL-3.0", "block"),
        ("licence-unknown", "warn"),
    ]
    assert normalise_licence("Mozilla Public License 2.0 (MPL 2.0)") == "MPL-2.0"
    assert normalise_licence("GPL-2.0+") == "GPL-2.0"


# ------------------------------------------------------------------ suppressions
def test_suppression_inventory(tmp_path: Path) -> None:
    src = tmp_path / "app"
    src.mkdir()
    (src / "a.py").write_text(
        "x = q  # nosec B608 -- only bound parameters reach this query\n"
        "y = 1  # nosec\n"
        "# justification: legacy endpoint kept for the migration\n"
        "z = eval(s)  # nosemgrep: python.lang.eval\n"
    )
    (tmp_path / "main.tf").write_text(
        'resource "x" "y" { # checkov:skip=CKV_AWS_18:access logs go to the org trail\n}\n'
    )
    (tmp_path / "Dockerfile").write_text("# hadolint ignore=DL3008\nRUN apt-get install -y curl\n")
    (tmp_path / "k8s.yaml").write_text("annotations:\n  checkov.io/skip1: CKV_K8S_43=digest pinned by the overlay\n")
    fixtures = tmp_path / "secpipe" / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "f.py").write_text("x = 1  # nosec\n")
    found = {(s.file, s.kind): s for s in scan(tmp_path)}
    assert set(found) == {
        ("app/a.py", "nosec"),
        ("app/a.py", "nosemgrep"),
        ("main.tf", "checkov-skip"),
        ("Dockerfile", "hadolint-ignore"),
        ("k8s.yaml", "checkov-skip-annotation"),
    }
    items = scan(tmp_path)
    nosec = [s for s in items if s.kind == "nosec"]
    assert [s.justified for s in nosec] == [True, False]
    assert nosec[0].rules == ("B608",)
    assert found[("app/a.py", "nosemgrep")].justification.startswith("legacy endpoint")
    assert found[("main.tf", "checkov-skip")].rules == ("CKV_AWS_18",)
    assert not found[("Dockerfile", "hadolint-ignore")].justified
    unjustified = unjustified_findings(items)
    assert {f.location for f in unjustified} == {"app/a.py:2", "Dockerfile:1"}
    assert all(f.rule_id == "secpipe-unjustified-suppression" and f.severity == Severity.MEDIUM for f in unjustified)
    assert len({s.key for s in items}) == len(items)
    assert nosec[0].to_dict()["justified"] is True
