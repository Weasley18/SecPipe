"""Every parser against a real (or schema-faithful) report, plus empty,
truncated and wrong-format input, which must never raise."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secpipe.aggregator.models import Severity
from secpipe.aggregator.parsers import REGISTRY, parse_report, spec_for
from secpipe.aggregator.parsers.zap import normalise_path
from secpipe.tests.conftest import FIXTURES

ALL_FIXTURES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file() and p.suffix in {".json", ".sarif"})


def parse(name: str):  # type: ignore[no-untyped-def]
    result = parse_report(FIXTURES / name)
    assert result is not None, name
    assert result.ok, result.errors
    return result


@pytest.mark.parametrize("spec", REGISTRY, ids=lambda s: s.tool)
def test_empty_report_is_an_error_not_a_crash(tmp_path: Path, spec) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / spec.patterns[0].replace("*", "")
    path.write_text("")
    result = spec.parse(path)
    assert not result.ok
    assert "empty" in result.errors[0]
    assert result.findings == []


@pytest.mark.parametrize("spec", REGISTRY, ids=lambda s: s.tool)
def test_truncated_report_is_an_error_not_a_crash(tmp_path: Path, spec) -> None:  # type: ignore[no-untyped-def]
    source = next((FIXTURES / n for n in ALL_FIXTURES if spec_for(FIXTURES / n) is spec), None)
    content = source.read_text()[: len(source.read_text()) // 2] if source else '{"results": ['
    path = tmp_path / spec.patterns[0].replace("*", "")
    path.write_text(content)
    result = spec.parse(path)
    assert not result.ok
    assert "truncated" in result.errors[0]


@pytest.mark.parametrize("spec", REGISTRY, ids=lambda s: s.tool)
def test_wrong_format_is_an_error(tmp_path: Path, spec) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / spec.patterns[0].replace("*", "")
    path.write_text(json.dumps({"hello": "world"}) if spec.tool not in {"pip-licenses", "prowler"} else '{"x": 1}')
    result = spec.parse(path)
    assert not result.ok


def test_unreadable_report(tmp_path: Path) -> None:
    missing = tmp_path / "bandit.json"
    result = spec_for(missing).parse(missing)  # type: ignore[union-attr]
    assert "cannot read" in result.errors[0]


def test_registry_routing() -> None:
    assert spec_for(Path("reports/trivy-iac.json")).tool == "trivy"  # type: ignore[union-attr]
    assert spec_for(Path("checkov-k8s.json")).tool == "checkov"  # type: ignore[union-attr]
    for ignored in ("trivy-image.meta.json", "sbom.cdx.json", "secpipe.sarif", "notes.txt"):
        assert spec_for(Path(ignored)) is None
    assert parse_report(Path("rendered-k8s.yaml")) is None


def test_gitleaks() -> None:
    result = parse("gitleaks.sarif")
    assert len(result.findings) == 6
    assert {f.severity for f in result.findings} == {Severity.CRITICAL}
    assert all(f.category == "secret" and f.cwe == "CWE-798" for f in result.findings)
    history = next(f for f in result.findings if f.file == "app/.env")
    assert "in commit" in history.description
    assert {f.rule_id for f in result.findings} >= {
        "aws-access-token",
        "secnotes-api-token",
        "dockerfile-env-secret",
    }
    raw = (FIXTURES / "gitleaks.sarif").read_text()
    assert "AKIA" not in raw and "supersecret" not in raw


def test_semgrep() -> None:
    result = parse("semgrep.sarif")
    ids = {f.rule_id for f in result.findings}
    assert "secnotes-sqlalchemy-raw-sql" in ids
    assert not any(i.startswith("policy.") for i in ids), "config-path prefix must be stripped"
    jwt = next(f for f in result.findings if f.rule_id == "secnotes-jwt-verification-disabled")
    assert jwt.severity == Severity.HIGH
    assert jwt.cwe == "CWE-347"
    assert jwt.help_url and jwt.help_url.endswith("secnotes-jwt-verification-disabled.yaml")
    assert jwt.title.startswith("JWT decoded without signature verification")


def test_sarif_unsuccessful_run_and_suppressions(tmp_path: Path) -> None:
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [{"id": "r1", "defaultConfiguration": {"level": "note"}}],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": False,
                        "toolExecutionNotifications": [{"level": "error", "message": {"text": "rule parse error"}}],
                    }
                ],
                "results": [
                    {
                        "ruleIndex": 0,
                        "message": {"text": "m"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    },
                    {"ruleId": "r1", "suppressions": [{"kind": "inSource"}], "message": {"text": "s"}},
                ],
            }
        ]
    }
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(sarif))
    result = spec_for(path).parse(path)  # type: ignore[union-attr]
    assert "unsuccessful run" in result.errors[0]
    assert result.suppressed == 1
    assert result.findings[0].severity == Severity.LOW
    assert result.findings[0].rule_id == "r1"


def test_bandit_confidence_downgrade() -> None:
    result = parse("bandit.json")
    by_id = {(f.rule_id, f.line): f for f in result.findings}
    shell = next(f for f in result.findings if f.rule_id == "B602")
    assert shell.severity == Severity.HIGH and shell.cwe == "CWE-78"
    sql = next(f for f in result.findings if f.rule_id == "B608")
    assert sql.severity == Severity.LOW, "MEDIUM severity with LOW confidence is downgraded"
    assert sql.raw_severity == "medium/low"
    assert len(by_id) == 10
    assert all(f.file and f.file.startswith("app/src/") for f in result.findings)


def test_hadolint_and_zizmor() -> None:
    hadolint = parse("hadolint.sarif")
    assert {f.rule_id for f in hadolint.findings} == {"DL3064", "DL3020", "DL3042", "DL3025"}
    assert all(f.file == "app/Dockerfile" and f.category == "container" for f in hadolint.findings)
    add = next(f for f in hadolint.findings if f.rule_id == "DL3020")
    assert add.severity == Severity.HIGH
    zizmor = parse("zizmor.sarif")
    assert {f.rule_id for f in zizmor.findings} >= {"zizmor/template-injection", "zizmor/dangerous-triggers"}
    assert all(f.file == ".github/workflows/bad.yml" for f in zizmor.findings)


def test_pip_audit() -> None:
    result = parse("pip-audit.json")
    pyyaml = next(f for f in result.findings if f.package == "pyyaml")
    assert pyyaml.cve == "CVE-2020-14343"
    assert pyyaml.fix_version == "5.4"
    assert pyyaml.severity == Severity.MEDIUM and pyyaml.raw_severity == "unknown"
    assert "PYSEC-2021-142" in pyyaml.aliases
    assert result.raw_count > len(result.findings), "duplicate ids in the report are collapsed"


def test_osv() -> None:
    result = parse("osv.json")
    h11 = next(f for f in result.findings if f.package == "h11")
    assert h11.cve == "CVE-2025-43859"
    assert h11.severity == Severity.CRITICAL
    assert h11.fix_version == "0.16.0"
    assert h11.cvss and h11.cvss >= 9
    assert all(f.pkg_type == "pypi" for f in result.findings)


def test_osv_without_groups(tmp_path: Path) -> None:
    data = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "Foo_Bar", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-1",
                                "aliases": ["CVE-2024-1"],
                                "summary": "bad",
                                "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
                                "affected": [
                                    {
                                        "package": {"name": "foo-bar"},
                                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2"}]}],
                                    },
                                    {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    path = tmp_path / "osv.json"
    path.write_text(json.dumps(data))
    finding = spec_for(path).parse(path).findings[0]  # type: ignore[union-attr]
    assert (finding.package, finding.severity, finding.fix_version, finding.cwe) == (
        "foo-bar",
        Severity.MEDIUM,
        "1.2",
        "CWE-79",
    )


def test_snyk() -> None:
    result = parse("snyk.json")
    assert len(result.findings) == 2, "one finding per vulnerability, not per dependency path"
    pyyaml = next(f for f in result.findings if f.package == "pyyaml")
    assert pyyaml.direct is True and pyyaml.fix_available is True and pyyaml.cvss == 9.8
    assert result.licences[0].licence == "AGPL-3.0"
    pyjwt = next(f for f in result.findings if f.package == "pyjwt")
    assert pyjwt.cwe == "CWE-347"


def test_snyk_error_project(tmp_path: Path) -> None:
    path = tmp_path / "snyk.json"
    path.write_text(json.dumps([{"ok": False, "error": "Missing auth token"}]))
    assert "Missing auth token" in spec_for(path).parse(path).errors[0]  # type: ignore[union-attr]


def test_licences() -> None:
    result = parse("licenses.json")
    assert len(result.licences) == 33
    assert any(lic.licence == "MIT License" for lic in result.licences)


def test_trivy_image() -> None:
    result = parse("trivy-image.json")
    eol = next(f for f in result.findings if f.rule_id == "container-eol-base-image")
    assert "debian 11" in eol.title and eol.severity == Severity.HIGH
    pyyaml = next(f for f in result.findings if f.package == "pyyaml")
    assert pyyaml.category == "sca" and pyyaml.severity == Severity.CRITICAL and pyyaml.cvss == 9.8
    grouped = [f for f in result.findings if f.pkg_type == "os" and f.related_packages]
    assert grouped, "binary packages sharing a CVE and version collapse into one finding"
    assert result.raw_count > len(result.findings)
    secrets = [f for f in result.findings if f.category == "secret"]
    assert {f.location.split(":")[0] for f in secrets} >= {"image"}
    assert all(f.file is None for f in secrets)
    misconfig = [f for f in result.findings if f.rule_id == "DS-0002"]
    assert any("(image config)" in f.location for f in misconfig)
    assert all(f.category == "container" for f in misconfig)
    no_fix = [f for f in result.findings if f.pkg_type == "os" and not f.fix_version]
    assert no_fix and all(f.fix_available is False for f in no_fix)


def test_trivy_config_scan(tmp_path: Path) -> None:
    data = {
        "SchemaVersion": 2,
        "ArtifactName": "infra",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "modules/bucket/main.tf",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0086",
                        "Title": "S3 public ACL",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {"Resource": "aws_s3_bucket.this", "StartLine": 3},
                    },
                    {"ID": "AVD-AWS-0090", "Title": "Versioning", "Severity": "MEDIUM", "Status": "PASS"},
                ],
            },
            {
                "Target": "k8s/deploy.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "Misconfigurations": [
                    {
                        "ID": "KSV017",
                        "Title": "Privileged",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {"StartLine": 9},
                    }
                ],
            },
            {
                "Target": "config.py",
                "Class": "secret",
                "Secrets": [{"RuleID": "aws-access-key-id", "Title": "AWS", "Severity": "CRITICAL", "StartLine": 2}],
            },
        ],
    }
    path = tmp_path / "trivy-iac.json"
    path.write_text(json.dumps(data))
    result = spec_for(path).parse(path)  # type: ignore[union-attr]
    tf, k8s, secret = result.findings
    assert (tf.category, tf.location) == ("iac", "modules/bucket/main.tf:aws_s3_bucket.this")
    assert (k8s.category, k8s.location) == ("k8s", "k8s/deploy.yaml:9")
    assert (secret.category, secret.location) == ("secret", "config.py:2")
    assert result.raw_count == 3, "passed checks are not raw results"


def test_trivy_unknown_severity_uses_cvss(tmp_path: Path) -> None:
    data = {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-9",
                        "PkgName": "X",
                        "InstalledVersion": "1",
                        "Severity": "UNKNOWN",
                        "CVSS": {"ghsa": {"V3Score": 7.5}},
                        "FixedVersion": "1.1, 2.0",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "trivy-image.json"
    path.write_text(json.dumps(data))
    finding = spec_for(path).parse(path).findings[0]  # type: ignore[union-attr]
    assert finding.severity == Severity.HIGH
    assert finding.fix_version == "1.1"


def test_checkov() -> None:
    result = parse("checkov-dockerfile.json")
    by_id = {f.rule_id: f for f in result.findings}
    assert by_id["CKV_DOCKER_3"].severity == Severity.HIGH
    assert by_id["CKV_DOCKER_2"].severity == Severity.LOW
    assert by_id["CKV_DOCKER_4"].location == "app/Dockerfile:6"
    assert all(f.raw_severity == "unmapped" for f in result.findings)


def test_checkov_multi_framework(tmp_path: Path) -> None:
    data = [
        {
            "check_type": "kubernetes",
            "summary": {"parsing_errors": 1},
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_16",
                        "check_name": "privileged",
                        "resource": "Deployment.secnotes.api",
                        "file_path": "/reports/rendered.yaml",
                        "file_line_range": [1, 40],
                    }
                ],
                "skipped_checks": [{"check_id": "CKV_K8S_43"}],
            },
        },
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_NEW_999",
                        "check_name": "future check",
                        "resource": "aws_s3_bucket.b",
                        "repo_file_path": "/infra/main.tf",
                        "file_line_range": [5, 9],
                        "severity": "LOW",
                    }
                ]
            },
        },
    ]
    path = tmp_path / "checkov-mixed.json"
    path.write_text(json.dumps(data))
    result = spec_for(path).parse(path)  # type: ignore[union-attr]
    k8s, tf = result.findings
    assert (k8s.category, k8s.severity, k8s.location) == ("k8s", Severity.CRITICAL, "Deployment.secnotes.api")
    assert (tf.category, tf.severity, tf.location) == ("iac", Severity.LOW, "infra/main.tf:aws_s3_bucket.b")
    assert result.suppressed == 1 and result.warnings


def test_kubescape() -> None:
    result = parse("kubescape.json")
    assert {f.rule_id for f in result.findings} == {"C-0057", "C-0013", "C-0009"}
    privileged = next(f for f in result.findings if f.rule_id == "C-0057")
    assert privileged.location == "Deployment.secnotes.secnotes-api"
    assert privileged.severity == Severity.HIGH
    assert "securityContext.privileged" in privileged.description
    assert result.raw_count == 3


def test_zap() -> None:
    result = parse("zap-api.json")
    sqli = next(f for f in result.findings if f.title == "SQL Injection")
    assert (sqli.severity, sqli.location, sqli.cwe, sqli.category) == (
        Severity.HIGH,
        "GET /notes/search",
        "CWE-89",
        "dast",
    )
    assert all("?" not in f.location and "localhost" not in f.location for f in result.findings)
    assert any(f.location == "GET /notes/{id}" for f in result.findings)
    assert normalise_path("/notes/42/x/3f2504e0-4f89-11d3-9a0c-0305e82c3301") == "/notes/{id}/x/{id}"


def test_sonarqube() -> None:
    result = parse("sonarqube.json")
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("pythonsecurity:S3649", Severity.CRITICAL),
        ("python:S4721", Severity.HIGH),
    ]
    assert result.findings[0].location == "app/src/secnotes/routes/notes.py:58"


def test_grype() -> None:
    result = parse("grype.json")
    pyyaml, libc = result.findings
    assert (pyyaml.category, pyyaml.package, pyyaml.cve, pyyaml.fix_available) == (
        "sca",
        "pyyaml",
        "CVE-2020-14343",
        True,
    )
    assert (libc.category, libc.pkg_type, libc.fix_available) == ("container", "os", False)


def test_prowler() -> None:
    result = parse("prowler.json")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert (finding.category, finding.location, finding.severity) == (
        "cloud",
        "arn:aws:s3:::secpipe-reports",
        Severity.HIGH,
    )
