from __future__ import annotations

import pytest

from secpipe.aggregator.models import Finding, Severity
from secpipe.aggregator.normalize import (
    as_float,
    as_int,
    clamp_text,
    code_location,
    find_cve,
    find_cwe,
    lowest_version,
    normalize_package,
    normalize_path,
    package_location,
    severity_or_cvss,
    strip_epoch,
)
from secpipe.tests.conftest import make_finding


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("moderate", Severity.MEDIUM),
        ("Blocker", Severity.CRITICAL),
        ("warning", Severity.MEDIUM),
        ("note", Severity.LOW),
        ("negligible", Severity.INFO),
        (3, Severity.HIGH),
        (Severity.LOW, Severity.LOW),
    ],
)
def test_severity_parse(value: object, expected: Severity) -> None:
    assert Severity.parse(value) == expected


def test_severity_parse_unknown() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("spicy")
    assert Severity.parse("spicy", Severity.MEDIUM) == Severity.MEDIUM
    assert Severity.parse(True, Severity.LOW) == Severity.LOW  # bools are not severities


def test_severity_bump_and_cvss() -> None:
    assert Severity.HIGH.bump() == Severity.CRITICAL
    assert Severity.CRITICAL.bump() == Severity.CRITICAL
    assert Severity.LOW.bump(-5) == Severity.INFO
    assert [Severity.from_cvss(s) for s in (9.8, 7.0, 4.0, 0.1, 0.0)] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert Severity.HIGH.label == "high"


def test_fingerprint_matches_spec_formula() -> None:
    import hashlib

    finding = make_finding(category="sca", rule_id="GHSA-1", cve="CVE-2020-14343", location="pyyaml@5.3.1")
    expected = hashlib.sha256(b"sca|CVE-2020-14343|pyyaml@5.3.1").hexdigest()[:16]
    assert finding.fingerprint == expected
    assert make_finding(rule_id="r1").fingerprint != make_finding(rule_id="r2").fingerprint


def test_finding_round_trip() -> None:
    finding = make_finding(cve="CVE-2024-1", aliases=["GHSA-x"], epss=0.2, in_kev=True, also_reported_by=["bandit"])
    clone = Finding.from_dict(finding.to_dict())
    assert clone.to_dict() == finding.to_dict()
    assert clone.stage == "SAST"
    assert clone.tools == ["semgrep", "bandit"]


def test_advisory_ids() -> None:
    finding = make_finding(category="sca", rule_id="PYSEC-1", cve="cve-2020-1", aliases=["GHSA-a"])
    assert finding.advisory_ids == {"CVE-2020-1", "PYSEC-1", "GHSA-A"}
    assert make_finding(rule_id="B602").advisory_ids == set()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/src/app/Dockerfile", "app/Dockerfile"),
        ("file:///github/workspace/app/x.py", "app/x.py"),
        ("./app/x.py", "app/x.py"),
        ("app\\src\\x.py", "app/src/x.py"),
        ("/home/runner/work/repo/app/x.py", "app/x.py"),
        ("image:/app/x.py", "image:/app/x.py"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw, roots=("/home/runner/work/repo",)) == expected


def test_package_and_version_helpers() -> None:
    assert normalize_package("PyYAML") == "pyyaml"
    assert normalize_package("python_multipart") == normalize_package("Python.Multipart") == "python-multipart"
    assert strip_epoch("1:2.36.1-8") == "2.36.1-8"
    assert lowest_version(["2.0", "10.0", "2.0.1"]) == "2.0"
    assert lowest_version(["5.4", "5.3.2b1"]) == "5.3.2b1"
    assert lowest_version([]) is None
    assert code_location("a.py", 3) == "a.py:3"
    assert code_location("a.py", None) == "a.py"
    assert package_location("x", None) == "x"


def test_cve_cwe_extraction() -> None:
    assert find_cve(None, "see cve-2021-1234 for details") == "CVE-2021-1234"
    assert find_cve("GHSA-xxxx") is None
    assert find_cwe(["security", "CWE-89: SQL Injection"]) == "CWE-89"
    assert find_cwe(78) == "CWE-78"
    assert find_cwe("-1", None, ["CWE-0"]) is None


def test_misc_coercions() -> None:
    assert as_int("12") == 12
    assert as_int("x") is None
    assert as_float("0.5") == 0.5
    assert as_float(None) is None
    assert clamp_text("a " * 400, 20).endswith("…")
    assert severity_or_cvss("High", None) == Severity.HIGH
    assert severity_or_cvss("weird", 9.1) == Severity.CRITICAL
    assert severity_or_cvss(None, None, Severity.LOW) == Severity.LOW
