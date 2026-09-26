from __future__ import annotations

import json
from pathlib import Path

from secpipe.aggregator.baseline import Baseline, diff, load_baseline
from secpipe.aggregator.dedupe import deduplicate
from secpipe.aggregator.enrich import TTL_SECONDS, ThreatIntel
from secpipe.aggregator.models import Severity
from secpipe.aggregator.parsers import parse_report
from secpipe.tests.conftest import FIXTURES, FakeFetcher, make_finding


def _sca(tool: str, **kw: object):  # type: ignore[no-untyped-def]
    base = {
        "tool": tool,
        "category": "sca",
        "rule_id": "CVE-2020-14343",
        "cve": "CVE-2020-14343",
        "location": "pyyaml@5.3.1",
        "package": "pyyaml",
        "version": "5.3.1",
        "pkg_type": "python",
        "file": None,
        "line": None,
    }
    base.update(kw)
    return make_finding(**base)


# --------------------------------------------------------------------- dedupe
def test_same_cve_same_package_across_tools_is_one_finding() -> None:
    findings = [
        _sca("pip-audit", rule_id="PYSEC-2021-142", severity=Severity.MEDIUM, aliases=["GHSA-8q59-q68h-6hv4"]),
        _sca("osv-scanner", rule_id="CVE-2020-14343", severity=Severity.CRITICAL, cvss=9.8, fix_version="5.4"),
        _sca("trivy", severity=Severity.CRITICAL, package="PyYAML", location="pyyaml@5.3.1"),
        _sca("snyk", rule_id="CVE-2020-14343", package="py_yaml", severity=Severity.HIGH, direct=True),
    ]
    unique, stats = deduplicate(findings)
    assert len(unique) == 1
    merged = unique[0]
    assert merged.severity == Severity.CRITICAL, "highest severity wins"
    assert merged.tool == "osv-scanner"
    assert set(merged.also_reported_by) == {"pip-audit", "snyk", "trivy"}
    assert merged.fix_version == "5.4" and merged.cvss == 9.8 and merged.direct is True
    assert "PYSEC-2021-142" in merged.aliases
    assert (stats.raw, stats.unique, stats.removed) == (4, 1, 3)


def test_alias_chain_merges_transitively() -> None:
    a = _sca("pip-audit", cve=None, rule_id="PYSEC-1", aliases=["GHSA-1"])
    b = _sca("osv-scanner", cve=None, rule_id="GHSA-1", aliases=["CVE-2024-9"])
    c = _sca("trivy", cve="CVE-2024-9", rule_id="CVE-2024-9")
    unique, _ = deduplicate([a, b, c])
    assert len(unique) == 1
    assert unique[0].rule_id == "CVE-2024-9"


def test_os_packages_never_merge_with_python_packages() -> None:
    python = _sca("trivy", package="pillow", location="pillow@9.0")
    os_pkg = _sca("trivy", category="container", pkg_type="os", package="pillow", location="python3-pil@9.0")
    unique, _ = deduplicate([python, os_pkg])
    assert len(unique) == 2


def test_code_findings_merge_across_tools_within_two_lines() -> None:
    semgrep = make_finding(
        tool="semgrep", rule_id="formatted-sql", cwe="CWE-89", line=58, location="n.py:58", file="n.py"
    )
    bandit = make_finding(
        tool="bandit",
        rule_id="B608",
        cwe="CWE-89",
        line=56,
        location="n.py:56",
        file="n.py",
        severity=Severity.MEDIUM,
    )
    far = make_finding(tool="bandit", rule_id="B608", cwe="CWE-89", line=90, location="n.py:90", file="n.py")
    unique, _ = deduplicate([semgrep, bandit, far])
    assert len(unique) == 2
    merged = next(f for f in unique if f.also_reported_by)
    assert merged.tool == "semgrep" and merged.also_reported_by == ["bandit"]


def test_same_tool_results_on_adjacent_lines_stay_separate() -> None:
    """Four different secrets on lines 21-26 of one file are four findings."""
    gitleaks = [
        make_finding(
            tool="gitleaks",
            category="secret",
            rule_id=r,
            cwe="CWE-798",
            line=n,
            file="c.py",
            location=f"c.py:{n}",
        )
        for r, n in (("aws", 21), ("db", 23), ("tok", 24), ("jwt", 26))
    ]
    semgrep = make_finding(
        tool="semgrep",
        category="sast",
        rule_id="hardcoded",
        cwe="CWE-798",
        line=22,
        file="c.py",
        location="c.py:22",
    )
    unique, _ = deduplicate([*gitleaks, semgrep])
    assert len(unique) == 4
    merged = [f for f in unique if f.also_reported_by]
    assert len(merged) == 1 and merged[0].category == "secret", "secret framing wins over sast"


def test_exact_fingerprint_duplicates() -> None:
    unique, stats = deduplicate([make_finding(), make_finding(), make_finding(rule_id="other")])
    assert len(unique) == 2 and stats.removed == 1


def test_real_reports_cross_tool_dedupe() -> None:
    parsed = [parse_report(FIXTURES / n) for n in ("pip-audit.json", "osv.json", "trivy-image.json")]
    findings = [f for r in parsed if r for f in r.findings]
    unique, stats = deduplicate(findings)
    pyyaml = [f for f in unique if f.package == "pyyaml" and f.cve == "CVE-2020-14343"]
    assert len(pyyaml) == 1
    assert set(pyyaml[0].tools) == {"trivy", "osv-scanner", "pip-audit"}
    assert stats.removed > 0


def test_dedupe_raw_results_override() -> None:
    _, stats = deduplicate([make_finding()], raw_results=50)
    assert (stats.raw, stats.unique) == (50, 1)


# --------------------------------------------------------------------- enrich
def test_enrichment_sets_kev_and_epss(tmp_path: Path) -> None:
    fetcher = FakeFetcher(kev=["CVE-2020-14343"], epss={"CVE-2020-14343": 0.42, "CVE-2024-1": 0.001})
    intel = ThreatIntel(tmp_path, fetch=fetcher, now=lambda: 1000.0)
    findings = [
        _sca("trivy"),
        _sca("trivy", cve="CVE-2024-1", rule_id="CVE-2024-1", location="x@1"),
        make_finding(),
    ]
    report = intel.enrich(findings)
    assert findings[0].in_kev and findings[0].epss == 0.42
    assert not findings[1].in_kev and findings[1].epss == 0.001
    assert (report.cves, report.in_kev, report.epss_scored, report.errors) == (2, 1, 2, [])
    assert json.loads((tmp_path / "kev.json").read_text())["cves"] == ["CVE-2020-14343"]


def test_enrichment_cache_is_reused_within_ttl(tmp_path: Path) -> None:
    clock = [1000.0]
    fetcher = FakeFetcher(kev=["CVE-1"], epss={"CVE-1": 0.2})
    intel = ThreatIntel(tmp_path, fetch=fetcher, now=lambda: clock[0])
    intel.enrich([_sca("trivy", cve="CVE-1")])
    calls = len(fetcher.calls)
    intel.enrich([_sca("trivy", cve="CVE-1")])
    assert len(fetcher.calls) == calls, "second run within 24h hits the cache"
    clock[0] += TTL_SECONDS + 1
    intel.enrich([_sca("trivy", cve="CVE-1")])
    assert len(fetcher.calls) == calls * 2


def test_epss_requests_are_batched(tmp_path: Path) -> None:
    fetcher = FakeFetcher(kev=["X"], epss={})
    intel = ThreatIntel(tmp_path, fetch=fetcher)
    intel.epss([f"CVE-2024-{i}" for i in range(250)])
    assert sum("epss" in c for c in fetcher.calls) == 3


def test_enrichment_is_best_effort(tmp_path: Path) -> None:
    intel = ThreatIntel(tmp_path, fetch=FakeFetcher(fail=True))
    finding = _sca("trivy")
    report = intel.enrich([finding])
    assert not report.kev_available and not report.epss_available
    assert len(report.errors) == 2 and finding.epss is None
    assert ThreatIntel(tmp_path, fetch=FakeFetcher()).enrich([make_finding()]).kev_available


def test_empty_kev_catalogue_is_an_error(tmp_path: Path) -> None:
    report = ThreatIntel(tmp_path, fetch=FakeFetcher(kev=[])).enrich([_sca("trivy")])
    assert any("KEV" in e for e in report.errors)


# ------------------------------------------------------------------- baseline
def test_diff_new_existing_fixed() -> None:
    existing = make_finding(rule_id="old")
    gone = make_finding(rule_id="gone", location="app/src/y.py:3", file="app/src/y.py", line=3)
    baseline = Baseline(findings=[existing, gone], generated_at="2026-09-01T00:00:00+00:00")
    current = [make_finding(rule_id="old"), make_finding(rule_id="brand-new")]
    fixed = diff(current, baseline)
    assert [f.status for f in current] == ["existing", "new"]
    assert current[0].first_seen == "2026-09-01T00:00:00+00:00"
    assert [f.rule_id for f in fixed] == ["gone"] and fixed[0].decision == "fixed"


def test_diff_survives_line_shifts() -> None:
    baseline = Baseline(findings=[make_finding(line=10, location="app/src/x.py:10")])
    current = [make_finding(line=14, location="app/src/x.py:14")]
    assert diff(current, baseline) == []
    assert current[0].status == "existing"


def test_diff_without_baseline_marks_everything_new() -> None:
    current = [make_finding()]
    assert diff(current, None) == [] and current[0].status == "new"


def test_load_baseline(tmp_path: Path) -> None:
    assert load_baseline(None) == (None, [])
    missing, warnings = load_baseline(tmp_path / "nope.json")
    assert missing is None and "no baseline" in warnings[0]
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert "unreadable" in load_baseline(bad)[1][0]
    good = tmp_path / "findings.json"
    good.write_text(
        json.dumps(
            {
                "meta": {"commit": "abc", "generated_at": "2026-09-01"},
                "findings": [
                    make_finding().to_dict(),
                    {**make_finding(rule_id="z").to_dict(), "status": "fixed"},
                ],
                "suppressions": [{"key": "k1"}],
            }
        )
    )
    baseline, warnings = load_baseline(good)
    assert baseline is not None and warnings == []
    assert len(baseline.findings) == 1 and baseline.suppression_keys == {"k1"} and baseline.commit == "abc"
