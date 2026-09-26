"""Parser registry: report file name -> parser.

Each parser is a pure function ``parse(path) -> ParseResult`` (file in,
findings out) that never raises on empty or truncated input.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from secpipe.aggregator.models import ParseResult
from secpipe.aggregator.parsers import (
    bandit,
    checkov,
    gitleaks,
    grype,
    hadolint,
    kubescape,
    licenses,
    osv,
    pip_audit,
    prowler,
    semgrep,
    snyk,
    sonarqube,
    trivy,
    zap,
    zizmor,
)

Parser = Callable[[Path], ParseResult]


@dataclass(frozen=True)
class ParserSpec:
    tool: str
    patterns: tuple[str, ...]
    parse: Parser


REGISTRY: tuple[ParserSpec, ...] = (
    ParserSpec("gitleaks", ("gitleaks*.sarif",), gitleaks.parse),
    ParserSpec("semgrep", ("semgrep*.sarif",), semgrep.parse),
    ParserSpec("bandit", ("bandit*.json",), bandit.parse),
    ParserSpec("hadolint", ("hadolint*.sarif",), hadolint.parse),
    ParserSpec("zizmor", ("zizmor*.sarif",), zizmor.parse),
    ParserSpec("snyk", ("snyk*.json",), snyk.parse),
    ParserSpec("osv-scanner", ("osv*.json",), osv.parse),
    ParserSpec("pip-audit", ("pip-audit*.json",), pip_audit.parse),
    ParserSpec("pip-licenses", ("licenses*.json", "pip-licenses*.json"), licenses.parse),
    ParserSpec("trivy", ("trivy*.json",), trivy.parse),
    ParserSpec("grype", ("grype*.json",), grype.parse),
    ParserSpec("checkov", ("checkov*.json",), checkov.parse),
    ParserSpec("kubescape", ("kubescape*.json",), kubescape.parse),
    ParserSpec("zap", ("zap*.json",), zap.parse),
    ParserSpec("sonarqube", ("sonarqube*.json",), sonarqube.parse),
    ParserSpec("prowler", ("prowler*.json",), prowler.parse),
)
IGNORED = ("*.meta.json", "sbom*.json", "*.cdx.json", "secpipe*.sarif", "findings*.json", "gate*.json")


def spec_for(path: Path) -> ParserSpec | None:
    name = path.name.lower()
    if any(fnmatch.fnmatch(name, pattern) for pattern in IGNORED):
        return None
    for spec in REGISTRY:
        if any(fnmatch.fnmatch(name, pattern) for pattern in spec.patterns):
            return spec
    return None


def parse_report(path: Path) -> ParseResult | None:
    """Parse one report, or return None if no parser claims the file name."""
    spec = spec_for(path)
    return spec.parse(path) if spec else None
