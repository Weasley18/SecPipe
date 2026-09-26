from __future__ import annotations

import datetime as dt
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from secpipe.aggregator.models import Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "policy" / "policy.yaml"
TODAY = dt.date(2026, 9, 26)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


def copy_reports(dest: Path, *names: str, meta: bool = True) -> Path:
    """Copy fixture reports into ``dest`` with scanner meta sidecars like scripts/ci writes."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy(FIXTURES / name, dest / name)
        if meta:
            tool = Path(name).stem
            (dest / f"{tool}.meta.json").write_text(
                json.dumps(
                    {
                        "tool": tool,
                        "report": name,
                        "exit_code": 0,
                        "status": "ok",
                        "duration_seconds": 1.5,
                        "version": "test",
                    }
                )
            )
    return dest


VULNERABLE_REPORTS = (
    "gitleaks.sarif",
    "semgrep.sarif",
    "bandit.json",
    "pip-audit.json",
    "osv.json",
    "licenses.json",
    "hadolint.sarif",
    "trivy-image.json",
    "checkov-dockerfile.json",
)


def make_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "tool": "semgrep",
        "category": "sast",
        "rule_id": "rule-x",
        "title": "Something bad",
        "severity": Severity.HIGH,
        "location": "app/src/x.py:10",
        "file": "app/src/x.py",
        "line": 10,
    }
    values.update(overrides)
    return Finding(**values)


class FakeFetcher:
    """Stands in for the EPSS and KEV APIs."""

    def __init__(self, kev: list[str] | None = None, epss: dict[str, float] | None = None, fail: bool = False) -> None:
        self.kev = kev or []
        self.epss = epss or {}
        self.fail = fail
        self.calls: list[str] = []

    def __call__(self, url: str) -> Any:
        from secpipe.http import HttpError

        self.calls.append(url)
        if self.fail:
            raise HttpError("offline")
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": c} for c in self.kev]}
        cves = url.split("cve=", 1)[1].split(",")
        return {"data": [{"cve": c, "epss": str(self.epss[c])} for c in cves if c in self.epss]}


@pytest.fixture
def fake_fetcher() -> Callable[..., FakeFetcher]:
    return FakeFetcher
