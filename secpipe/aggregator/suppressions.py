"""Inventory of in-code scanner suppressions.

A suppression without a reason is a finding in itself. SecPipe finds the
inline markers for Bandit, Semgrep, Checkov, Trivy, Hadolint and Gitleaks,
requires a written justification after the rule id (for example
``-- query only uses bound parameters``) or on the line above
(``# justification: ...``), reports unjustified ones as findings, and counts
new suppressions per pull request against ``max_suppressions_per_pr``.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from secpipe.aggregator.models import Finding, Severity

MIN_JUSTIFICATION = 10
CODE_SUFFIXES = {".py", ".tf", ".yaml", ".yml", ".sh", ".toml", ".hcl", ".json", ".j2"}
# Tests are excluded from SAST (see .semgrepignore / [tool.bandit]), so a marker
# there suppresses nothing; test data also contains markers as string literals.
SKIP_DIRS = {
    "tests",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".secpipe-tools",
    ".secpipe-tooling",
    ".secpipe-main",
    "reports",
    "out",
    "build",
    "dist",
    "__pycache__",
    ".terraform",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
SKIP_PREFIXES = ("secpipe/tests/fixtures/",)

# kind -> (marker regex with an optional "rules" group and a "rest" group)
MARKERS: dict[str, re.Pattern[str]] = {
    "nosec": re.compile(r"#\s*nosec\b[:\s]*(?P<rules>(?:B\d{3}[,\s]*)*)(?P<rest>.*)$"),
    "nosemgrep": re.compile(r"#\s*nosemgrep\b:?\s*(?P<rules>[\w.\-]+(?:\s*,\s*[\w.\-]+)*)?(?P<rest>.*)$"),
    "checkov-skip": re.compile(r"(?:#|//)\s*checkov:skip=(?P<rules>[A-Z0-9_]+)(?::?(?P<rest>.*))$"),
    "checkov-skip-annotation": re.compile(r"checkov\.io/skip\d+:\s*(?P<rules>[A-Z0-9_]+)(?:=(?P<rest>.*))?$"),
    "trivy-ignore": re.compile(r"(?:#|//)\s*(?:trivy|tfsec):ignore:(?P<rules>[\w\-]+)(?P<rest>.*)$"),
    "hadolint-ignore": re.compile(r"#\s*hadolint\s+ignore=(?P<rules>[A-Z0-9,]+)(?P<rest>.*)$"),
    "gitleaks-allow": re.compile(r"(?:#|//)\s*gitleaks:allow(?P<rules>)(?P<rest>.*)$"),
}
_JUSTIFY_ABOVE = re.compile(r"^\s*(?:#|//)\s*(?:justification|reason)\s*:\s*(?P<text>.+)$", re.IGNORECASE)
_SEPARATORS = re.compile(r"^[\s:\-\u2013\u2014,;(]+|[\s)]+$")


@dataclass(frozen=True)
class Suppression:
    file: str
    line: int
    kind: str
    rules: tuple[str, ...]
    justification: str
    code: str

    @property
    def justified(self) -> bool:
        return len(self.justification) >= MIN_JUSTIFICATION

    @property
    def key(self) -> str:
        """Line-number-free identity used to tell new suppressions from old ones."""
        raw = f"{self.file}|{self.kind}|{','.join(self.rules)}|{self.code.strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "rules": list(self.rules),
            "justification": self.justification,
            "justified": self.justified,
            "key": self.key,
        }


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if rel.startswith(SKIP_PREFIXES):
                continue
            if path.suffix in CODE_SUFFIXES or "dockerfile" in name.lower():
                files.append(path)
    return files


def scan(root: Path) -> list[Suppression]:
    found: list[Suppression] = []
    for path in _iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(root).as_posix()
        for index, text in enumerate(lines):
            for kind, pattern in MARKERS.items():
                match = pattern.search(text)
                if not match:
                    continue
                rules = tuple(r for r in re.split(r"[,\s]+", match.group("rules") or "") if r)
                justification = _SEPARATORS.sub("", (match.group("rest") or "").strip())
                if len(justification) < MIN_JUSTIFICATION and index > 0:
                    above = _JUSTIFY_ABOVE.match(lines[index - 1])
                    if above:
                        justification = above.group("text").strip()
                code = text[: match.start()].strip()
                found.append(Suppression(rel, index + 1, kind, rules, justification, code))
    return found


def unjustified_findings(suppressions: list[Suppression]) -> list[Finding]:
    return [
        Finding(
            tool="secpipe",
            category="sast",
            rule_id="secpipe-unjustified-suppression",
            title=f"{s.kind} suppression without a justification",
            severity=Severity.MEDIUM,
            location=f"{s.file}:{s.line}",
            file=s.file,
            line=s.line,
            description=(
                f"{s.kind} {' '.join(s.rules) or '(all rules)'} silences a scanner with no reason. "
                "Add one after the rule id, e.g. '-- input is validated by schema X'."
            ),
        )
        for s in suppressions
        if not s.justified
    ]
