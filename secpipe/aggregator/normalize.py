"""Normalisation helpers shared by the parsers."""

from __future__ import annotations

import re
from typing import Any

from secpipe.aggregator.models import Severity

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-?(\d+)\b", re.IGNORECASE)
_PKG = re.compile(r"[-_.]+")
_EPOCH = re.compile(r"^\d+:")
# Prefixes scanners put in front of repository paths (container mounts, CI
# workspaces, SARIF URI schemes).
_PATH_PREFIXES = ("file://", "/github/workspace/", "/src/", "/repo/", "/code/", "/workspace/")


def normalize_path(path: str, roots: tuple[str, ...] = ()) -> str:
    """Repository-relative, forward-slash path."""
    value = path.replace("\\", "/").strip()
    for root in sorted((r.rstrip("/") + "/" for r in roots if r), key=len, reverse=True):
        if value.startswith(root):
            value = value[len(root) :]
            break
    for prefix in _PATH_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix) :]
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/") if not value.startswith("image:") else value


def normalize_package(name: str) -> str:
    """PEP 503 name: case-insensitive, runs of - _ . are equivalent."""
    return _PKG.sub("-", name).strip().lower()


def strip_epoch(version: str) -> str:
    return _EPOCH.sub("", version or "")


def find_cve(*values: str | None) -> str | None:
    for value in values:
        if value:
            match = _CVE.search(value)
            if match:
                return match.group(0).upper()
    return None


def find_cwe(*values: object) -> str | None:
    for value in values:
        if value is None:
            continue
        items = value if isinstance(value, list | tuple) else [value]
        for item in items:
            if isinstance(item, int) and item > 0:
                return f"CWE-{item}"
            match = _CWE.search(str(item))
            if match and match.group(1) not in {"0"}:
                return f"CWE-{int(match.group(1))}"
    return None


def code_location(path: str, line: int | None) -> str:
    return f"{path}:{line}" if line else path


def package_location(name: str, version: str | None) -> str:
    return f"{name}@{version}" if version else name


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def clamp_text(text: str, limit: int = 600) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def lowest_version(versions: list[str]) -> str | None:
    """The smallest fix version (numeric-aware), so the upgrade is minimal."""
    cleaned = [v for v in versions if v]
    if not cleaned:
        return None

    def key(version: str) -> list[tuple[int, int | str]]:
        parts = re.split(r"[.\-+~]", strip_epoch(version))
        return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]

    return sorted(cleaned, key=key)[0]


def severity_or_cvss(label: str | None, cvss: float | None, default: Severity = Severity.MEDIUM) -> Severity:
    if label:
        parsed = Severity.parse(label, None) if label.lower() in _KNOWN else None
        if parsed is not None:
            return parsed
    if cvss is not None:
        return Severity.from_cvss(cvss)
    return default


_KNOWN = {
    "critical",
    "blocker",
    "high",
    "error",
    "medium",
    "moderate",
    "warning",
    "low",
    "minor",
    "note",
    "info",
    "informational",
    "negligible",
    "none",
}
