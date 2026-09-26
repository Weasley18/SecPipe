"""Cross-tool deduplication.

Rules (applied in order, with union-find so merges are transitive):

1. Exact: identical fingerprint (category + CVE-or-rule + location).
2. Dependencies: same advisory (any shared CVE/GHSA/PYSEC id) in the same
   package, case-insensitive with ``-``/``_``/``.`` equivalent. This also
   merges a CVE in a Python package found in the image by Trivy with the same
   CVE found in requirements.txt by Snyk/OSV/pip-audit. OS-package CVEs are
   never merged with language packages.
3. Code: same CWE in the same file with start lines at most 2 apart
   (Semgrep and Bandit often flag the same line).

The merged finding keeps the highest severity and lists the other tools in
``also_reported_by``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from secpipe.aggregator.models import CATEGORY_PRIORITY, Finding
from secpipe.aggregator.normalize import normalize_package

CODE_CATEGORIES = {"sast", "secret"}
LINE_WINDOW = 2
# Richer dependency data first when choosing the finding that "speaks" for a group.
TOOL_PREFERENCE = ["snyk", "osv-scanner", "trivy", "grype", "pip-audit", "semgrep", "gitleaks", "bandit"]


@dataclass(frozen=True)
class DedupeStats:
    raw: int
    unique: int

    @property
    def removed(self) -> int:
        return self.raw - self.unique


class _UnionFind:
    def __init__(self, findings: list[Finding]) -> None:
        self.parent = list(range(len(findings)))
        self.tools: list[set[str]] = [{f.tool} for f in findings]

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            keep, drop = min(ra, rb), max(ra, rb)
            self.parent[drop] = keep
            self.tools[keep] |= self.tools[drop]

    def can_merge_tools(self, a: int, b: int) -> bool:
        """Code rule: only merge across tools, never two results of one tool."""
        ra, rb = self.find(a), self.find(b)
        return ra != rb and not (self.tools[ra] & self.tools[rb])


def _tool_rank(tool: str) -> int:
    return TOOL_PREFERENCE.index(tool) if tool in TOOL_PREFERENCE else len(TOOL_PREFERENCE)


def _category_rank(category: str) -> int:
    return CATEGORY_PRIORITY.index(category) if category in CATEGORY_PRIORITY else len(CATEGORY_PRIORITY)


def _merge(group: list[Finding]) -> Finding:
    primary = min(group, key=lambda f: (-int(f.severity), _tool_rank(f.tool)))
    merged = primary
    others = [f for f in group if f is not primary]
    tools = {f.tool for f in others} - {primary.tool}
    merged.also_reported_by = sorted(set(merged.also_reported_by) | tools)
    merged.category = min((f.category for f in group), key=_category_rank)
    merged.severity = max(f.severity for f in group)
    for f in others:
        merged.cve = merged.cve or f.cve
        merged.cwe = merged.cwe or f.cwe
        merged.fix_version = merged.fix_version or f.fix_version
        if merged.fix_available is None or (f.fix_available and not merged.fix_available):
            merged.fix_available = f.fix_available if f.fix_available is not None else merged.fix_available
        if f.cvss is not None and (merged.cvss is None or f.cvss > merged.cvss):
            merged.cvss = f.cvss
        if merged.direct is None:
            merged.direct = f.direct
        merged.help_url = merged.help_url or f.help_url
        merged.description = merged.description or f.description
        merged.aliases = sorted(
            set(merged.aliases) | set(f.aliases) | ({f.rule_id} if f.category in {"sca", "container"} else set())
        )
        merged.related_packages = sorted(set(merged.related_packages) | set(f.related_packages))
    if merged.cve:
        merged.aliases = [a for a in merged.aliases if a.upper() != merged.cve.upper()]
        if merged.category in {"sca", "container"}:
            merged.rule_id = merged.cve
    return merged


def deduplicate(findings: list[Finding], raw_results: int | None = None) -> tuple[list[Finding], DedupeStats]:
    """Merge duplicates. ``raw_results`` is the scanners' own result count
    (before parser-level grouping); it defaults to ``len(findings)``."""
    raw = len(findings) if raw_results is None else max(raw_results, len(findings))
    uf = _UnionFind(findings)

    # 1. exact fingerprint
    by_fingerprint: dict[str, int] = {}
    for i, f in enumerate(findings):
        first = by_fingerprint.setdefault(f.fingerprint, i)
        if first != i:
            uf.union(first, i)

    # 2. dependency advisories per package (language packages only)
    by_advisory: dict[tuple[str, str], int] = {}
    for i, f in enumerate(findings):
        if not f.package or f.pkg_type == "os" or f.category not in {"sca", "container"}:
            continue
        package = normalize_package(f.package)
        for advisory in f.advisory_ids:
            first = by_advisory.setdefault((package, advisory), i)
            if first != i:
                uf.union(first, i)

    # 3. code: same CWE, same file, lines within LINE_WINDOW, different tools.
    # Closest pairs first, so each result pairs with its nearest counterpart.
    by_file: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        if f.category in CODE_CATEGORIES and f.file and f.line and f.cwe:
            by_file[(f.file, f.cwe)].append(i)
    for indexes in by_file.values():
        pairs = sorted(
            (abs((findings[a].line or 0) - (findings[b].line or 0)), a, b)
            for pos, a in enumerate(indexes)
            for b in indexes[pos + 1 :]
            if findings[a].tool != findings[b].tool
        )
        for distance, a, b in pairs:
            if distance <= LINE_WINDOW and uf.can_merge_tools(a, b):
                uf.union(a, b)

    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(findings):
        groups[uf.find(i)].append(f)
    unique = [_merge(group) for _, group in sorted(groups.items())]
    return unique, DedupeStats(raw=raw, unique=len(unique))
