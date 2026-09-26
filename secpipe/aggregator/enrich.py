"""Risk-based prioritisation data: FIRST EPSS scores and the CISA KEV catalogue.

Both are cached on disk for 24 hours (the CI workflow persists the cache
directory with actions/cache) to stay polite to the APIs. Enrichment is
best-effort: if the feeds are unreachable the gate still runs, and the report
says enrichment was unavailable.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding
from secpipe.aggregator.normalize import as_dict, as_float, as_list, as_str
from secpipe.http import HttpError, get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TTL_SECONDS = 24 * 3600
EPSS_BATCH = 100

Fetcher = Callable[[str], Any]


@dataclass
class EnrichmentReport:
    kev_available: bool = False
    epss_available: bool = False
    cves: int = 0
    in_kev: int = 0
    epss_scored: int = 0
    errors: list[str] = field(default_factory=list)


class ThreatIntel:
    def __init__(self, cache_dir: Path, fetch: Fetcher = get_json, now: Callable[[], float] = time.time) -> None:
        self.cache_dir = cache_dir
        self.fetch = fetch
        self.now = now

    # ------------------------------------------------------------------ cache
    def _read(self, name: str) -> dict[str, Any]:
        try:
            return as_dict(json.loads((self.cache_dir / name).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, name: str, data: dict[str, Any]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            (self.cache_dir / name).write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass  # a read-only cache only costs an extra download next time

    def _fresh(self, fetched_at: object) -> bool:
        stamp = as_float(fetched_at)
        return stamp is not None and self.now() - stamp < TTL_SECONDS

    # -------------------------------------------------------------------- KEV
    def kev(self) -> set[str]:
        cached = self._read("kev.json")
        if self._fresh(cached.get("fetched_at")):
            return {as_str(c) for c in as_list(cached.get("cves"))}
        catalogue = as_dict(self.fetch(KEV_URL))
        cves = sorted(
            {as_str(as_dict(v).get("cveID")).upper() for v in as_list(catalogue.get("vulnerabilities"))} - {""}
        )
        if not cves:
            raise HttpError("KEV catalogue was empty or malformed")
        self._write("kev.json", {"fetched_at": self.now(), "cves": cves})
        return set(cves)

    # ------------------------------------------------------------------- EPSS
    def epss(self, cves: Iterable[str]) -> dict[str, float]:
        cached = self._read("epss.json")
        entries = as_dict(cached.get("scores"))
        scores: dict[str, float] = {}
        missing: list[str] = []
        for cve in sorted(set(cves)):
            entry = as_dict(entries.get(cve))
            if self._fresh(entry.get("fetched_at")):
                value = as_float(entry.get("epss"))
                if value is not None:
                    scores[cve] = value
            else:
                missing.append(cve)
        for start in range(0, len(missing), EPSS_BATCH):
            batch = missing[start : start + EPSS_BATCH]
            response = as_dict(self.fetch(f"{EPSS_URL}?cve={','.join(batch)}"))
            returned = {
                as_str(as_dict(r).get("cve")).upper(): as_float(as_dict(r).get("epss"))
                for r in as_list(response.get("data"))
            }
            for cve in batch:
                value = returned.get(cve)
                # Unscored CVEs are cached as 0 too, so they are not re-requested every run.
                entries[cve] = {"epss": value if value is not None else 0.0, "fetched_at": self.now()}
                if value is not None:
                    scores[cve] = value
        if missing:
            self._write("epss.json", {"scores": entries})
        return scores

    # ----------------------------------------------------------------- enrich
    def enrich(self, findings: list[Finding]) -> EnrichmentReport:
        report = EnrichmentReport()
        cves = sorted({f.cve.upper() for f in findings if f.cve})
        report.cves = len(cves)
        if not cves:
            report.kev_available = report.epss_available = True
            return report
        try:
            kev = self.kev()
            report.kev_available = True
        except (HttpError, OSError, ValueError) as exc:
            kev = set()
            report.errors.append(f"KEV catalogue unavailable: {exc}")
        try:
            scores = self.epss(cves)
            report.epss_available = True
        except (HttpError, OSError, ValueError) as exc:
            scores = {}
            report.errors.append(f"EPSS unavailable: {exc}")
        for finding in findings:
            if not finding.cve:
                continue
            cve = finding.cve.upper()
            if cve in kev:
                finding.in_kev = True
                report.in_kev += 1
            if cve in scores:
                finding.epss = scores[cve]
                report.epss_scored += 1
        return report
