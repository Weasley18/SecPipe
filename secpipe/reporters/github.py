"""GitHub REST integration: sticky PR comment and remediation tracking Issues.

Issues (pushes to main only):
* a new high/critical finding that blocks or is warned (e.g. no fix yet)
  opens an Issue labelled ``security``, ``sev:<severity>``, ``tool:<tool>``,
  with the fix version and a due date from ``sla_days``;
* the fingerprint is stored in a hidden HTML comment so the next run updates
  the same Issue instead of opening a duplicate;
* when a finding disappears the Issue gets "Fixed in <sha>" and is closed;
* past the due date the Issue gets ``sla-breached``.
OS-package CVEs with no upstream fix are rolled up into one Issue per branch,
because there is nothing to do per CVE until the distribution ships a fix.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from secpipe.aggregator.models import Finding, Severity
from secpipe.aggregator.normalize import as_dict, as_list, as_str
from secpipe.http import request_json

API = "https://api.github.com"
FINGERPRINT = re.compile(r"<!--\s*secpipe:fingerprint=([0-9a-z:\-]+)\s*-->")
ROLLUP_ID = "rollup-os-nofix"
BASE_LABELS = ("security", "secpipe")

Requester = Callable[..., Any]


@dataclass
class IssueSync:
    opened: list[int] = field(default_factory=list)
    updated: list[int] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    breached: list[int] = field(default_factory=list)
    skipped: int = 0
    metrics: list[tuple[str, dict[str, str], float]] = field(default_factory=list)


class GitHubClient:
    def __init__(self, token: str, repository: str, api: str = API, request: Requester = request_json) -> None:
        self.repository = repository
        self.api = api.rstrip("/")
        self._request = request
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def call(self, method: str, path: str, body: Any = None) -> Any:
        return self._request(method, f"{self.api}{path}", body=body, headers=self._headers)

    def paginate(self, path: str, limit: int = 2000) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        sep = "&" if "?" in path else "?"
        while len(items) < limit:
            batch = as_list(self.call("GET", f"{path}{sep}per_page=100&page={page}"))
            items.extend(as_dict(i) for i in batch)
            if len(batch) < 100:
                break
            page += 1
        return items

    # ---------------------------------------------------------------- comment
    def upsert_comment(self, pr: int, body: str, marker: str) -> tuple[str, int]:
        """Create the sticky comment or update it in place (found by marker)."""
        repo = self.repository
        for comment in self.paginate(f"/repos/{repo}/issues/{pr}/comments"):
            if marker in as_str(comment.get("body")):
                cid = int(comment["id"])
                self.call("PATCH", f"/repos/{repo}/issues/comments/{cid}", {"body": body})
                return "updated", cid
        created = as_dict(self.call("POST", f"/repos/{repo}/issues/{pr}/comments", {"body": body}))
        return "created", int(created.get("id", 0))

    # ----------------------------------------------------------------- issues
    def sync_issues(
        self,
        findings: list[Finding],
        *,
        sha: str,
        branch: str,
        today: dt.date,
        run_url: str | None = None,
        max_new: int = 25,
    ) -> IssueSync:
        repo = self.repository
        report = IssueSync()
        open_issues = self.paginate(f"/repos/{repo}/issues?state=open&labels=secpipe")
        by_fp: dict[str, dict[str, Any]] = {}
        for issue in open_issues:
            if "pull_request" in issue:
                continue
            match = FINGERPRINT.search(as_str(issue.get("body")))
            if match:
                by_fp[match.group(1)] = issue

        tracked = [f for f in findings if f.decision in {"block", "warn"} and f.severity >= Severity.HIGH]
        rollup = [f for f in tracked if f.pkg_type == "os" and f.fix_available is False]
        individual = [f for f in tracked if f not in rollup]
        wanted: set[str] = {f.fingerprint for f in individual}

        for finding in individual:
            found = by_fp.get(finding.fingerprint)
            if found is None:
                if len(report.opened) >= max_new:
                    report.skipped += 1
                    continue
                found = as_dict(
                    self.call(
                        "POST",
                        f"/repos/{repo}/issues",
                        {
                            "title": _title(finding),
                            "body": _body(finding, sha, run_url),
                            "labels": _labels(finding),
                        },
                    )
                )
                report.opened.append(int(found.get("number", 0)))
            issue = found
            if finding.due_date and dt.date.fromisoformat(finding.due_date) < today:
                names = {as_str(as_dict(label).get("name")) for label in as_list(issue.get("labels"))}
                if "sla-breached" not in names:
                    number = int(issue.get("number", 0))
                    self.call("POST", f"/repos/{repo}/issues/{number}/labels", {"labels": ["sla-breached"]})
                    report.breached.append(number)

        rollup_key = f"{ROLLUP_ID}-{branch}"
        if rollup:
            wanted.add(rollup_key)
            body = _rollup_body(rollup, rollup_key, branch, sha, run_url)
            existing = by_fp.get(rollup_key)
            if existing is None:
                created = as_dict(
                    self.call(
                        "POST",
                        f"/repos/{repo}/issues",
                        {
                            "title": f"[SecPipe] {len(rollup)} unfixed high/critical OS CVEs in the "
                            f"base image ({branch})",
                            "body": body,
                            "labels": [*BASE_LABELS, "tool:trivy", "no-fix-available"],
                        },
                    )
                )
                report.opened.append(int(created.get("number", 0)))
            else:
                number = int(existing.get("number", 0))
                self.call("PATCH", f"/repos/{repo}/issues/{number}", {"body": body})
                report.updated.append(number)

        for fingerprint, issue in by_fp.items():
            if fingerprint in wanted:
                continue
            if fingerprint.startswith(ROLLUP_ID) and not fingerprint.endswith(f"-{branch}"):
                continue  # another branch's rollup
            number = int(issue.get("number", 0))
            self.call(
                "POST",
                f"/repos/{repo}/issues/{number}/comments",
                {"body": f"Fixed in {sha}: SecPipe no longer reports this finding."},
            )
            self.call("PATCH", f"/repos/{repo}/issues/{number}", {"state": "closed", "state_reason": "completed"})
            report.closed.append(number)

        report.metrics = self._issue_metrics(today)
        return report

    def _issue_metrics(self, today: dt.date) -> list[tuple[str, dict[str, str], float]]:
        """Mean age of open Issues and mean time to remediate closed ones, per severity."""
        repo = self.repository
        issues = self.paginate(f"/repos/{repo}/issues?state=all&labels=secpipe", limit=1000)
        ages: dict[str, list[float]] = {}
        mttr: dict[str, list[float]] = {}
        breached = 0
        for issue in issues:
            if "pull_request" in issue:
                continue
            labels = {as_str(as_dict(label).get("name")) for label in as_list(issue.get("labels"))}
            severity = next((name.split(":", 1)[1] for name in labels if name.startswith("sev:")), None)
            if severity is None:
                continue
            created = _parse_time(as_str(issue.get("created_at")))
            if created is None:
                continue
            if as_str(issue.get("state")) == "open":
                ages.setdefault(severity, []).append((today - created.date()).days)
                breached += "sla-breached" in labels
            else:
                closed = _parse_time(as_str(issue.get("closed_at")))
                if closed is not None:
                    mttr.setdefault(severity, []).append((closed - created).total_seconds() / 86400)
        metrics: list[tuple[str, dict[str, str], float]] = []
        for severity, values in sorted(ages.items()):
            metrics.append(("secpipe_issue_age_days", {"severity": severity}, sum(values) / len(values)))
            metrics.append(("secpipe_open_issues", {"severity": severity}, len(values)))
        for severity, values in sorted(mttr.items()):
            metrics.append(("secpipe_mttr_days", {"severity": severity}, sum(values) / len(values)))
        metrics.append(("secpipe_sla_breached_issues", {}, breached))
        return metrics


def _parse_time(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _title(finding: Finding) -> str:
    what = finding.cve or finding.rule_id
    return f"[SecPipe] {finding.severity.label}: {what} in {finding.location}"[:250]


def _labels(finding: Finding) -> list[str]:
    labels = [
        *BASE_LABELS,
        f"sev:{finding.severity.label}",
        f"tool:{finding.tool}",
        f"category:{finding.category}",
    ]
    if finding.fix_available is False:
        labels.append("no-fix-available")
    return labels


def _body(finding: Finding, sha: str, run_url: str | None) -> str:
    rows = [
        ("Severity", finding.severity.label),
        ("Tool(s)", ", ".join(finding.tools)),
        ("Rule", finding.rule_id),
        ("Location", f"`{finding.location}`"),
        ("CVE / CWE", " / ".join(x for x in (finding.cve, finding.cwe) if x) or "-"),
        (
            "Fix",
            finding.fix_version or ("no fix available yet" if finding.fix_available is False else "see guidance"),
        ),
        (
            "EPSS / KEV",
            f"{finding.epss if finding.epss is not None else '-'} / {'yes' if finding.in_kev else 'no'}",
        ),
        ("Due (SLA)", finding.due_date or "-"),
        ("First seen", finding.first_seen or "-"),
        ("Detected at", sha[:12]),
    ]
    table = "\n".join(f"| {k} | {v} |" for k, v in rows)
    run = f"\n[Workflow run]({run_url})" if run_url else ""
    return (
        f"<!-- secpipe:fingerprint={finding.fingerprint} -->\n"
        f"**{finding.title}**\n\n| Field | Value |\n|---|---|\n{table}\n\n"
        f"{finding.description}\n{run}\n\n"
        "_Opened automatically by SecPipe; it closes itself when the finding disappears._"
    )


def _rollup_body(findings: list[Finding], key: str, branch: str, sha: str, run_url: str | None) -> str:
    rows = "\n".join(
        f"| {f.cve or f.rule_id} | {f.severity.label} | `{f.location}` | {len(f.related_packages) + 1} |"
        for f in sorted(findings, key=lambda x: (-int(x.severity), x.location))[:200]
    )
    run = f"\n[Workflow run]({run_url})" if run_url else ""
    return (
        f"<!-- secpipe:fingerprint={key} -->\n"
        f"The `{branch}` image contains {len(findings)} high/critical OS CVEs for which the distribution has "
        "not shipped a fix. Policy: warn, do not block. Rebuild when fixes land (Dependabot bumps the base digest); "
        "consider a distroless/Chainguard base to shrink this list.\n\n"
        f"| CVE | Severity | Package | Binary packages |\n|---|---|---|---|\n{rows}\n\n"
        f"Last updated at {sha[:12]}.{run}"
    )
