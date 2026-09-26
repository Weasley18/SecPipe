"""Optional DefectDojo import: ``POST /api/v2/import-scan/`` per tool report.

DefectDojo then does its own cross-run deduplication and gives the security
team a central finding database. Enabled when DEFECTDOJO_URL and
DEFECTDOJO_TOKEN are set.
"""

from __future__ import annotations

import secrets
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from secpipe.aggregator.parsers import spec_for
from secpipe.http import HttpError, check_url

SCAN_TYPES: dict[str, str] = {
    "gitleaks": "Gitleaks Scan",
    "semgrep": "SARIF",
    "hadolint": "SARIF",
    "zizmor": "SARIF",
    "bandit": "Bandit Scan",
    "trivy": "Trivy Scan",
    "checkov": "Checkov Scan",
    "kubescape": "Kubescape JSON Importer",
    "snyk": "Snyk Scan",
    "osv-scanner": "OSV Scan",
    "pip-audit": "pip-audit Scan",
    "grype": "Anchore Grype",
    "prowler": "Prowler Scan",
}

Poster = Callable[[str, bytes, dict[str, str]], int]


@dataclass
class ImportReport:
    imported: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


def _multipart(fields: dict[str, str], file_name: str, content: bytes) -> tuple[bytes, str]:
    boundary = f"secpipe-{secrets.token_hex(12)}"
    parts: list[bytes] = []
    for key, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{file_name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    check_url(url)
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310 -- scheme checked
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310  # nosec B310 -- scheme validated by check_url()
            return int(resp.status)
    except OSError as exc:
        raise HttpError(f"DefectDojo import failed: {exc}") from exc


def import_reports(
    reports: Path,
    *,
    url: str,
    token: str,
    engagement: int,
    commit: str | None = None,
    branch: str | None = None,
    post: Poster = _post,
) -> ImportReport:
    result = ImportReport()
    endpoint = url.rstrip("/") + "/api/v2/import-scan/"
    for path in sorted(p for p in reports.rglob("*") if p.is_file()):
        spec = spec_for(path)
        if spec is None:
            continue
        scan_type = SCAN_TYPES.get(spec.tool)
        if scan_type is None:
            result.skipped.append(path.name)
            continue
        fields = {
            "scan_type": scan_type,
            "engagement": str(engagement),
            "active": "true",
            "verified": "false",
            "close_old_findings": "true",
            "deduplication_on_engagement": "true",
            "test_title": f"SecPipe {spec.tool}",
        }
        if commit:
            fields["commit_hash"] = commit
        if branch:
            fields["branch_tag"] = branch
        body, content_type = _multipart(fields, path.name, path.read_bytes())
        headers = {"Authorization": f"Token {token}", "Content-Type": content_type}
        try:
            status = post(endpoint, body, headers)
        except HttpError as exc:
            result.failed.append(f"{path.name}: {exc}")
            continue
        (result.imported if 200 <= status < 300 else result.failed).append(path.name)
    return result
