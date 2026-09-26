"""Normalised log events from the app, ingress-nginx and Falco."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from secpipe.aggregator.normalize import as_dict, as_int, as_str

SUSPICIOUS_QUERY = (
    "' or",
    "union select",
    "--",
    "/*",
    "sleep(",
    "../",
    "%27",
    "169.254.169.254",
    "metadata.google",
)
INTERNAL_NAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "postgres",
    "kubernetes",
    "kubernetes.default",
}


@dataclass(frozen=True)
class LogEvent:
    ts: dt.datetime
    source: str  # app | ingress | falco | audit
    fields: dict[str, Any] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def event(self) -> str:
        return as_str(self.fields.get("event"))

    @property
    def ip(self) -> str:
        return as_str(self.fields.get("client_ip") or self.fields.get("remote_addr"))

    @property
    def pod(self) -> str:
        output = as_dict(self.fields.get("output_fields"))
        return as_str(self.labels.get("pod") or output.get("k8s.pod.name") or self.fields.get("host"))

    @property
    def path(self) -> str:
        return as_str(self.fields.get("path")) or urlsplit(as_str(self.fields.get("request_uri"))).path

    @property
    def query(self) -> str:
        return as_str(self.fields.get("query")) or urlsplit(as_str(self.fields.get("request_uri"))).query

    @property
    def status(self) -> int | None:
        return as_int(self.fields.get("status"))

    def is_failed_login(self) -> bool:
        """A rejected login attempt, including ones stopped by the rate limiter:
        a 429 is still an attacker guessing, just a blocked guess."""
        if self.source == "app":
            return self.event == "login_failed" or (self.event == "rate_limited" and self.path == "/auth/login")
        return self.source == "ingress" and self.path == "/auth/login" and self.status in {401, 429}

    def is_successful_login(self) -> bool:
        if self.source == "app":
            return self.event == "login_success"
        return self.source == "ingress" and self.path == "/auth/login" and self.status == 200

    def preview_target(self) -> str | None:
        if self.source == "app" and self.event == "preview_blocked":
            return as_str(self.fields.get("target_address") or self.fields.get("target_host")) or None
        if self.path == "/preview":
            values = parse_qs(self.query).get("url")
            if values:
                return urlsplit(values[0]).hostname
        return None

    def is_suspicious_request(self) -> bool:
        if self.source not in {"app", "ingress"}:
            return False
        if self.event in {"preview_blocked", "import_rejected", "token_rejected", "authz_denied"}:
            return True
        target = self.preview_target()
        if target and target_class(target) != "public":
            return True
        lowered = self.query.lower()
        return any(marker in lowered for marker in SUSPICIOUS_QUERY)

    def is_falco_alert(self) -> bool:
        if self.source != "falco":
            return False
        rule = as_str(self.fields.get("rule")).lower()
        priority = as_str(self.fields.get("priority")).lower()
        return "shell" in rule or priority in {"critical", "error", "warning", "alert", "emergency"}


def target_class(host: str) -> str:
    host = host.strip("[]").lower()
    if host in INTERNAL_NAMES or host.endswith((".svc", ".svc.cluster.local", ".internal", ".local")):
        return "internal_name"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "public"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private or ip.is_reserved or ip.is_unspecified or not ip.is_global:
        return "private"
    return "public"


def _parse_ts(value: object, fallback_ns: str | None = None) -> dt.datetime:
    if isinstance(value, str) and value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
        except ValueError:
            pass
    if fallback_ns:
        return dt.datetime.fromtimestamp(int(fallback_ns) / 1e9, dt.UTC)
    return dt.datetime.now(dt.UTC)


def classify(labels: dict[str, str], fields: dict[str, Any]) -> str:
    if "output_fields" in fields and "rule" in fields:
        return "falco"
    if labels.get("namespace") == "ingress-nginx" or "request_uri" in fields:
        return "ingress"
    if fields.get("kind") == "Event" and "auditID" in fields:
        return "audit"
    return "app"


def from_line(line: str, labels: dict[str, str] | None = None, ts_ns: str | None = None) -> LogEvent | None:
    try:
        fields = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(fields, dict):
        return None
    labels = labels or {}
    ts = _parse_ts(
        fields.get("ts") or fields.get("time") or fields.get("timestamp") or fields.get("stageTimestamp"),
        ts_ns,
    )
    return LogEvent(ts=ts, source=classify(labels, fields), fields=fields, labels=dict(labels))


def from_record(record: dict[str, Any]) -> LogEvent | None:
    """A JSONL fixture record: {"labels": {...}, "line": "<raw log line>"} or a bare log object."""
    if "line" in record:
        return from_line(as_str(record.get("line")), {str(k): str(v) for k, v in as_dict(record.get("labels")).items()})
    return from_line(json.dumps(record))
