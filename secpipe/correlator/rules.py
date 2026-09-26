"""Correlation rules. Each rule is a pure function of (events, now).

| Rule                        | Logic                                                        | Severity |
|-----------------------------|--------------------------------------------------------------|----------|
| brute_force                 | >= 10 failed logins from one IP in 5 minutes                 | medium   |
| credential_stuffing         | >= 5 distinct usernames failing from one IP in 5 minutes     | high     |
| brute_force_then_success    | success from an IP flagged for brute force within 30 minutes | critical |
| ssrf_probe                  | /preview to private, loopback or link-local targets          | high     |
| post_exploitation_chain     | Falco alert in a pod <= 10 min after a suspicious request to it | critical |
| token_misuse                | same JWT jti used from two IPs within 5 minutes              | high     |
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from secpipe.aggregator.normalize import as_str
from secpipe.correlator.events import LogEvent, target_class

FIVE_MIN = dt.timedelta(minutes=5)
TEN_MIN = dt.timedelta(minutes=10)
THIRTY_MIN = dt.timedelta(minutes=30)
BRUTE_FORCE_THRESHOLD = 10
STUFFING_THRESHOLD = 5


@dataclass
class Alert:
    rule: str
    severity: str
    summary: str
    description: str
    runbook: str
    labels: dict[str, str] = field(default_factory=dict)
    first_seen: dt.datetime | None = None
    last_seen: dt.datetime | None = None
    evidence: int = 0

    @property
    def key(self) -> tuple[str, tuple[tuple[str, str], ...]]:
        return self.rule, tuple(sorted(self.labels.items()))


def _max_in_window(times: list[dt.datetime], window: dt.timedelta) -> tuple[int, dt.datetime | None]:
    """Largest number of events inside any sliding window, and when it peaked."""
    times = sorted(times)
    best, best_end, start = 0, None, 0
    for end, ts in enumerate(times):
        while ts - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, best_end = end - start + 1, ts
    return best, best_end


def _failed_by_ip(events: list[LogEvent]) -> dict[str, list[LogEvent]]:
    """Failed logins per IP, counting app and ingress logs for the same request once."""
    app: dict[str, list[LogEvent]] = defaultdict(list)
    ingress: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.is_failed_login() and e.ip:
            (app if e.source == "app" else ingress)[e.ip].append(e)
    return {ip: max(app.get(ip, []), ingress.get(ip, []), key=len) for ip in set(app) | set(ingress)}


def brute_force(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    alerts = []
    for ip, failures in _failed_by_ip(events).items():
        count, peak = _max_in_window([e.ts for e in failures], FIVE_MIN)
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append(
                Alert(
                    rule="brute_force",
                    severity="medium",
                    summary=f"Brute force: {count} failed logins from {ip} within 5 minutes",
                    description=f"{count} failed logins from {ip} in a 5-minute window (peak at {peak:%H:%M:%S}Z).",
                    runbook="brute-force.md",
                    labels={"source_ip": ip},
                    first_seen=min(e.ts for e in failures),
                    last_seen=max(e.ts for e in failures),
                    evidence=count,
                )
            )
    return alerts


def credential_stuffing(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    alerts = []
    for ip, failures in _failed_by_ip(events).items():
        failures = sorted((e for e in failures if as_str(e.fields.get("username"))), key=lambda e: e.ts)
        best: set[str] = set()
        start = 0
        for end, event in enumerate(failures):
            while event.ts - failures[start].ts > FIVE_MIN:
                start += 1
            users = {as_str(e.fields.get("username")) for e in failures[start : end + 1]}
            if len(users) > len(best):
                best = users
        if len(best) >= STUFFING_THRESHOLD:
            alerts.append(
                Alert(
                    rule="credential_stuffing",
                    severity="high",
                    summary=f"Credential stuffing: {len(best)} usernames tried from {ip} within 5 minutes",
                    description=f"Distinct usernames: {', '.join(sorted(best)[:10])}.",
                    runbook="brute-force.md",
                    labels={"source_ip": ip},
                    first_seen=failures[0].ts,
                    last_seen=failures[-1].ts,
                    evidence=len(best),
                )
            )
    return alerts


def brute_force_then_success(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    alerts = []
    failures = _failed_by_ip(events)
    for event in sorted((e for e in events if e.is_successful_login() and e.ip), key=lambda e: e.ts):
        prior = [f.ts for f in failures.get(event.ip, []) if event.ts - THIRTY_MIN <= f.ts <= event.ts]
        count, _ = _max_in_window(prior, FIVE_MIN)
        if count >= BRUTE_FORCE_THRESHOLD:
            user = as_str(event.fields.get("username"), "unknown")
            alerts.append(
                Alert(
                    rule="brute_force_then_success",
                    severity="critical",
                    summary=f"Successful login for '{user}' from {event.ip} after brute force",
                    description=(
                        f"{event.ip} made {count} failed attempts within 5 minutes, then logged in as '{user}' "
                        f"at {event.ts:%H:%M:%S}Z. Treat the account as compromised."
                    ),
                    runbook="brute-force.md",
                    labels={"source_ip": event.ip, "username": user},
                    first_seen=min(prior),
                    last_seen=event.ts,
                    evidence=count + 1,
                )
            )
    return _unique(alerts)


def ssrf_probe(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    hits: dict[str, list[tuple[LogEvent, str]]] = defaultdict(list)
    for event in events:
        target = event.preview_target()
        if target and target_class(target) != "public" and event.ip:
            hits[event.ip].append((event, target))
    alerts = []
    for ip, items in hits.items():
        targets = sorted({t for _, t in items})
        alerts.append(
            Alert(
                rule="ssrf_probe",
                severity="high",
                summary=f"SSRF probe from {ip}: /preview aimed at {', '.join(targets[:3])}",
                description=f"{len(items)} /preview requests to internal targets ({', '.join(targets)}).",
                runbook="container-compromise.md",
                labels={"source_ip": ip},
                first_seen=min(e.ts for e, _ in items),
                last_seen=max(e.ts for e, _ in items),
                evidence=len(items),
            )
        )
    return alerts


def post_exploitation_chain(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    suspicious: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.is_suspicious_request() and event.pod:
            suspicious[event.pod].append(event)
    alerts = []
    for falco in (e for e in events if e.is_falco_alert() and e.pod):
        prior = [s for s in suspicious.get(falco.pod, []) if falco.ts - TEN_MIN <= s.ts <= falco.ts]
        if not prior:
            continue
        ips = sorted({s.ip for s in prior if s.ip})
        rule_name = as_str(falco.fields.get("rule"))
        alerts.append(
            Alert(
                rule="post_exploitation_chain",
                severity="critical",
                summary=f"Post-exploitation chain in pod {falco.pod}: '{rule_name}' after suspicious requests",
                description=(
                    f"Falco '{rule_name}' at {falco.ts:%H:%M:%S}Z followed {len(prior)} suspicious "
                    f"request(s) to the same pod from {', '.join(ips) or 'unknown'} within 10 minutes. "
                    "Quarantine the pod (scripts/quarantine-pod.sh)."
                ),
                runbook="container-compromise.md",
                labels={"pod": falco.pod, "source_ip": ips[0] if ips else "unknown"},
                first_seen=min(s.ts for s in prior),
                last_seen=falco.ts,
                evidence=len(prior) + 1,
            )
        )
    return _unique(alerts)


def token_misuse(events: list[LogEvent], now: dt.datetime) -> list[Alert]:
    by_jti: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        jti = as_str(event.fields.get("jti"))
        if jti and event.ip and event.source == "app":
            by_jti[jti].append(event)
    alerts = []
    for jti, uses in by_jti.items():
        uses.sort(key=lambda e: e.ts)
        for i, first in enumerate(uses):
            others = {u.ip for u in uses[i + 1 :] if u.ts - first.ts <= FIVE_MIN and u.ip != first.ip}
            if others:
                ips = sorted({first.ip, *others})
                alerts.append(
                    Alert(
                        rule="token_misuse",
                        severity="high",
                        summary=f"JWT {jti[:8]}... used from {len(ips)} IPs within 5 minutes",
                        description=f"Token id {jti} seen from {', '.join(ips)}: likely a stolen bearer token.",
                        runbook="container-compromise.md",
                        labels={"jti": jti, "source_ip": ips[0]},
                        first_seen=first.ts,
                        last_seen=uses[-1].ts,
                        evidence=len(uses),
                    )
                )
                break
    return alerts


def _unique(alerts: list[Alert]) -> list[Alert]:
    seen: dict[tuple[str, tuple[tuple[str, str], ...]], Alert] = {}
    for alert in alerts:
        seen[alert.key] = alert  # keep the latest occurrence
    return list(seen.values())


Rule = Callable[[list[LogEvent], dt.datetime], list[Alert]]
RULES: dict[str, Rule] = {
    "brute_force": brute_force,
    "credential_stuffing": credential_stuffing,
    "brute_force_then_success": brute_force_then_success,
    "ssrf_probe": ssrf_probe,
    "post_exploitation_chain": post_exploitation_chain,
    "token_misuse": token_misuse,
}


def evaluate(events: list[LogEvent], now: dt.datetime, enabled: list[str] | None = None) -> list[Alert]:
    alerts: list[Alert] = []
    for name, rule in RULES.items():
        if enabled is None or name in enabled:
            alerts.extend(rule(events, now))
    return alerts
