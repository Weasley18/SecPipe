"""``secpipe correlate``: query Loki, apply the rules, push alerts to Alertmanager."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

from secpipe.aggregator.normalize import as_dict
from secpipe.correlator.clients import AlertmanagerClient, LokiClient, to_alertmanager
from secpipe.correlator.events import LogEvent, from_record
from secpipe.correlator.rules import RULES, evaluate
from secpipe.http import HttpError

# Stream labels set by Grafana Alloy (monitoring/alloy/config.alloy).
DEFAULT_QUERIES = [
    '{namespace="secnotes", app="secnotes-api"}',
    '{namespace="ingress", app="traefik"} |= "RequestPath"',
    '{namespace="monitoring", app="falco"} |= "output_fields"',
]


def parse_duration(value: str) -> dt.timedelta:
    match = re.fullmatch(r"(\d+)([smh])", value.strip())
    if not match:
        raise argparse.ArgumentTypeError(f"invalid duration {value!r} (use e.g. 35m)")
    amount, unit = int(match.group(1)), match.group(2)
    return dt.timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[unit]: amount})


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--loki-url", default="http://loki.monitoring.svc:3100")
    parser.add_argument("--alertmanager-url", default="http://alertmanager.monitoring.svc:9093")
    parser.add_argument("--grafana-url", default="http://localhost:3000")
    parser.add_argument("--query", action="append", help="LogQL stream selector (repeatable)")
    parser.add_argument("--lookback", type=parse_duration, default=dt.timedelta(minutes=35))
    parser.add_argument("--rules", help="comma-separated subset of: " + ", ".join(RULES))
    parser.add_argument("--from-file", help="JSONL events instead of Loki (tests, replays)")
    parser.add_argument("--now", help="evaluation time (ISO 8601), default: now")
    parser.add_argument("--dry-run", action="store_true", help="print alerts, do not send them")
    parser.add_argument("--output", help="also write the Alertmanager payload to this file")


def load_events(args: argparse.Namespace, now: dt.datetime) -> list[LogEvent]:
    if args.from_file:
        events = []
        for line in Path(args.from_file).read_text(encoding="utf-8").splitlines():
            if line.strip():
                event = from_record(as_dict(json.loads(line)))
                if event is not None:
                    events.append(event)
        return events
    loki = LokiClient(args.loki_url)
    start = now - args.lookback
    events = []
    for query in args.query or DEFAULT_QUERIES:
        events.extend(loki.query_range(query, start, now))
    return events


def run(args: argparse.Namespace) -> int:
    now = dt.datetime.fromisoformat(args.now) if args.now else dt.datetime.now(dt.UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.UTC)
    try:
        events = load_events(args, now)
    except HttpError as exc:
        print(f"correlate: cannot query Loki: {exc}", file=sys.stderr)
        return 2
    enabled = [r.strip() for r in args.rules.split(",")] if args.rules else None
    alerts = evaluate(sorted(events, key=lambda e: e.ts), now, enabled)
    payload = [to_alertmanager(a, now, args.grafana_url) for a in alerts]
    print(f"correlate: {len(events)} events, {len(alerts)} alerts")
    for alert in alerts:
        print(f"  [{alert.severity.upper():8}] {alert.rule}: {alert.summary}")
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if not args.dry_run and payload:
        try:
            AlertmanagerClient(args.alertmanager_url).send(payload)
        except HttpError as exc:
            print(f"correlate: cannot reach Alertmanager: {exc}", file=sys.stderr)
            return 2
    return 0
