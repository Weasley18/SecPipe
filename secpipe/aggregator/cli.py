"""``secpipe`` command line.

    secpipe gate --reports reports/ --expect gitleaks,semgrep,... \\
                 --policy policy/policy.yaml --branch main \\
                 --baseline baseline/findings.json --out out/

Exit codes for ``gate``: 0 pass, 1 blocked by policy, 2 tool/config error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from secpipe import __version__
from secpipe.aggregator.gate import EXIT_ERROR, GateOptions, run_gate
from secpipe.aggregator.models import Finding
from secpipe.aggregator.normalize import as_dict, as_list
from secpipe.aggregator.policy import Policy, PolicyError, schema


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _default_branch(event: str) -> str | None:
    if event.startswith("pull_request") and os.environ.get("GITHUB_BASE_REF"):
        return os.environ["GITHUB_BASE_REF"]
    return os.environ.get("GITHUB_REF_NAME") or None


def _run_url() -> str | None:
    server, repo, run = (os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    return f"{server}/{repo}/actions/runs/{run}" if server and repo and run else None


# ---------------------------------------------------------------------- gate
def cmd_gate(args: argparse.Namespace) -> int:
    from secpipe.reporters import write_outputs

    event = args.event or os.environ.get("GITHUB_EVENT_NAME", "push")
    opts = GateOptions(
        reports=Path(args.reports),
        policy=Path(args.policy),
        expect=_csv(args.expect),
        branch=args.branch or _default_branch(event),
        event=event,
        baseline=Path(args.baseline) if args.baseline else None,
        out=Path(args.out),
        stage=args.stage,
        source_root=Path(args.source_root) if args.source_root else None,
        offline=args.offline,
        cache_dir=Path(args.cache_dir),
        labels=tuple(_csv(args.labels)),
        today=dt.date.fromisoformat(args.today) if args.today else None,
        commit=args.commit or os.environ.get("GITHUB_SHA"),
        policy_ref=args.policy_ref,
        run_url=args.run_url or _run_url(),
        repository=args.repository or os.environ.get("GITHUB_REPOSITORY"),
    )
    result = run_gate(opts)
    write_outputs(result, opts.out or Path("out"))
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write((opts.out or Path("out")).joinpath("summary.md").read_text(encoding="utf-8"))
    stats = result.dedupe
    print(
        f"secpipe {opts.stage}: {result.outcome.upper()} "
        f"({len(result.blocking)} blocking, {len(result.warned)} warnings; "
        f"{stats.raw} raw results -> {stats.unique} unique findings; policy {result.policy_ref})"
    )
    for problem in result.tool_errors:
        print(f"  FAILED CLOSED: {problem}", file=sys.stderr)
    for problem in result.evaluation.gate_errors:
        print(f"  POLICY: {problem}", file=sys.stderr)
    for finding in result.blocking[:25]:
        print(f"  BLOCK {finding.severity.name:8} {finding.tool:12} {finding.title[:70]} @ {finding.location}")
    return result.exit_code


# -------------------------------------------------------------------- policy
def cmd_policy(args: argparse.Namespace) -> int:
    if args.action == "schema":
        print(json.dumps(schema(), indent=2))
        return 0
    status = 0
    for path in args.files:
        try:
            policy = Policy.load(Path(path))
        except PolicyError as exc:
            print(f"INVALID {exc}", file=sys.stderr)
            status = EXIT_ERROR
            continue
        today = dt.date.today()
        expired = [e for e in policy.exceptions if e.expires < today]
        print(f"OK {path} ({len(policy.exceptions)} exceptions, {len(policy.severity_overrides)} overrides)")
        for item in expired:
            print(f"  EXPIRED exception {item.label} ({item.owner}, {item.expires})", file=sys.stderr)
            status = max(status, 1)
    return status


# -------------------------------------------------------------------- github
def _client(args: argparse.Namespace) -> Any:
    from secpipe.reporters.github import GitHubClient

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise SystemExit("GITHUB_TOKEN and --repository (or GITHUB_REPOSITORY) are required")
    return GitHubClient(token, repository, api=os.environ.get("GITHUB_API_URL", "https://api.github.com"))


def cmd_github_comment(args: argparse.Namespace) -> int:
    from secpipe.reporters.markdown import MARKER

    body = Path(args.body).read_text(encoding="utf-8")
    action, cid = _client(args).upsert_comment(int(args.pr), body, args.marker or MARKER)
    print(f"{action} comment {cid} on #{args.pr}")
    return 0


def cmd_github_issues(args: argparse.Namespace) -> int:
    document = as_dict(json.loads(Path(args.findings).read_text(encoding="utf-8")))
    findings = [
        Finding.from_dict(as_dict(f)) for f in as_list(document.get("findings")) if as_dict(f).get("status") != "fixed"
    ]
    report = _client(args).sync_issues(
        findings,
        sha=args.sha or os.environ.get("GITHUB_SHA", "unknown"),
        branch=args.branch or os.environ.get("GITHUB_REF_NAME", "main"),
        today=dt.date.today(),
        run_url=args.run_url or _run_url(),
        max_new=args.max_new,
    )
    print(
        f"issues: {len(report.opened)} opened, {len(report.updated)} updated, {len(report.closed)} closed, "
        f"{len(report.breached)} newly SLA-breached, {report.skipped} deferred (cap {args.max_new})"
    )
    if args.metrics_out:
        Path(args.metrics_out).write_text(
            json.dumps([{"name": n, "labels": labels, "value": v} for n, labels, v in report.metrics], indent=2),
            encoding="utf-8",
        )
    return 0


# ------------------------------------------------------------------- metrics
def cmd_metrics_append(args: argparse.Namespace) -> int:
    record = as_dict(json.loads(Path(args.record).read_text(encoding="utf-8")))
    for extra in args.extra or []:
        path = Path(extra)
        if path.exists():
            record.setdefault("samples", []).extend(as_list(json.loads(path.read_text(encoding="utf-8"))))
    history = Path(args.history)
    history.parent.mkdir(parents=True, exist_ok=True)
    with history.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    print(f"appended {len(as_list(record.get('samples')))} samples to {history}")
    return 0


def cmd_metrics_backfill(args: argparse.Namespace) -> int:
    from secpipe.exporter import backfill

    sys.stdout.write(backfill(Path(args.history).read_text(encoding="utf-8")))
    return 0


def cmd_exporter(args: argparse.Namespace) -> int:
    from secpipe.exporter import serve

    serve(args.history, port=args.port, refresh=args.refresh)
    return 0


def cmd_defectdojo(args: argparse.Namespace) -> int:
    from secpipe.reporters.defectdojo import import_reports

    token = os.environ.get("DEFECTDOJO_TOKEN")
    if not token:
        raise SystemExit("DEFECTDOJO_TOKEN is required")
    report = import_reports(
        Path(args.reports),
        url=args.url,
        token=token,
        engagement=args.engagement,
        commit=os.environ.get("GITHUB_SHA"),
        branch=os.environ.get("GITHUB_REF_NAME"),
    )
    print(f"defectdojo: {len(report.imported)} imported, {len(report.skipped)} skipped, {len(report.failed)} failed")
    for failure in report.failed:
        print(f"  {failure}", file=sys.stderr)
    return 1 if report.failed else 0


def cmd_correlate(args: argparse.Namespace) -> int:
    from secpipe.correlator.cli import run

    return run(args)


# ---------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpipe", description="SecPipe security gate and tooling")
    parser.add_argument("--version", action="version", version=f"secpipe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="aggregate reports, apply policy, exit 0/1/2")
    gate.add_argument("--reports", required=True, help="directory of scanner reports")
    gate.add_argument("--expect", default="", help="comma-separated scanners that must have produced a report")
    gate.add_argument("--policy", default="policy/policy.yaml")
    gate.add_argument("--branch", help="branch whose policy applies (default: PR base or pushed branch)")
    gate.add_argument("--baseline", help="findings.json from the base branch")
    gate.add_argument("--out", default="out")
    gate.add_argument("--event", help="pull_request | push | schedule (default: $GITHUB_EVENT_NAME)")
    gate.add_argument("--stage", default="gate", help="label for this gate run, e.g. gate-1 or gate-2")
    gate.add_argument("--source-root", default=".", help="repository root for the suppression inventory")
    gate.add_argument("--offline", action="store_true", help="skip EPSS/KEV enrichment")
    gate.add_argument("--cache-dir", default=".secpipe-cache", help="EPSS/KEV cache (24h TTL)")
    gate.add_argument("--labels", help="PR labels, comma-separated")
    gate.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests and replays")
    gate.add_argument("--commit")
    gate.add_argument("--policy-ref")
    gate.add_argument("--run-url")
    gate.add_argument("--repository")
    gate.add_argument("--step-summary", action="store_true", help="append summary.md to $GITHUB_STEP_SUMMARY")
    gate.set_defaults(func=cmd_gate)

    policy = sub.add_parser("policy", help="validate policy files against the JSON Schema")
    policy.add_argument("action", choices=["validate", "schema"])
    policy.add_argument("files", nargs="*", default=["policy/policy.yaml"])
    policy.set_defaults(func=cmd_policy)

    github = sub.add_parser("github", help="PR comment and Issue sync")
    gh_sub = github.add_subparsers(dest="github_command", required=True)
    comment = gh_sub.add_parser("comment", help="create or update the sticky PR comment")
    comment.add_argument("--pr", required=True)
    comment.add_argument("--body", default="out/comment.md")
    comment.add_argument("--marker")
    comment.add_argument("--repository")
    comment.set_defaults(func=cmd_github_comment)
    issues = gh_sub.add_parser("issues", help="sync high/critical findings to GitHub Issues")
    issues.add_argument("--findings", default="out/findings.json")
    issues.add_argument("--sha")
    issues.add_argument("--branch")
    issues.add_argument("--run-url")
    issues.add_argument("--repository")
    issues.add_argument("--max-new", type=int, default=25)
    issues.add_argument("--metrics-out")
    issues.set_defaults(func=cmd_github_issues)

    metrics = sub.add_parser("metrics", help="metrics history for Prometheus/Grafana")
    m_sub = metrics.add_subparsers(dest="metrics_command", required=True)
    append = m_sub.add_parser("append", help="append a run's metrics.json to history.jsonl")
    append.add_argument("--record", default="out/metrics.json")
    append.add_argument("--history", default="metrics/history.jsonl")
    append.add_argument("--extra", action="append", help="extra samples file (e.g. issue metrics)")
    append.set_defaults(func=cmd_metrics_append)
    backfill = m_sub.add_parser("backfill", help="history.jsonl -> OpenMetrics for promtool backfill")
    backfill.add_argument("--history", default="metrics/history.jsonl")
    backfill.set_defaults(func=cmd_metrics_backfill)

    exporter = sub.add_parser("exporter", help="serve the latest metrics from history.jsonl on /metrics")
    exporter.add_argument("--history", required=True, help="path or https URL of history.jsonl")
    exporter.add_argument("--port", type=int, default=9108)
    exporter.add_argument("--refresh", type=int, default=300, help="seconds between history reloads")
    exporter.set_defaults(func=cmd_exporter)

    dojo = sub.add_parser("defectdojo", help="import raw reports into DefectDojo")
    dojo.add_argument("--reports", default="reports")
    dojo.add_argument("--url", required=True)
    dojo.add_argument("--engagement", type=int, required=True)
    dojo.set_defaults(func=cmd_defectdojo)

    from secpipe.correlator.cli import add_arguments

    correlate = sub.add_parser("correlate", help="run log-correlation rules (Loki -> Alertmanager)")
    add_arguments(correlate)
    correlate.set_defaults(func=cmd_correlate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.func(args)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
