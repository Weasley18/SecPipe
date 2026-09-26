"""Kubescape JSON (``--format json --format-version v2``). The control ID is
the rule; the Kubernetes object is the location."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_float, as_list, as_str, clamp_text
from secpipe.aggregator.parsers.base import load_json


def _severity(control: dict[str, Any]) -> Severity:
    label = as_str(control.get("severity"))
    if label:
        return Severity.parse(label, Severity.MEDIUM)
    score = as_float(control.get("scoreFactor") or control.get("baseScore"))
    if score is None:
        return Severity.MEDIUM
    # Kubescape: 1-3 low, 4-6 medium, 7-8 high, 9-10 critical
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _object_name(resource_id: str, resources: dict[str, dict[str, Any]]) -> str:
    obj = as_dict(resources.get(resource_id, {}).get("object"))
    meta = as_dict(obj.get("metadata"))
    if obj.get("kind") and meta.get("name"):
        namespace = as_str(meta.get("namespace"), "default")
        return f"{as_str(obj.get('kind'))}.{namespace}.{as_str(meta.get('name'))}"
    # resourceID looks like "path=123/api=apps/v1/secnotes/Deployment/secnotes-api"
    parts = re.sub(r"^.*?api=", "", resource_id).split("/")
    if len(parts) >= 3:
        return f"{parts[-2]}.{parts[-3] or 'default'}.{parts[-1]}"
    return resource_id


def _status(control: dict[str, Any]) -> str:
    status = control.get("status")
    if isinstance(status, dict):
        return as_str(status.get("status")).lower()
    return as_str(status).lower()


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="kubescape", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "results" not in data and "summaryDetails" not in data:
        result.errors = [f"{path.name} is not a Kubescape JSON report"]
        return result
    summary_controls = as_dict(as_dict(data.get("summaryDetails")).get("controls"))
    resources = {as_str(r.get("resourceID")): r for r in (as_dict(x) for x in as_list(data.get("resources")))}
    for res in as_list(data.get("results")):
        res = as_dict(res)
        resource_id = as_str(res.get("resourceID"))
        target = _object_name(resource_id, resources)
        for control in as_list(res.get("controls")):
            control = as_dict(control)
            if _status(control) != "failed":
                continue
            result.raw_count += 1
            cid = as_str(control.get("controlID") or control.get("id"))
            meta = as_dict(summary_controls.get(cid))
            # A path entry names the offending field as failedPath, deletePath
            # (remove it), reviewPath (inspect it) or fixPath.path (set it).
            paths = [
                as_str(
                    as_dict(p).get("failedPath")
                    or as_dict(p).get("deletePath")
                    or as_dict(p).get("reviewPath")
                    or as_dict(as_dict(p).get("fixPath")).get("path")
                )
                for rule in as_list(control.get("rules"))
                for p in as_list(as_dict(rule).get("paths"))
            ]
            result.findings.append(
                Finding(
                    tool="kubescape",
                    category="k8s",
                    rule_id=cid,
                    title=clamp_text(as_str(control.get("name") or meta.get("name")), 160),
                    severity=_severity({**meta, **control}),
                    location=target,
                    description=clamp_text("Failed paths: " + ", ".join(p for p in paths if p)) if any(paths) else "",
                    help_url=f"https://hub.armosec.io/docs/{cid.lower()}" if cid else None,
                    raw_severity=as_str(control.get("severity") or meta.get("severity")) or None,
                )
            )
    return result
