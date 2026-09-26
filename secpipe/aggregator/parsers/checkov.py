"""Checkov JSON (terraform, terraform_plan, kubernetes, dockerfile,
github_actions). Open-source Checkov reports no severity, so SecPipe keeps a
curated map for the checks that matter here; anything unmapped is MEDIUM and
can be tuned with ``severity_overrides`` in policy.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import as_dict, as_int, as_list, as_str, clamp_text, normalize_path
from secpipe.aggregator.parsers.base import load_json

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

SEVERITY: dict[str, Severity] = {
    # --- AWS: S3
    "CKV_AWS_20": H,
    "CKV_AWS_57": C,
    "CKV_AWS_53": H,
    "CKV_AWS_54": H,
    "CKV_AWS_55": H,
    "CKV_AWS_56": H,
    "CKV2_AWS_6": H,
    "CKV_AWS_19": H,
    "CKV_AWS_145": M,
    "CKV_AWS_21": M,
    "CKV_AWS_18": L,
    "CKV_AWS_144": L,
    "CKV2_AWS_61": L,
    "CKV2_AWS_62": L,
    "CKV_AWS_93": H,
    "CKV2_AWS_65": M,
    # --- AWS: network
    "CKV_AWS_24": H,
    "CKV_AWS_25": H,
    "CKV_AWS_260": M,
    "CKV_AWS_277": H,
    "CKV_AWS_23": L,
    "CKV2_AWS_5": L,
    "CKV_AWS_382": L,
    # --- AWS: IAM / OIDC
    "CKV_AWS_1": C,
    "CKV_AWS_49": C,
    "CKV_AWS_62": C,
    "CKV_AWS_63": C,
    "CKV_AWS_286": H,
    "CKV_AWS_287": H,
    "CKV_AWS_288": H,
    "CKV_AWS_289": H,
    "CKV_AWS_290": H,
    "CKV_AWS_355": H,
    "CKV_AWS_358": H,
    "CKV_AWS_107": H,
    "CKV_AWS_108": H,
    "CKV_AWS_109": H,
    "CKV_AWS_110": H,
    "CKV_AWS_111": H,
    "CKV2_AWS_40": H,
    # --- AWS: ECR / KMS
    "CKV_AWS_51": M,
    "CKV_AWS_163": M,
    "CKV_AWS_136": L,
    "CKV_AWS_7": M,
    "CKV2_AWS_64": L,
    "CKV_AWS_33": M,
    # --- SecPipe custom policies
    "CKV_SECPIPE_2": C,
    "CKV2_SECPIPE_1": L,
    # --- Kubernetes
    "CKV_K8S_16": C,
    "CKV_K8S_27": C,
    "CKV_K8S_39": H,
    "CKV_K8S_20": H,
    "CKV_K8S_23": H,
    "CKV_K8S_17": H,
    "CKV_K8S_19": H,
    "CKV_K8S_6": H,
    "CKV_K8S_14": H,
    "CKV_K8S_22": M,
    "CKV_K8S_28": M,
    "CKV_K8S_37": M,
    "CKV_K8S_10": L,
    "CKV_K8S_11": M,
    "CKV_K8S_12": L,
    "CKV_K8S_13": M,
    "CKV_K8S_8": L,
    "CKV_K8S_9": L,
    "CKV_K8S_15": L,
    "CKV_K8S_21": L,
    "CKV_K8S_29": M,
    "CKV_K8S_30": M,
    "CKV_K8S_31": M,
    "CKV_K8S_35": M,
    "CKV_K8S_38": M,
    "CKV_K8S_40": L,
    "CKV_K8S_43": L,
    "CKV2_K8S_6": M,
    "CKV_K8S_25": M,
    "CKV_K8S_26": M,
    # --- Dockerfile
    "CKV_DOCKER_1": H,
    "CKV_DOCKER_2": L,
    "CKV_DOCKER_3": H,
    "CKV_DOCKER_4": M,
    "CKV_DOCKER_7": M,
    "CKV_DOCKER_8": H,
    "CKV_DOCKER_5": L,
    "CKV_DOCKER_9": L,
    # --- GitHub Actions
    "CKV_GHA_1": H,
    "CKV_GHA_2": H,
    "CKV_GHA_3": M,
    "CKV_GHA_7": L,
    "CKV2_GHA_1": M,
}

CATEGORY = {
    "terraform": "iac",
    "terraform_plan": "iac",
    "cloudformation": "iac",
    "github_actions": "iac",
    "kubernetes": "k8s",
    "helm": "k8s",
    "kustomize": "k8s",
    "dockerfile": "container",
    "secrets": "secret",
}


def _reports(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [as_dict(r) for r in data]
    return [as_dict(data)]


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="checkov", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    reports = _reports(data)
    if not all("results" in r or "summary" in r or "passed" in r for r in reports):
        result.errors = [f"{path.name} is not a Checkov JSON report"]
        return result
    for report in reports:
        framework = as_str(report.get("check_type"), "unknown")
        category = CATEGORY.get(framework, "iac")
        results = as_dict(report.get("results"))
        summary = as_dict(report.get("summary"))
        if summary.get("parsing_errors"):
            result.warnings.append(f"checkov {framework}: {summary.get('parsing_errors')} file(s) failed to parse")
        result.suppressed += len(as_list(results.get("skipped_checks")))
        for check in as_list(results.get("failed_checks")):
            check = as_dict(check)
            result.raw_count += 1
            check_id = as_str(check.get("check_id"))
            raw = as_str(check.get("severity"))
            severity = Severity.parse(raw, None) if raw else SEVERITY.get(check_id, Severity.MEDIUM)
            file_path = as_str(check.get("repo_file_path") or check.get("file_path"))
            file = normalize_path(file_path) if file_path else None
            lines = as_list(check.get("file_line_range"))
            line = as_int(lines[0]) if lines else None
            resource = as_str(check.get("resource"))
            if category == "k8s":
                location = resource  # rendered manifests: the object is the useful address
            elif category == "container":
                location = f"{file}:{line}" if line else (file or resource)
            else:
                location = f"{file}:{resource}" if file else resource
            result.findings.append(
                Finding(
                    tool="checkov",
                    category=category,
                    rule_id=check_id,
                    title=clamp_text(as_str(check.get("check_name")), 160),
                    severity=severity,
                    location=location,
                    file=file,
                    line=line,
                    description=clamp_text(f"{framework}: {as_str(check.get('check_name'))} ({resource})"),
                    help_url=as_str(check.get("guideline")) or None,
                    raw_severity=raw or "unmapped",
                )
            )
    return result
