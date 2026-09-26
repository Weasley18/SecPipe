"""Trivy JSON. One parser, several categories:

* ``os-pkgs``   -> container (OS package CVEs)
* ``lang-pkgs`` -> sca (library CVEs, merged with the SCA tools by dedupe)
* ``config``    -> container (Dockerfile/image config), k8s or iac
* ``secret``    -> secret

OS CVEs are grouped by (CVE, installed version): Debian ships one source
package as many binary packages (util-linux -> bsdutils, libblkid1, ...) that
share a version and are fixed by the same update, so they are one finding.
An end-of-life base OS is reported as its own finding.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secpipe.aggregator.models import Finding, ParseResult, Severity
from secpipe.aggregator.normalize import (
    as_dict,
    as_float,
    as_int,
    as_list,
    as_str,
    clamp_text,
    code_location,
    find_cwe,
    normalize_package,
    normalize_path,
    package_location,
    strip_epoch,
)
from secpipe.aggregator.parsers.base import load_json

NO_FIX_STATUSES = {"affected", "will_not_fix", "fix_deferred", "end_of_life", "under_investigation"}
CVSS_SOURCES = ("nvd", "ghsa", "redhat")


def _cvss(vuln: dict[str, Any]) -> float | None:
    scores = as_dict(vuln.get("CVSS"))
    for source in (*CVSS_SOURCES, *scores.keys()):
        entry = as_dict(scores.get(source))
        score = as_float(entry.get("V3Score")) or as_float(entry.get("V40Score"))
        if score:
            return score
    return None


def _severity(vuln: dict[str, Any], cvss: float | None) -> Severity:
    label = as_str(vuln.get("Severity")).lower()
    if label and label != "unknown":
        return Severity.parse(label, Severity.MEDIUM)
    return Severity.from_cvss(cvss) if cvss else Severity.MEDIUM


def _config_category(is_image: bool, target_type: str) -> str:
    if is_image or target_type == "dockerfile":
        return "container"
    if target_type in {"kubernetes", "helm"}:
        return "k8s"
    return "iac"


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="trivy", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    data = as_dict(data)
    if "Results" not in data and "SchemaVersion" not in data:
        result.errors = [f"{path.name} is not a Trivy JSON report"]
        return result
    artifact = as_str(data.get("ArtifactName"))
    is_image = as_str(data.get("ArtifactType")) == "container_image"
    metadata = as_dict(data.get("Metadata"))
    tags = [as_str(t) for t in as_list(metadata.get("RepoTags"))]
    image_label = tags[0] if tags else "image"
    os_info = as_dict(metadata.get("OS"))
    result.metadata.update({"artifact": artifact, "is_image": is_image, "os": os_info})

    if is_image and os_info.get("EOSL"):
        os_name = f"{as_str(os_info.get('Family'))} {as_str(os_info.get('Name'))}".strip()
        result.raw_count += 1
        result.findings.append(
            Finding(
                tool="trivy",
                category="container",
                rule_id="container-eol-base-image",
                title=f"Base image OS {os_name} is end-of-life",
                severity=Severity.HIGH,
                location=f"image-os:{os_name}",
                description="The OS no longer receives security updates, so its CVEs will never be fixed. "
                "Rebuild on a supported, slim base image pinned by digest.",
                fix_available=True,
                fix_version="supported base image",
                raw_severity="eosl",
            )
        )

    for res in as_list(data.get("Results")):
        res = as_dict(res)
        cls = as_str(res.get("Class"))
        target = as_str(res.get("Target"))
        target_type = as_str(res.get("Type"))
        if cls == "os-pkgs":
            _os_packages(result, res, os_info)
        elif cls == "lang-pkgs":
            _lang_packages(result, res, target_type)
        elif cls == "config":
            _misconfigurations(result, res, is_image, artifact, image_label, target, target_type)
        elif cls == "secret":
            _secrets(result, res, is_image, target)
    return result


def _os_packages(result: ParseResult, res: dict[str, Any], os_info: dict[str, Any]) -> None:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for vuln in as_list(res.get("Vulnerabilities")):
        vuln = as_dict(vuln)
        result.raw_count += 1
        key = (as_str(vuln.get("VulnerabilityID")), strip_epoch(as_str(vuln.get("InstalledVersion"))))
        groups.setdefault(key, []).append(vuln)
    os_name = f"{as_str(os_info.get('Family'))} {as_str(os_info.get('Name'))}".strip()
    for (vid, _), vulns in groups.items():
        vulns.sort(key=lambda v: as_str(v.get("PkgName")))
        primary = vulns[0]
        cvss = max((c for c in (_cvss(v) for v in vulns) if c is not None), default=None)
        severity = max(_severity(v, cvss) for v in vulns)
        fixed = as_str(primary.get("FixedVersion")) or None
        pkg = as_str(primary.get("PkgName"))
        version = as_str(primary.get("InstalledVersion")) or None
        status = as_str(primary.get("Status"))
        result.findings.append(
            Finding(
                tool="trivy",
                category="container",
                rule_id=vid,
                title=clamp_text(f"{vid} in {pkg}: {as_str(primary.get('Title'))}", 160),
                severity=severity,
                location=package_location(pkg, version),
                cve=vid if vid.upper().startswith("CVE-") else None,
                cwe=find_cwe(as_list(primary.get("CweIDs"))),
                fix_version=fixed,
                package=pkg,
                version=version,
                pkg_type="os",
                fix_available=bool(fixed) and status not in NO_FIX_STATUSES - {"fixed"},
                cvss=cvss,
                description=clamp_text(f"{os_name}: {as_str(primary.get('Description'))}"),
                help_url=as_str(primary.get("PrimaryURL")) or None,
                raw_severity=as_str(primary.get("Severity")).lower() or None,
                related_packages=[as_str(v.get("PkgName")) for v in vulns[1:]],
                aliases=[as_str(a) for a in as_list(primary.get("VendorIDs"))],
            )
        )


def _lang_packages(result: ParseResult, res: dict[str, Any], target_type: str) -> None:
    seen: set[tuple[str, str, str]] = set()
    pkg_type = "python" if target_type in {"python-pkg", "pip", "pipenv", "poetry", "uv"} else target_type or None
    for vuln in as_list(res.get("Vulnerabilities")):
        vuln = as_dict(vuln)
        result.raw_count += 1
        vid = as_str(vuln.get("VulnerabilityID"))
        name = normalize_package(as_str(vuln.get("PkgName")))
        version = as_str(vuln.get("InstalledVersion")) or None
        if (vid, name, version or "") in seen:
            continue
        seen.add((vid, name, version or ""))
        cvss = _cvss(vuln)
        fixed = as_str(vuln.get("FixedVersion")) or None
        first_fix = fixed.split(",")[0].strip() if fixed else None
        result.findings.append(
            Finding(
                tool="trivy",
                category="sca",
                rule_id=vid,
                title=clamp_text(as_str(vuln.get("Title")) or f"{vid} in {name}", 160),
                severity=_severity(vuln, cvss),
                location=package_location(name, version),
                cve=vid if vid.upper().startswith("CVE-") else None,
                cwe=find_cwe(as_list(vuln.get("CweIDs"))),
                fix_version=first_fix,
                package=name,
                version=version,
                pkg_type=pkg_type,
                fix_available=first_fix is not None,
                cvss=cvss,
                description=clamp_text(as_str(vuln.get("Description"))),
                help_url=as_str(vuln.get("PrimaryURL")) or None,
                raw_severity=as_str(vuln.get("Severity")).lower() or None,
                aliases=[as_str(a) for a in as_list(vuln.get("VendorIDs"))],
            )
        )


def _misconfigurations(
    result: ParseResult,
    res: dict[str, Any],
    is_image: bool,
    artifact: str,
    image_label: str,
    target: str,
    target_type: str,
) -> None:
    category = _config_category(is_image, target_type)
    for item in as_list(res.get("Misconfigurations")):
        item = as_dict(item)
        if as_str(item.get("Status"), "FAIL") != "FAIL":
            continue
        result.raw_count += 1
        cause = as_dict(item.get("CauseMetadata"))
        line = as_int(cause.get("StartLine"))
        if is_image and target == artifact:
            file, location = None, f"{image_label} (image config)"
        elif is_image:
            file = None
            location = code_location(f"image:/{target.lstrip('/')}", line)
        else:
            file = normalize_path(target)
            resource = as_str(cause.get("Resource"))
            location = f"{file}:{resource}" if resource else code_location(file, line)
        rule = as_str(item.get("ID") or item.get("AVDID"))
        result.findings.append(
            Finding(
                tool="trivy",
                category=category,
                rule_id=rule,
                title=clamp_text(as_str(item.get("Title")), 160),
                severity=Severity.parse(item.get("Severity"), Severity.MEDIUM),
                location=location,
                file=file,
                line=line,
                description=clamp_text(f"{as_str(item.get('Message'))} {as_str(item.get('Resolution'))}"),
                help_url=as_str(item.get("PrimaryURL")) or None,
                raw_severity=as_str(item.get("Severity")).lower() or None,
            )
        )


def _secrets(result: ParseResult, res: dict[str, Any], is_image: bool, target: str) -> None:
    for item in as_list(res.get("Secrets")):
        item = as_dict(item)
        result.raw_count += 1
        line = as_int(item.get("StartLine"))
        if is_image:
            file = None
            location = code_location(f"image:/{target.lstrip('/')}", line)
        else:
            file = normalize_path(target)
            location = code_location(file, line)
        rule = as_str(item.get("RuleID"))
        created_by = as_str(as_dict(item.get("Layer")).get("CreatedBy"))
        # The matched text is never copied: Trivy masks it, and SecPipe never stores secret values.
        result.findings.append(
            Finding(
                tool="trivy",
                category="secret",
                rule_id=rule,
                title=f"Secret in image: {as_str(item.get('Title'))}" if is_image else as_str(item.get("Title")),
                severity=Severity.parse(item.get("Severity"), Severity.HIGH),
                location=location,
                cwe="CWE-798",
                file=file,
                line=line,
                description=clamp_text(f"Added by layer: {created_by}" if created_by else "Secret detected by Trivy"),
                raw_severity=as_str(item.get("Severity")).lower() or None,
            )
        )
