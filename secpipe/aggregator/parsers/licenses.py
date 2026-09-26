"""pip-licenses JSON: a licence inventory evaluated against policy.yaml."""

from __future__ import annotations

from pathlib import Path

from secpipe.aggregator.models import LicenceRecord, ParseResult
from secpipe.aggregator.normalize import as_dict, as_str, normalize_package
from secpipe.aggregator.parsers.base import load_json


def parse(path: Path) -> ParseResult:
    result = ParseResult(tool="pip-licenses", report=path.name)
    data, errors = load_json(path)
    if errors:
        result.errors = errors
        return result
    if not isinstance(data, list):
        result.errors = [f"{path.name} is not a pip-licenses JSON list"]
        return result
    for item in data:
        item = as_dict(item)
        result.raw_count += 1
        result.licences.append(
            LicenceRecord(
                package=normalize_package(as_str(item.get("Name"))),
                version=as_str(item.get("Version")),
                licence=as_str(item.get("License"), "UNKNOWN"),
                tool="pip-licenses",
            )
        )
    return result
