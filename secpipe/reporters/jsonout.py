"""findings.json: the full normalised result, also the next run's baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secpipe.aggregator.gate import GateResult


def findings_document(result: GateResult) -> dict[str, Any]:
    opts = result.options
    return {
        "schema": "secpipe/findings/v1",
        "meta": {
            "stage": opts.stage,
            "branch": opts.branch,
            "event": opts.event,
            "commit": opts.commit,
            "repository": opts.repository,
            "generated_at": result.generated_at,
            "policy": result.policy_ref,
        },
        "summary": result.summary(),
        "findings": [f.to_dict() for f in [*result.findings, *result.fixed]],
        "suppressions": [s.to_dict() for s in result.suppressions],
    }


def write(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8")
    return path
