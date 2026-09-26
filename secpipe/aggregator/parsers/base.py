"""Safe report loading shared by all parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> tuple[Any, list[str]]:
    """Load a JSON report, returning ``(data, errors)`` and never raising.

    An empty file is an error rather than "no findings": a scanner that was
    killed mid-write must fail the gate closed, not pass it silently.
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, [f"cannot read {path.name}: {exc.strerror or exc}"]
    if not raw.strip():
        return None, [f"{path.name} is empty"]
    try:
        return json.loads(raw), []
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"{path.name} is truncated or not valid JSON ({exc})"]
