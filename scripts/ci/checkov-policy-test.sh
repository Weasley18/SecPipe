#!/usr/bin/env bash
# Unit tests for the custom Checkov policies in policy/checkov: runs them on
# policy/checkov-tests and compares pass/fail per resource with expected.json.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

bin="$(python_tools iac)"
tests="$SECPIPE_ROOT/policy/checkov-tests"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

checks="$("$PYTHON" -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))))' "$tests/expected.json")"
"$bin/checkov" -d "$tests" --framework terraform \
  --external-checks-dir "$SECPIPE_ROOT/policy/checkov" --check "$checks" \
  --skip-download -o json >"$out/result.json" || true

"$PYTHON" - "$tests/expected.json" "$out/result.json" <<'PY'
import json
import sys

expected = json.load(open(sys.argv[1]))
report = json.load(open(sys.argv[2]))
reports = report if isinstance(report, list) else [report]
actual: dict[tuple[str, str], set[str]] = {}
for rep in reports:
    for outcome in ("passed", "failed"):
        for item in rep.get("results", {}).get(f"{outcome}_checks", []):
            actual.setdefault((item["check_id"], outcome), set()).add(item["resource"])
errors = []
for check, outcomes in expected.items():
    for outcome, resources in outcomes.items():
        got = actual.get((check, outcome), set())
        for resource in resources:
            if resource not in got:
                errors.append(f"{check}: expected {resource} to be {outcome}")
    extra = actual.get((check, "failed"), set()) - set(outcomes.get("failed", []))
    errors.extend(f"{check}: unexpected failure on {r}" for r in sorted(extra))
if errors:
    print("\n".join(errors))
    sys.exit(1)
total = sum(len(r) for o in expected.values() for r in o.values())
print(f"checkov custom policies: {total}/{total} expectations met")
PY
