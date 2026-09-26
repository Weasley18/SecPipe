#!/usr/bin/env bash
# SAST: Semgrep (OWASP/Python/secrets packs + SecPipe's custom rules) and Bandit.
#   SEMGREP_BASELINE_REF  set on pull requests: report only findings new since
#                         the merge base (the nightly run scans everything)
#   SAST_TARGETS          paths for Bandit (default: app/src secpipe)
#   SECPIPE_OFFLINE=1     custom rules only (no registry download)
source "$(dirname "$0")/lib.sh"
bin=$(python_tools sast)
version=$("$bin/python" -c 'import importlib.metadata as m; print(m.version("semgrep"))')

configs=(--config "$SECPIPE_ROOT/policy/semgrep")
if [[ "$SECPIPE_OFFLINE" != 1 ]]; then
  configs=(--config p/owasp-top-ten --config p/python --config p/secrets "${configs[@]}")
fi
baseline=()
if [[ -n "${SEMGREP_BASELINE_REF:-}" ]]; then
  baseline=(--baseline-commit "$SEMGREP_BASELINE_REF")
fi
cd "$WORKSPACE"
run_scanner semgrep semgrep.sarif "0" "$version" -- \
  "$bin/semgrep" scan "${configs[@]}" "${baseline[@]}" \
  --sarif --output "$REPORTS_DIR/semgrep.sarif" \
  --metrics off --disable-version-check --quiet .

read -r -a targets <<<"${SAST_TARGETS:-app/src secpipe}"
existing=()
for t in "${targets[@]}"; do [[ -e "$t" ]] && existing+=("$t"); done
run_scanner bandit bandit.json "0 1" "$("$bin/bandit" --version | head -1 | awk '{print $2}')" -- \
  "$bin/bandit" -r "${existing[@]}" -c "$SECPIPE_ROOT/pyproject.toml" \
  -f json -o "$REPORTS_DIR/bandit.json" -q
finish
