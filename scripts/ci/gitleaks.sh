#!/usr/bin/env bash
# Secrets: Gitleaks over the FULL git history (CI checks out with fetch-depth: 0,
# otherwise secrets buried in old commits are missed). --redact keeps secret
# values out of logs and the SARIF report. The aggregator treats every result
# as critical.
#
# Scope: all history reachable from the checked-out commit (HEAD). Gitleaks'
# default is `git log --all`, which after a fetch-depth: 0 checkout includes
# every other branch, so main would inherit findings from unmerged branches.
#
# Fail-closed guards: Gitleaks prints "0 commits scanned ... no leaks found" and
# exits 0 when git cannot read the repository (shallow clone, safe.directory,
# a worktree whose gitdir is outside the mount). This script therefore refuses
# shallow clones and cross-checks the scanned-commit count against git itself.
source "$(dirname "$0")/lib.sh"
cd "$WORKSPACE"

config="$WORKSPACE/.gitleaks.toml"
[[ -f "$config" ]] || config="$SECPIPE_ROOT/.gitleaks.toml"
scan_log="$REPORTS_DIR/gitleaks.log"

# The repo is owned by the runner user; tell git inside the container it is safe.
DOCKER_TOOL_ARGS=(-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src)
gitleaks_scan() {
  local rc=0
  docker_tool gitleaks "$@" 2>"$scan_log" || rc=$?
  cat "$scan_log" >&2
  return "$rc"
}
run_scanner gitleaks gitleaks.sarif "0 1" "$(tool_version gitleaks)" -- \
  gitleaks_scan git /src \
  --config "$(in_container "$config")" \
  --log-opts "${GITLEAKS_LOG_OPTS:-HEAD}" \
  --redact --no-banner --no-color --exit-code 1 \
  --report-format sarif --report-path "$(in_container "$REPORTS_DIR")/gitleaks.sarif"

expected=$(git rev-list --count "${GITLEAKS_LOG_OPTS:-HEAD}" 2>/dev/null || echo 0)
scanned=$(grep -oE '[0-9]+ commits scanned' "$scan_log" | grep -oE '^[0-9]+' | tail -1 || true)
if [[ "$(git rev-parse --is-shallow-repository 2>/dev/null)" == "true" && "${SECPIPE_ALLOW_SHALLOW:-0}" != 1 ]]; then
  fail_scanner gitleaks "shallow clone: history is incomplete (use actions/checkout with fetch-depth: 0)"
elif grep -q '\[git\] fatal' "$scan_log"; then
  fail_scanner gitleaks "git failed inside the scanner: $(grep -m1 '\[git\] fatal' "$scan_log")"
elif [[ "${expected:-0}" -gt 0 && "${scanned:-0}" -eq 0 ]]; then
  fail_scanner gitleaks "scanned 0 of $expected commits"
else
  log "gitleaks scanned ${scanned:-?} of $expected commits"
fi
finish
