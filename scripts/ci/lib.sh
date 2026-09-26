#!/usr/bin/env bash
# Shared helpers for scripts/ci/*.sh.
#
# Contract for every scanner script:
#   * runs the same on a laptop (`make scan`) and in GitHub Actions;
#   * writes its report into $REPORTS_DIR plus a <tool>.meta.json sidecar
#     (exit code, duration, version, status) that the aggregator reads;
#   * exits 0 whenever the tool ran, with or without findings: severity
#     thresholds live in policy/policy.yaml, not in scanner flags;
#   * exits non-zero only when a tool itself failed. The job goes red and
#     the gate fails closed on the missing/errored report.
set -euo pipefail

# SECPIPE_ROOT: where SecPipe's tooling lives (scripts, policy, tools/).
# WORKSPACE:    the repository being scanned. Identical for this repo; for
#               the reusable workflow the tooling is checked out inside it.
SECPIPE_ROOT="${SECPIPE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WORKSPACE="${WORKSPACE:-$(pwd)}"
REPORTS_DIR="${REPORTS_DIR:-$WORKSPACE/reports}"
TOOLS_VENV_DIR="${TOOLS_VENV_DIR:-$WORKSPACE/.secpipe-tools}"
SECPIPE_OFFLINE="${SECPIPE_OFFLINE:-0}"
PYTHON="${PYTHON:-python3}"  # must match the Python version the lock files target (3.12)
mkdir -p "$REPORTS_DIR"
export SECPIPE_ROOT WORKSPACE REPORTS_DIR TOOLS_VENV_DIR
SECPIPE_FAILURES=0

log() { printf '[secpipe] %s\n' "$*" >&2; }

# Path of $1 as seen inside a scanner container that mounts $WORKSPACE at /src.
in_container() {
  python3 -c 'import os,sys; print("/src/" + os.path.relpath(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])))' \
    "$1" "$WORKSPACE"
}

# Pinned image reference for a tool, read from tools/scanners.Dockerfile.
# SECPIPE_IMAGE_<TOOL> (e.g. SECPIPE_IMAGE_GITLEAKS) overrides it, for
# registries mirrored inside an air-gapped network.
tool_image() {
  local ref override
  override="SECPIPE_IMAGE_$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
  if [[ -n "${!override:-}" ]]; then
    printf '%s' "${!override}"
    return 0
  fi
  ref=$(awk -v stage="$1" 'toupper($1)=="FROM" && tolower($NF)==stage {print $2}' \
    "$SECPIPE_ROOT/tools/scanners.Dockerfile")
  if [[ -z "$ref" ]]; then
    log "no pinned image for '$1' in tools/scanners.Dockerfile"
    return 1
  fi
  printf '%s' "$ref"
}

tool_version() {
  local ref
  ref=$(tool_image "$1")
  ref=${ref%@*}
  printf '%s' "${ref##*:}"
}

# Run a pinned tool image with the workspace mounted at /src, as the calling
# user (reports stay owned by the runner), without privileges.
docker_tool() {
  local tool=$1
  shift
  local image extra=()
  image=$(tool_image "$tool")
  # SECPIPE_DOCKER_EXTRA_ARGS: extra `docker run` flags for every tool, e.g. to
  # mount a corporate TLS-proxy CA: "-v /path/ca.crt:/ca.crt:ro -e SSL_CERT_FILE=/ca.crt"
  read -r -a extra <<<"${SECPIPE_DOCKER_EXTRA_ARGS:-}"
  # DOCKER_TOOL_USER: run as the image's own user when the tool needs its home
  # directory (ZAP); otherwise as the caller so reports stay runner-owned.
  docker run --rm --user "${DOCKER_TOOL_USER:-$(id -u):$(id -g)}" -e HOME="${DOCKER_TOOL_HOME:-/tmp}" \
    --security-opt no-new-privileges --cap-drop ALL \
    -v "$WORKSPACE:/src" -w /src "${extra[@]}" "${DOCKER_TOOL_ARGS[@]}" "$image" "$@"
}
DOCKER_TOOL_ARGS=()

# Create (or reuse) a venv with hash-pinned Python scanners; prints its bin dir.
python_tools() {
  local name=$1
  local venv="$TOOLS_VENV_DIR/$name"
  local lock="$SECPIPE_ROOT/scripts/ci/requirements/$name.txt"
  local want
  want=$(sha256sum "$lock" | cut -d' ' -f1)
  if [[ ! -x "$venv/bin/python" || "$(cat "$venv/.lock-sha256" 2>/dev/null)" != "$want" ]]; then
    log "installing $name scanners from $(basename "$lock") (hash-verified)"
    "$PYTHON" -m venv --clear "$venv"
    "$venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes -r "$lock" >&2
    printf '%s' "$want" >"$venv/.lock-sha256"
  fi
  printf '%s/bin' "$venv"
}

write_meta() {
  # write_meta <tool> <report> <exit> <status> <started> <finished> <version>
  python3 - "$@" <<'PY'
import json, os, sys
tool, report, code, status, started, finished, version = sys.argv[1:8]
meta = {
    "tool": tool,
    "report": report,
    "exit_code": int(code),
    "status": status,
    "duration_seconds": round(float(finished) - float(started), 2),
    "version": version,
}
path = os.path.join(os.environ["REPORTS_DIR"], f"{tool}.meta.json")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
}

# run_scanner <tool> <report-file> "<ok exit codes>" <version> [--stdout] -- <command...>
# Runs the command, records meta, and marks the tool failed if it exited with
# an unexpected code or produced no report.
run_scanner() {
  local tool=$1 report=$2 ok_codes=$3 version=$4
  shift 4
  local to_stdout=0
  if [[ "${1:-}" == "--stdout" ]]; then
    to_stdout=1
    shift
  fi
  [[ "${1:-}" == "--" ]] && shift
  local started finished code status out="$REPORTS_DIR/$report"
  log "running $tool -> reports/$report"
  started=$(date +%s.%N)
  set +e
  if ((to_stdout)); then
    "$@" >"$out"
  else
    "$@"
  fi
  code=$?
  set -e
  finished=$(date +%s.%N)
  status=ok
  if [[ " $ok_codes " != *" $code "* ]]; then
    status=error
    log "ERROR: $tool exited with $code (expected one of: $ok_codes)"
  elif [[ ! -s "$out" ]]; then
    status=error
    log "ERROR: $tool produced no report at $out"
  fi
  write_meta "$tool" "$report" "$code" "$status" "$started" "$finished" "$version"
  if [[ "$status" == error ]]; then
    SECPIPE_FAILURES=$((SECPIPE_FAILURES + 1))
  fi
  return 0
}

# Mark an already-recorded scanner run as failed (post-run sanity checks).
fail_scanner() {
  local tool=$1 reason=$2
  log "ERROR: $tool: $reason"
  python3 - "$tool" "$reason" <<'PY'
import json, os, sys
tool, reason = sys.argv[1:3]
path = os.path.join(os.environ["REPORTS_DIR"], f"{tool}.meta.json")
with open(path, encoding="utf-8") as fh:
    meta = json.load(fh)
meta["status"] = "error"
meta["reason"] = reason
with open(path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
  SECPIPE_FAILURES=$((SECPIPE_FAILURES + 1))
}

skip_scanner() {
  # Record an intentionally skipped optional scanner (e.g. Snyk without a token).
  local tool=$1 reason=$2
  log "skipping $tool: $reason"
  python3 - "$tool" "$reason" <<'PY'
import json, os, sys
tool, reason = sys.argv[1:3]
path = os.path.join(os.environ["REPORTS_DIR"], f"{tool}.meta.json")
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"tool": tool, "status": "skipped", "reason": reason, "exit_code": 0,
               "duration_seconds": 0, "report": None, "version": None}, fh, indent=2)
PY
}

finish() {
  if ((SECPIPE_FAILURES > 0)); then
    log "$SECPIPE_FAILURES scanner(s) failed; the gate will fail closed on their reports"
    exit 1
  fi
}
