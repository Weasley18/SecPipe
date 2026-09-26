#!/usr/bin/env bash
# SCA: vulnerable dependencies and licence compliance.
#   OSV-Scanner  always (no account needed)
#   pip-audit    always (PyPA)
#   Snyk         when SNYK_TOKEN is set (adds dependency paths and licences)
#   pip-licenses always, feeds the licence deny-list in policy.yaml
source "$(dirname "$0")/lib.sh"
req="${REQUIREMENTS_FILE:-app/requirements.txt}"
cd "$WORKSPACE"
[[ -f "$req" ]] || { log "requirements file $req not found"; exit 1; }
bin=$(python_tools sca)
# Hash-locked requirements are verified; a plain pin list (no hashes) is
# audited as-is, which also flags the missing hashes as a supply-chain gap.
if grep -q -- '--hash=' "$req"; then
  audit_mode=(--require-hashes)
  install_mode=(--require-hashes)
else
  log "WARNING: $req has no hashes; dependencies are installed without integrity checks"
  audit_mode=(--no-deps)
  install_mode=()
fi

run_scanner osv-scanner osv.json "0 1" "$(tool_version osv-scanner)" -- \
  docker_tool osv-scanner scan source \
  --lockfile "requirements.txt:$(in_container "$req")" \
  --format json --output "$(in_container "$REPORTS_DIR")/osv.json"

run_scanner pip-audit pip-audit.json "0 1" "$("$bin/python" -c 'import importlib.metadata as m; print(m.version("pip-audit"))')" -- \
  "$bin/pip-audit" -r "$req" "${audit_mode[@]}" --disable-pip --progress-spinner off \
  --format json --output "$REPORTS_DIR/pip-audit.json"

# Install the app's locked dependencies into an isolated venv so licence and
# Snyk analysis see exactly what ships.
appenv="$TOOLS_VENV_DIR/app-deps"
"$PYTHON" -m venv --clear "$appenv"
"$appenv/bin/pip" install --quiet --disable-pip-version-check "${install_mode[@]}" -r "$req" >&2

run_scanner pip-licenses licenses.json "0" "$("$bin/python" -c 'import importlib.metadata as m; print(m.version("pip-licenses"))')" --stdout -- \
  "$bin/pip-licenses" --python "$appenv/bin/python" --format json --with-urls

SNYK_VERSION=1.1307.4
if [[ -n "${SNYK_TOKEN:-}" && "$SECPIPE_OFFLINE" != 1 ]]; then
  run_scanner snyk snyk.json "0 1" "$SNYK_VERSION" -- \
    npx --yes "snyk@$SNYK_VERSION" test --file="$req" --package-manager=pip \
    --command="$appenv/bin/python" --json-file-output="$REPORTS_DIR/snyk.json"
else
  skip_scanner snyk "SNYK_TOKEN not set"
fi
finish
