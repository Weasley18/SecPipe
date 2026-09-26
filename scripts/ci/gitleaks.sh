#!/usr/bin/env bash
# Secrets: Gitleaks over the FULL git history (CI checks out with fetch-depth: 0,
# otherwise secrets buried in old commits are missed). --redact keeps secret
# values out of logs and the SARIF report. The aggregator treats every result
# as critical.
source "$(dirname "$0")/lib.sh"

config="$WORKSPACE/.gitleaks.toml"
[[ -f "$config" ]] || config="$SECPIPE_ROOT/.gitleaks.toml"

# The repo is owned by the runner user; tell git inside the container it is safe.
DOCKER_TOOL_ARGS=(-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src)
run_scanner gitleaks gitleaks.sarif "0 1" "$(tool_version gitleaks)" -- \
  docker_tool gitleaks git /src \
  --config "$(in_container "$config")" \
  --redact --no-banner --exit-code 1 \
  --report-format sarif --report-path "$(in_container "$REPORTS_DIR")/gitleaks.sarif"
finish
