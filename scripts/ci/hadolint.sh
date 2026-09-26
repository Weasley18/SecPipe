#!/usr/bin/env bash
# Dockerfile lint (Hadolint) with the repo's .hadolint.yaml.
source "$(dirname "$0")/lib.sh"
cd "$WORKSPACE"
DOCKERFILE="${DOCKERFILE:-app/Dockerfile}"
config=".hadolint.yaml"
[[ -f "$config" ]] || config="$SECPIPE_ROOT/.hadolint.yaml"
run_scanner hadolint hadolint.sarif "0 1" "$(tool_version hadolint)" --stdout -- \
  docker_tool hadolint hadolint --config "$(in_container "$config")" --format sarif "$(in_container "$DOCKERFILE")"
finish
