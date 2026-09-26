#!/usr/bin/env bash
# Re-scan a stored SBOM with Grype: catches CVEs disclosed after the image
# was released, without rebuilding it (nightly).
#   grype.sh <sbom.cdx.json>
source "$(dirname "$0")/lib.sh"
sbom="${1:?usage: grype.sh <sbom.cdx.json>}"
cd "$WORKSPACE"
cache="${GRYPE_DB_CACHE_DIR:-$HOME/.cache/grype}"
mkdir -p "$cache"
DOCKER_TOOL_ARGS=(-v "$cache:/cache" -e GRYPE_DB_CACHE_DIR=/cache)
run_scanner grype grype.json "0" "$(tool_version grype)" -- \
  docker_tool grype "sbom:$(in_container "$sbom")" --output json \
  --file "$(in_container "$REPORTS_DIR")/grype.json"
finish
