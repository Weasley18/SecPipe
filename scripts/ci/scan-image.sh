#!/usr/bin/env bash
# Container image: scan the freshly built image BEFORE it is pushed anywhere.
#   Trivy  OS + library CVEs, secrets and misconfigurations (including the image
#          config, which is where `ENV DB_PASSWORD=...` ends up), all severities;
#          policy.yaml decides what blocks, including "no fix available".
#   Syft   CycloneDX SBOM, later attested to the pushed image with Cosign.
# Usage: scan-image.sh <local-image-ref>
source "$(dirname "$0")/lib.sh"
image="${1:?usage: scan-image.sh <image>}"
cd "$WORKSPACE"
mkdir -p build
tarball="build/image.tar"
docker save "$image" -o "$tarball"

cache="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
mkdir -p "$cache"
DOCKER_TOOL_ARGS=(-v "$cache:/cache" -e TRIVY_CACHE_DIR=/cache)
run_scanner trivy-image trivy-image.json "0" "$(tool_version trivy)" -- \
  docker_tool trivy image --quiet --input "/src/$tarball" \
  --scanners vuln,secret,misconfig --image-config-scanners misconfig,secret \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output "$(in_container "$REPORTS_DIR")/trivy-image.json"

DOCKER_TOOL_ARGS=(-e SYFT_CHECK_FOR_APP_UPDATE=false)
run_scanner syft sbom.cdx.json "0" "$(tool_version syft)" -- \
  docker_tool syft scan "docker-archive:/src/$tarball" --quiet \
  -o "cyclonedx-json=$(in_container "$REPORTS_DIR")/sbom.cdx.json"
finish
