#!/usr/bin/env bash
# `make scan`: every static stage of the pipeline, locally, in CI order.
# Builds the image as secnotes:local first. Individual stages can be run with
# `make scan-secrets`, `make scan-sast`, ... (see Makefile).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
status=0
"$here/gitleaks.sh" || status=1
"$here/sast.sh" || status=1
"$here/sca.sh" || status=1
"$here/iac.sh" || status=1
"$here/hadolint.sh" || status=1
docker build -f "${DOCKERFILE:-app/Dockerfile}" -t "${IMAGE:-secnotes:local}" . && "$here/scan-image.sh" "${IMAGE:-secnotes:local}" || status=1
exit $status
