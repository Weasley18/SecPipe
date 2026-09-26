#!/usr/bin/env bash
# Unit tests for the Kyverno admission policies (policy/kyverno/tests).
# Uses a kyverno CLI on PATH, else downloads the pinned release and checks
# its SHA-256 before running it.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

KYVERNO_VERSION="${KYVERNO_VERSION:-1.19.1}"
KYVERNO_SHA256="${KYVERNO_SHA256:-b38228f367fc0fdc2b08f4c83ea50ac5f16c60ff8d62d76a66157c33c47b70ae}"

if ! command -v kyverno >/dev/null; then
  dir="$TOOLS_VENV_DIR/kyverno-$KYVERNO_VERSION"
  if [[ ! -x "$dir/kyverno" ]]; then
    mkdir -p "$dir"
    tarball="$dir/kyverno.tar.gz"
    curl -fsSL -o "$tarball" \
      "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/kyverno-cli_v${KYVERNO_VERSION}_linux_x86_64.tar.gz"
    echo "$KYVERNO_SHA256  $tarball" | sha256sum --check --status || {
      log "kyverno CLI checksum mismatch"
      rm -f "$tarball"
      exit 1
    }
    tar -xzf "$tarball" -C "$dir" kyverno
    rm -f "$tarball"
  fi
  PATH="$dir:$PATH"
fi

log "kyverno $(kyverno version 2>/dev/null | awk '/^Version/ {print $2}')"
kyverno test "$SECPIPE_ROOT/policy/kyverno/tests" --detailed-results=false
