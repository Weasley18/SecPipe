#!/usr/bin/env bash
# First-time setup on a laptop: check prerequisites, create the hash-locked
# dev venv, install pre-commit hooks and generate local secrets.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
missing=0
need() { # need <command> <why>
  if command -v "$1" >/dev/null; then
    printf '  ok      %-10s %s\n' "$1" "$2"
  else
    printf '  MISSING %-10s %s\n' "$1" "$2"
    missing=1
  fi
}
echo "Prerequisites:"
need python3.12 "dev venv, scanners, aggregator"
need docker "pinned scanner images, image build"
need git "history scanning"
need terraform "kind cluster (local profile), AWS profile"
need kubectl "deploy, admission and NetworkPolicy tests"
need kind "loading local images into the cluster"
need helm "monitoring stack"
need cosign "optional: verify image signatures"
((missing)) && echo "Install the missing tools above (cosign is optional)."
make -C "$root" setup secrets
echo "Next: make test, make scan, make cluster deploy monitoring, make demo"
