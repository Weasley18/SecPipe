#!/usr/bin/env bash
# CI: install Kyverno + policies on the throwaway kind cluster and deploy the
# image this run built and signed, by digest.
#   deploy-kind.sh <image@sha256:...> [pull/<n>/merge]
# Env: GHCR_USER, GHCR_TOKEN (the job's GITHUB_TOKEN, packages: read).
set -euo pipefail
source "$(dirname "$0")/../k8s-lib.sh"

image="${1:?image reference with digest}"
pr_ref="${2:-}"
[[ "$image" == *@sha256:* ]] || {
  klog "deploy by digest only (got $image)"
  exit 2
}

install_kyverno
registry_secret kyverno ghcr-pull
KYVERNO_REGISTRY_SECRET=ghcr-pull apply_policies "$pr_ref"
ensure_app_secrets
registry_secret "$APP_NS" ghcr-pull
deploy_app k8s/overlays/ci "$image"
kubectl -n "$APP_NS" get pods -o wide
