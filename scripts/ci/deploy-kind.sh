#!/usr/bin/env bash
# CI: install Kyverno + policies, cert-manager and Traefik on the throwaway kind
# cluster and deploy the image this run built and signed, by digest.
#   deploy-kind.sh [--platform-only] <image@sha256:...> [pull/<n>/merge]
#   K8S_OVERLAY   overlay to deploy, relative to the repository (default k8s/overlays/ci)
#   GHCR_USER, GHCR_TOKEN   the job's GITHUB_TOKEN (packages: read)
# --platform-only stops after the platform (used to dry-run a branch's own
# manifests against admission before deploying).
# DAST reaches the app the way a client does: through the TLS Ingress on kind's
# 127.0.0.1:8443, verified against the trust anchor this script writes to
# build/k8s/ingress-ca.pem.
set -euo pipefail
source "$(dirname "$0")/../k8s-lib.sh"

platform_only=0
if [[ "${1:-}" == --platform-only ]]; then
  platform_only=1
  shift
fi
image="${1:?image reference with digest}"
pr_ref="${2:-}"
[[ "$image" == *@sha256:* ]] || {
  klog "deploy by digest only (got $image)"
  exit 2
}

if ! kubectl get clusterpolicy verify-image-signature >/dev/null 2>&1; then
  install_kyverno
  registry_secret kyverno ghcr-pull
  KYVERNO_REGISTRY_SECRET=ghcr-pull apply_policies "$pr_ref"
fi
if ! kubectl -n ingress get deployment traefik >/dev/null 2>&1; then
  install_cert_manager
  install_traefik
fi
((platform_only)) && exit 0

ensure_app_secrets
registry_secret "$APP_NS" ghcr-pull
deploy_app "${K8S_OVERLAY:-k8s/overlays/ci}" "$image"
export_ingress_ca
kubectl -n "$APP_NS" get pods -o wide
