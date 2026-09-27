#!/usr/bin/env bash
# make deploy: build the hardened image, load it into kind and deploy the
# local overlay (Ingress on https://secnotes.localtest.me:8443).
set -euo pipefail
source "$(dirname "$0")/k8s-lib.sh"

IMAGE="${IMAGE:-secnotes:local}"
CLUSTER="${CLUSTER:-secpipe}"
docker build -f "$K8S_ROOT/app/Dockerfile" -t "$IMAGE" "$K8S_ROOT"
kind load docker-image "$IMAGE" --name "$CLUSTER"
ensure_app_secrets
deploy_app k8s/overlays/local "$IMAGE"
export_ingress_ca
klog "SecNotes: https://secnotes.localtest.me:8443 (private CA: curl --cacert build/k8s/ingress-ca.pem)"
