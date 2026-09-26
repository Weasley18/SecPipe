#!/usr/bin/env bash
# make cluster: kind (1 control plane + 2 workers, Calico, audit logging) via
# the Terraform local profile, then Kyverno + policies, cert-manager and
# Traefik. Needs docker, terraform, kubectl, helm.
set -euo pipefail
source "$(dirname "$0")/k8s-lib.sh"

mkdir -p /tmp/secpipe-audit
terraform -chdir="$K8S_ROOT/infra/envs/local" init -input=false >/dev/null
terraform -chdir="$K8S_ROOT/infra/envs/local" apply -auto-approve -input=false
kubeconfig="$(terraform -chdir="$K8S_ROOT/infra/envs/local" output -raw kubeconfig_path)"
export KUBECONFIG="$kubeconfig"

install_kyverno
apply_policies
install_cert_manager
install_traefik
klog "cluster ready: export KUBECONFIG=$kubeconfig"
