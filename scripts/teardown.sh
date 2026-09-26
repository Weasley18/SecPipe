#!/usr/bin/env bash
# make teardown: delete the kind cluster (and its local Terraform state).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$root/infra/envs/local/terraform.tfstate" ]]; then
  terraform -chdir="$root/infra/envs/local" destroy -auto-approve -input=false
else
  kind delete cluster --name "${CLUSTER:-secpipe}"
fi
rm -rf "$root/build/k8s"
