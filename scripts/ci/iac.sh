#!/usr/bin/env bash
# IaC, Kubernetes manifests and pipeline config.
#   Checkov   Terraform (+ custom policies in policy/checkov), rendered K8s
#             manifests, the Dockerfile and the GitHub workflows
#   Trivy     second opinion on Terraform (tfsec checks)
#   Kubescape NSA/CISA hardening framework on the rendered manifests
#   zizmor    GitHub Actions security linter
source "$(dirname "$0")/lib.sh"
cd "$WORKSPACE"
IAC_DIR="${IAC_DIR:-infra}"
K8S_OVERLAY="${K8S_OVERLAY:-k8s/overlays/ci}"
DOCKERFILE="${DOCKERFILE:-app/Dockerfile}"
WORKFLOWS_DIR="${WORKFLOWS_DIR:-.github/workflows}"
KUBESCAPE_VERSION="${KUBESCAPE_VERSION:-4.0.14}"
bin=$(python_tools iac)
checkov_version=$("$bin/python" -c 'import importlib.metadata as m; print(m.version("checkov"))')
checkov=("$bin/checkov" --output json --soft-fail --compact --skip-download --quiet)

if [[ -d "$IAC_DIR" ]]; then
  run_scanner checkov-terraform checkov-terraform.json "0" "$checkov_version" --stdout -- \
    "${checkov[@]}" -d "$IAC_DIR" --framework terraform \
    --external-checks-dir "$SECPIPE_ROOT/policy/checkov"
  run_scanner trivy-iac trivy-iac.json "0" "$(tool_version trivy)" -- \
    docker_tool trivy config --quiet --format json \
    --output "$(in_container "$REPORTS_DIR")/trivy-iac.json" "$(in_container "$IAC_DIR")"
fi

if [[ -d "$K8S_OVERLAY" ]]; then
  rendered="$REPORTS_DIR/rendered-k8s.yaml"
  if command -v kubectl >/dev/null; then
    kubectl kustomize "$K8S_OVERLAY" >"$rendered"
  else
    kustomize build "$K8S_OVERLAY" >"$rendered"
  fi
  run_scanner checkov-k8s checkov-k8s.json "0" "$checkov_version" --stdout -- \
    "${checkov[@]}" -f "$rendered" --framework kubernetes \
    --external-checks-dir "$SECPIPE_ROOT/policy/checkov"

  if ! command -v kubescape >/dev/null; then
    # Release binary, verified against the release's checksums.sha256 manifest.
    ks_dir="$TOOLS_VENV_DIR/kubescape-$KUBESCAPE_VERSION"
    if [[ ! -x "$ks_dir/kubescape" ]]; then
      mkdir -p "$ks_dir"
      asset="kubescape_${KUBESCAPE_VERSION}_linux_amd64"
      base="https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}"
      curl -fsSL "$base/$asset" -o "$ks_dir/kubescape"
      expected=$(curl -fsSL "$base/checksums.sha256" | awk -v a="$asset" '$2==a || $2=="*"a {print $1}')
      echo "$expected  $ks_dir/kubescape" | sha256sum --check --status || {
        log "kubescape checksum mismatch"
        rm -f "$ks_dir/kubescape"
        exit 1
      }
      chmod +x "$ks_dir/kubescape"
    fi
    PATH="$ks_dir:$PATH"
  fi
  run_scanner kubescape kubescape.json "0" "$KUBESCAPE_VERSION" -- \
    kubescape scan framework nsa "$rendered" --format json --format-version v2 \
    --output "$REPORTS_DIR/kubescape.json"
fi

if [[ -f "$DOCKERFILE" ]]; then
  run_scanner checkov-dockerfile checkov-dockerfile.json "0" "$checkov_version" --stdout -- \
    "${checkov[@]}" -f "$DOCKERFILE" --framework dockerfile
fi

if [[ -d "$WORKFLOWS_DIR" ]]; then
  run_scanner checkov-gha checkov-gha.json "0" "$checkov_version" --stdout -- \
    "${checkov[@]}" -d "$(dirname "$WORKFLOWS_DIR")" --framework github_actions
  zizmor_mode=(--offline)
  [[ -n "${GH_TOKEN:-}" && "$SECPIPE_OFFLINE" != 1 ]] && zizmor_mode=()
  run_scanner zizmor zizmor.sarif "0" "$("$bin/zizmor" --version | awk '{print $2}')" --stdout -- \
    "$bin/zizmor" "${zizmor_mode[@]}" --format sarif --no-exit-codes "$WORKFLOWS_DIR"
fi
finish
