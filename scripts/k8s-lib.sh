#!/usr/bin/env bash
# Shared helpers for the kind cluster scripts (make cluster/deploy locally,
# scripts/ci/deploy-kind.sh in CI). Every remote manifest is checked against
# the SHA-256 pinned in k8s/cluster/versions.sh before it is applied.
set -euo pipefail

K8S_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../k8s/cluster/versions.sh
source "$K8S_ROOT/k8s/cluster/versions.sh"
APP_NS="${APP_NS:-secnotes}"
# The application's manifests come from the repository under test (WORKSPACE);
# policies and add-on pins come from the SecPipe tooling (K8S_ROOT).
APP_ROOT="${WORKSPACE:-$K8S_ROOT}"
BUILD_DIR="$APP_ROOT/build/k8s"

klog() { printf '[k8s] %s\n' "$*" >&2; }

# retry <attempts> <delay-seconds> <command...>
retry() {
  local attempts=$1 delay=$2 n=1
  shift 2
  until "$@"; do
    ((n >= attempts)) && return 1
    klog "retry $n/$attempts in ${delay}s: $*"
    sleep "$delay"
    n=$((n + 1))
  done
}

# fetch_verified <url> <sha256> <dest>
fetch_verified() {
  curl -fsSL -o "$3" "$1"
  if ! echo "$2  $3" | sha256sum --check --status; then
    klog "checksum mismatch for $1"
    rm -f "$3"
    return 1
  fi
}

install_kyverno() {
  klog "installing Kyverno v$KYVERNO_VERSION"
  local manifest
  manifest="$(mktemp)"
  fetch_verified "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/install.yaml" \
    "$KYVERNO_INSTALL_SHA256" "$manifest"
  # Server-side apply: the CRDs are too large for client-side annotations.
  kubectl apply --server-side --force-conflicts -f "$manifest" >/dev/null
  rm -f "$manifest"
  kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=300s
  # "Available" can precede the webhook Service having ready endpoints; policy
  # creation goes through Kyverno's own webhook, so wait for it to answer.
  retry 30 2 bash -c '[[ -n "$(kubectl -n kyverno get endpointslices -l kubernetes.io/service-name=kyverno-svc \
    -o jsonpath="{.items[*].endpoints[?(@.conditions.ready==true)].addresses[0]}")" ]]'
}

install_cert_manager() {
  klog "installing cert-manager $CERT_MANAGER_VERSION"
  local manifest
  manifest="$(mktemp)"
  fetch_verified "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml" \
    "$CERT_MANAGER_SHA256" "$manifest"
  kubectl apply --server-side --force-conflicts -f "$manifest" >/dev/null
  rm -f "$manifest"
  kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=300s
  kubectl apply -f "$K8S_ROOT/k8s/cluster/cert-manager-issuer.yaml"
}

install_traefik() {
  klog "installing Traefik (chart $TRAEFIK_CHART_VERSION) into namespace ingress"
  helm upgrade --install traefik traefik --repo https://traefik.github.io/charts \
    --version "$TRAEFIK_CHART_VERSION" --namespace ingress --create-namespace \
    --values "$K8S_ROOT/k8s/cluster/traefik-values.yaml" --wait --timeout 5m
}

# apply_policies [extra-ref]
# extra-ref (pull/42/merge, or heads/<branch> for a manual run on a branch)
# additionally trusts signatures made by that ref's own CI run; only the
# throwaway CI cluster passes it. Production trusts main alone.
apply_policies() {
  local extra_ref="${1:-}"
  local dir="$K8S_ROOT/policy/kyverno"
  retry 10 6 kubectl apply -f "$dir/disallow-latest-tag.yaml" -f "$dir/require-non-root.yaml" \
    -f "$dir/require-limits.yaml" -f "$dir/disallow-privileged.yaml"
  local policy
  policy="$(cat "$dir/verify-image-signature.yaml")"
  if [[ -n "$extra_ref" ]]; then
    [[ "$extra_ref" =~ ^(pull/[0-9]+/merge|heads/[A-Za-z0-9_/-]+)$ ]] || {
      klog "refusing unexpected ref '$extra_ref'"
      return 1
    }
    policy="$(sed "s#@refs/heads/main\\\$#@refs/(heads/main|${extra_ref})\$#" <<<"$policy")"
  fi
  if [[ -n "${KYVERNO_REGISTRY_SECRET:-}" ]]; then
    # Private registry: Kyverno reads signatures with this secret (namespace kyverno).
    policy="$(sed "s#^\(\s*\)- type: SigstoreBundle#&\n\1  imageRegistryCredentials:\n\1    secrets: [${KYVERNO_REGISTRY_SECRET}]#" <<<"$policy")"
  fi
  local rendered
  rendered="$(mktemp --suffix=.yaml)"
  printf '%s\n' "$policy" >"$rendered"
  retry 10 6 kubectl apply -f "$rendered"
  rm -f "$rendered"
  kubectl wait --for=condition=Ready clusterpolicy --all --timeout=120s
}

# Random DB password and JWT key, created once per cluster as a Secret and
# mounted as files. Nothing secret is written to the repository.
ensure_app_secrets() {
  if ! kubectl get namespace "$APP_NS" >/dev/null 2>&1; then
    kubectl create namespace "$APP_NS" >/dev/null
    kubectl label namespace "$APP_NS" pod-security.kubernetes.io/enforce=restricted \
      pod-security.kubernetes.io/enforce-version=latest >/dev/null
  fi
  if kubectl -n "$APP_NS" get secret secnotes-secrets >/dev/null 2>&1; then
    klog "secnotes-secrets already exists; keeping it (Postgres is initialised with it)"
    return 0
  fi
  local tmp
  tmp="$(mktemp -d)"
  (
    umask 077
    python3 -c 'import secrets; print(secrets.token_urlsafe(32), end="")' >"$tmp/db_password"
    python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' >"$tmp/jwt_secret"
  )
  kubectl -n "$APP_NS" create secret generic secnotes-secrets \
    --from-file=db_password="$tmp/db_password" --from-file=jwt_secret="$tmp/jwt_secret" >/dev/null
  rm -rf "$tmp"
  klog "created secnotes-secrets"
}

# registry_secret <namespace> <name>: dockerconfigjson for ghcr.io from
# GHCR_USER/GHCR_TOKEN (the job's short-lived GITHUB_TOKEN in CI), written via
# a 0600 temp file so the token never appears on a command line.
registry_secret() {
  local ns="$1" name="$2" tmp
  kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >/dev/null
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  python3 - "$tmp" <<'PY'
import base64, json, os, sys
auth = base64.b64encode(f"{os.environ['GHCR_USER']}:{os.environ['GHCR_TOKEN']}".encode()).decode()
with open(sys.argv[1], "w") as fh:
    json.dump({"auths": {"ghcr.io": {"auth": auth}}}, fh)
PY
  kubectl -n "$ns" create secret generic "$name" --type=kubernetes.io/dockerconfigjson \
    --from-file=.dockerconfigjson="$tmp" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  rm -f "$tmp"
}

# deploy_app <overlay> <image-ref>
# Renders the overlay with the image pinned (by digest in CI) into build/k8s
# so the checked-in overlay is never edited, then applies and waits.
deploy_app() {
  local overlay="$1" image="$2"
  mkdir -p "$BUILD_DIR"
  local rel
  rel="$(realpath --relative-to="$BUILD_DIR" "$APP_ROOT/$overlay")"
  local name="${image%@*}"
  name="${name%:*}"
  {
    echo "apiVersion: kustomize.config.k8s.io/v1beta1"
    echo "kind: Kustomization"
    echo "resources:"
    echo "  - $rel"
    echo "images:"
    echo "  - name: ghcr.io/weasley18/secnotes"
    echo "    newName: $name"
    if [[ "$image" == *@sha256:* ]]; then
      echo "    digest: ${image#*@}"
    else
      echo "    newTag: ${image##*:}"
    fi
  } >"$BUILD_DIR/kustomization.yaml"
  kubectl kustomize "$BUILD_DIR" >"$BUILD_DIR/rendered.yaml"
  kubectl apply -f "$BUILD_DIR/rendered.yaml"
  kubectl -n "$APP_NS" rollout status statefulset/postgres --timeout=300s
  kubectl -n "$APP_NS" rollout status deployment/secnotes-api --timeout=300s
}
