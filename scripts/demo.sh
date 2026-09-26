#!/usr/bin/env bash
# make demo: the cluster half of the 5-minute demo, step by step (press Enter
# between steps while recording). The PR half (blocked vulnerable PR, passing
# main) is shown on GitHub.
#   3. supply chain      unsigned image rejected, pipeline image verified
#   4. guardrails        privileged/root/:latest manifest rejected
#   5. attack + detect   scripts/drill.sh
#   6. respond           scripts/quarantine-pod.sh on the attacked pod
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pause() { [[ -t 0 ]] && read -r -p $'\n--- '"$1"' (Enter) ---' _ || echo "--- $1 ---"; }
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/weasley18/secnotes}"

kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f - >/dev/null

pause "3. Supply chain: an unsigned image is rejected by Kyverno"
kubectl -n demo run unsigned --image="${IMAGE_REPO}:ci-unsigned" --restart=Never --dry-run=server 2>&1 | tail -5 || true
if command -v cosign >/dev/null; then
  signed="$(kubectl -n secnotes get deploy secnotes-api -o jsonpath='{.spec.template.spec.containers[0].image}')"
  if [[ "$signed" == ghcr.io/* ]]; then
    cosign verify "$signed" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp '^https://github\.com/Weasley18/SecPipe/\.github/workflows/secpipe-reusable\.yml@refs/heads/main$' |
      jq '.[0].optional // .'
  fi
fi

pause "4. Cluster guardrails: privileged + root + :latest + no limits"
cat <<'EOF' | kubectl -n demo apply --dry-run=server -f - 2>&1 | sed 's/^/    /' || true
apiVersion: v1
kind: Pod
metadata: {name: bad-pod}
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext: {privileged: true, runAsUser: 0}
EOF
echo "  ...and in the restricted secnotes namespace Pod Security Admission rejects it first:"
kubectl -n secnotes run bad --image=nginx:1.29.1 --restart=Never --dry-run=server \
  --overrides='{"spec":{"containers":[{"name":"bad","image":"nginx:1.29.1","securityContext":{"privileged":true}}]}}' 2>&1 | tail -2 || true

pause "5. Attack and detect: drill.sh (brute force -> success -> SSRF -> shell)"
"$root/scripts/drill.sh"

pause "6. Respond: quarantine the attacked API pod"
victim="$(kubectl -n secnotes get pods -l app.kubernetes.io/name=secnotes-api -o jsonpath='{.items[0].metadata.name}')"
"$root/scripts/quarantine-pod.sh" "$victim" secnotes
kubectl -n secnotes rollout status deploy/secnotes-api --timeout=120s

pause "7. Posture: open Grafana (kubectl -n monitoring port-forward svc/kps-grafana 3000:80) -> SecPipe Security Posture"
