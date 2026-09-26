#!/usr/bin/env bash
# The first five minutes of containment for a suspected compromised pod.
#   scripts/quarantine-pod.sh <pod> [namespace]
#
# 1. Label it quarantine=true: the pre-installed "quarantine" NetworkPolicy and
#    the allow policies (which all exclude quarantine=true) cut every flow.
# 2. Change its app label so the Service stops routing to it and the
#    Deployment's ReplicaSet releases it and starts a clean replacement.
# 3. Save describe, YAML, logs, events and recent Falco events to a
#    timestamped evidence folder with a SHA-256 manifest (chain of custody).
# 4. Leave the pod RUNNING for forensics. Deleting it destroys memory and /tmp.
# Runbook: docs/runbooks/container-compromise.md
set -euo pipefail

pod="${1:?usage: quarantine-pod.sh <pod> [namespace]}"
ns="${2:-secnotes}"
root="$(cd "$(dirname "$0")/.." && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$root/evidence/${stamp}-${pod}"
log() { printf '[quarantine] %s\n' "$*" >&2; }

kubectl -n "$ns" get pod "$pod" >/dev/null
mkdir -p "$evidence"
chmod 700 "$evidence"
started="$(date -u +%s)"

# ---------------------------------------------------------------- 1. isolate
kubectl -n "$ns" label pod "$pod" quarantine=true --overwrite
kubectl -n "$ns" annotate pod "$pod" --overwrite \
  secpipe.io/quarantined-at="$stamp" secpipe.io/quarantined-by="${USER:-unknown}"
log "network-isolated (quarantine=true)"

# --------------------------------------------------- 2. out of service rotation
owner_kind="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.ownerReferences[0].kind}')"
app="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/name}')"
if [[ "$owner_kind" == ReplicaSet && -n "$app" ]]; then
  kubectl -n "$ns" label pod "$pod" "app.kubernetes.io/name=${app}-quarantined" secpipe.io/original-app="$app" --overwrite
  log "removed from Service ${app}; the Deployment is starting a replacement"
else
  # A StatefulSet cannot recreate a pod whose name is still taken: keep the
  # label, rely on the NetworkPolicy, and fail over by hand (see runbook).
  log "owner is ${owner_kind:-none}: kept its labels; isolate-only (see runbook for failover)"
fi

# ------------------------------------------------------------------ 3. evidence
kubectl -n "$ns" get pod "$pod" -o yaml >"$evidence/pod.yaml"
kubectl -n "$ns" describe pod "$pod" >"$evidence/describe.txt"
for c in $(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.spec.containers[*].name}'); do
  kubectl -n "$ns" logs "$pod" -c "$c" --timestamps >"$evidence/logs-$c.txt" 2>&1 || true
  kubectl -n "$ns" logs "$pod" -c "$c" --timestamps --previous >"$evidence/logs-$c-previous.txt" 2>/dev/null || rm -f "$evidence/logs-$c-previous.txt"
done
kubectl -n "$ns" get events --field-selector "involvedObject.name=$pod" -o wide >"$evidence/events.txt" 2>&1 || true
kubectl get networkpolicies -n "$ns" -o yaml >"$evidence/networkpolicies.yaml"
if kubectl get namespace monitoring >/dev/null 2>&1; then
  kubectl -n monitoring logs -l app.kubernetes.io/name=falco -c falco --since=2h --tail=-1 2>/dev/null |
    grep -F "\"k8s.pod.name\":\"$pod\"" >"$evidence/falco-events.jsonl" || true
fi
(cd "$evidence" && sha256sum -- * >SHA256SUMS)

elapsed=$(($(date -u +%s) - started))
cat >"$evidence/SUMMARY.md" <<EOF
# Quarantine of ${ns}/${pod}

- Quarantined at: ${stamp} (UTC) by ${USER:-unknown}; containment took ${elapsed}s
- Owner: ${owner_kind:-none}; original app label: ${app:-none}
- Pod left running for forensics. Do not delete before memory/disk capture.
- Falco events captured: $(wc -l <"$evidence/falco-events.jsonl" 2>/dev/null || echo 0)
- Integrity: SHA256SUMS

Next steps: docs/runbooks/container-compromise.md (eradication and recovery).
EOF
log "evidence: ${evidence#"$root"/} (${elapsed}s)"
kubectl -n "$ns" get pods -o wide -L quarantine,app.kubernetes.io/name
