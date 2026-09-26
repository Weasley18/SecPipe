#!/usr/bin/env bash
# Admission and network regression tests against the CI kind cluster. Every
# defensive layer must visibly block something:
#   Pod Security Admission  privileged pod in the restricted namespace
#   Kyverno                 :latest, root, no limits, privileged, unsigned image
#   Signature policy        the image this run signed is admitted
#   NetworkPolicy           a stray pod cannot reach Postgres or the API server;
#                           the API pod can reach Postgres
#   admission-test.sh <signed image@digest> <unsigned image@digest>
# Writes reports/admission-tests.json and exits 1 if any expectation fails.
source "$(dirname "$0")/../k8s-lib.sh"
# k8s-lib enables errexit; here most commands are expected to fail (denials,
# blocked connections), so results are checked explicitly instead.
set +e -uo pipefail

signed="${1:?signed image digest ref}"
unsigned="${2:?unsigned image digest ref}"
reports="${REPORTS_DIR:-$APP_ROOT/reports}"
mkdir -p "$reports"
results="$(mktemp)"
test_ns=admission-test

kubectl get namespace "$test_ns" >/dev/null 2>&1 || kubectl create namespace "$test_ns" >/dev/null
# PSA off here, so every rejection in this namespace is Kyverno's.
kubectl label namespace "$test_ns" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
registry_secret "$test_ns" ghcr-pull

record() { # name expected actual detail
  python3 - "$results" "$@" <<'PY'
import json, sys
path, name, expected, actual, detail = sys.argv[1:6]
with open(path, "a") as fh:
    fh.write(json.dumps({"name": name, "expected": expected, "actual": actual,
                         "passed": expected == actual, "detail": detail[-600:]}) + "\n")
print(f"[{'PASS' if expected == actual else 'FAIL'}] {name}: expected {expected}, got {actual}", file=sys.stderr)
PY
}

# pod_json <image> [overrides-python-expression]
pod_json() {
  python3 - "$@" <<'PY'
import json, sys
image = sys.argv[1]
pod = {
  "apiVersion": "v1", "kind": "Pod", "metadata": {"generateName": "probe-"},
  "spec": {
    "automountServiceAccountToken": False,
    "imagePullSecrets": [{"name": "ghcr-pull"}],
    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{
      "name": "probe", "image": image,
      "securityContext": {"allowPrivilegeEscalation": False, "privileged": False, "readOnlyRootFilesystem": True,
                          "capabilities": {"drop": ["ALL"]}},
      "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
    }],
  },
}
spec, c = pod["spec"], pod["spec"]["containers"][0]
if len(sys.argv) > 2:
    exec(sys.argv[2])
print(json.dumps(pod))
PY
}

# admit <name> <namespace> <expected allowed|denied> <reason-substring> <image> [mutation]
admit() {
  local name="$1" ns="$2" expected="$3" reason="$4" image="$5" mutation="${6:-}" out actual
  out="$(pod_json "$image" "$mutation" | kubectl -n "$ns" create --dry-run=server -f - 2>&1)"
  if [[ $? -eq 0 ]]; then
    actual=allowed
  elif grep -qiE -- "$reason" <<<"$out"; then
    actual=denied
  else
    actual="error"
  fi
  record "$name" "$expected" "$actual" "$out"
}

admit "psa-rejects-privileged-in-secnotes" "$APP_NS" denied "PodSecurity" "$signed" \
  'c["securityContext"]["privileged"] = True; c["securityContext"]["allowPrivilegeEscalation"] = True'
admit "kyverno-rejects-latest-tag" "$test_ns" denied "disallow-latest-tag" "docker.io/library/nginx:latest"
admit "kyverno-rejects-root" "$test_ns" denied "require-non-root" "$signed" \
  'spec["securityContext"] = {"runAsUser": 0}'
admit "kyverno-rejects-missing-limits" "$test_ns" denied "require-limits" "$signed" 'c.pop("resources")'
# privileged + allowPrivilegeEscalation=false is rejected by API validation
# before admission runs, so the probe drops both, like a real privileged pod.
admit "kyverno-rejects-privileged" "$test_ns" denied "disallow-privileged" "$signed" \
  'c["securityContext"]["privileged"] = True; c["securityContext"]["allowPrivilegeEscalation"] = True'
admit "kyverno-rejects-host-path" "$test_ns" denied "disallow-privileged" "$signed" \
  'spec["volumes"] = [{"name": "root", "hostPath": {"path": "/"}}]'
admit "kyverno-rejects-unsigned-image" "$test_ns" denied "verify-image-signature" "$unsigned"
admit "kyverno-admits-signed-image" "$test_ns" allowed "" "$signed"

# connect <name> <expected reachable|blocked> <pod-or-new> <host> <port>
connect_probe() {
  local name="$1" expected="$2" where="$3" host="$4" port="$5" out actual
  local code="import socket,sys
try:
    socket.create_connection(('$host', $port), timeout=5).close(); print('reachable')
except OSError as exc:
    print('blocked', exc)"
  if [[ "$where" == new ]]; then
    local pod
    pod="$(pod_json "$signed" "c['command'] = ['python', '-c', '''$code''']; spec['restartPolicy'] = 'Never'; pod['metadata']['labels'] = {'app.kubernetes.io/name': 'np-probe'}" |
      kubectl -n "$APP_NS" create -f - -o name)"
    kubectl -n "$APP_NS" wait "$pod" --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s >/dev/null 2>&1
    out="$(kubectl -n "$APP_NS" logs "$pod" 2>&1)"
    kubectl -n "$APP_NS" delete "$pod" --wait=false >/dev/null 2>&1
  else
    out="$(kubectl -n "$APP_NS" exec "$where" -- python -c "$code" 2>&1)"
  fi
  actual="$(awk 'NR==1 {print $1}' <<<"$out")"
  record "$name" "$expected" "${actual:-error}" "$out"
}

connect_probe "netpol-api-reaches-postgres" reachable deploy/secnotes-api postgres 5432
connect_probe "netpol-blocks-stray-pod-to-postgres" blocked new postgres 5432
connect_probe "netpol-blocks-api-to-kubernetes-api" blocked deploy/secnotes-api kubernetes.default.svc 443
connect_probe "netpol-blocks-api-egress-internet" blocked deploy/secnotes-api 1.1.1.1 443

python3 - "$results" "$reports/admission-tests.json" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
json.dump({"tests": rows, "passed": sum(r["passed"] for r in rows), "total": len(rows)}, open(sys.argv[2], "w"), indent=2)
print(f"admission/network tests: {sum(r['passed'] for r in rows)}/{len(rows)} passed", file=sys.stderr)
sys.exit(0 if all(r["passed"] for r in rows) else 1)
PY
