#!/usr/bin/env bash
# Security drill against YOUR OWN local deployment (make deploy + make monitoring):
#   1. brute force      15 wrong passwords for one user from one client
#   2. success          the right password from the same client (after the
#                       rate-limit window), i.e. "brute force then success"
#   3. SSRF probe       /preview aimed at the cloud metadata address
#   4. post-exploit     kubectl exec a shell into the API pod, touch the secrets
# For every step it records when the action happened and when the matching
# alert first appeared in Alertmanager: time to detect (target < 60 s).
# Output: evidence/drill-<timestamp>/timeline.json + timeline.md, for
# docs/incidents/drill-NN.md. Numbers are only what this run measured.
#
#   BASE_URL      default https://secnotes.localtest.me:8443 (TLS verified against
#                 the cluster CA, written to build/k8s/ingress-ca.pem)
#   DETECT_TIMEOUT seconds to wait for each alert (default 180)
set -euo pipefail

BASE_URL="${BASE_URL:-https://secnotes.localtest.me:8443}"
DETECT_TIMEOUT="${DETECT_TIMEOUT:-180}"
NS=secnotes
root="$(cd "$(dirname "$0")/.." && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$root/evidence/drill-$stamp"
mkdir -p "$out"
timeline="$out/timeline.jsonl"
# shellcheck source=k8s-lib.sh
source "$root/scripts/k8s-lib.sh"
export_ingress_ca
tls=(--cacert "$BUILD_DIR/ingress-ca.pem")
log() { printf '[drill %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

kubectl -n monitoring port-forward svc/kps-alertmanager 19093:9093 >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
sleep 3

curl_app() { curl -s "${tls[@]}" -o /dev/null -w '%{http_code}' "$@"; }
now() { date -u +%s.%N; }

# wait_alert <step> <started> <label=value>...  (first alert matching all labels, active since the step)
wait_alert() {
  local step=$1 started=$2
  shift 2
  python3 - "$step" "$started" "$DETECT_TIMEOUT" "$timeline" "$@" <<'PY'
import datetime as dt, json, sys, time, urllib.request

step, started, timeout, timeline = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
wanted = dict(arg.split("=", 1) for arg in sys.argv[5:])
deadline = time.time() + timeout
detected = alert = None
while time.time() < deadline and detected is None:
    try:
        with urllib.request.urlopen("http://localhost:19093/api/v2/alerts?active=true", timeout=5) as resp:  # noqa: S310
            alerts = json.load(resp)
    except OSError:
        alerts = []
    for a in alerts:
        labels = a.get("labels", {})
        if all(labels.get(k) == v for k, v in wanted.items()):
            alert, detected = a, time.time()
            break
    else:
        time.sleep(2)
row = {
    "step": step,
    "action_at": dt.datetime.fromtimestamp(started, dt.UTC).isoformat(),
    "match": wanted,
    "detected": detected is not None,
    "time_to_detect_seconds": round(detected - started, 1) if detected else None,
    "alertname": (alert or {}).get("labels", {}).get("alertname"),
    "severity": (alert or {}).get("labels", {}).get("severity"),
    "summary": (alert or {}).get("annotations", {}).get("summary"),
}
with open(timeline, "a") as fh:
    fh.write(json.dumps(row) + "\n")
state = f"detected in {row['time_to_detect_seconds']} s" if detected else f"NOT detected within {timeout:.0f} s"
print(f"[drill] {step}: {state} ({row['alertname']})", file=sys.stderr)
PY
}

user="drill$(date +%s)"
password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
creds() { printf '{"username":"%s","password":"%s"}' "$user" "$1"; }
code="$(curl_app -X POST "$BASE_URL/auth/register" -H 'Content-Type: application/json' -d "$(creds "$password")")"
log "registered victim $user ($code)"

# ------------------------------------------------------------- 1. brute force
t1="$(now)"
for i in $(seq 1 15); do
  code="$(curl_app -X POST "$BASE_URL/auth/login" -H 'Content-Type: application/json' -d "$(creds "wrong-password-$i")")"
  printf '%s ' "$code" >&2
done
echo >&2
log "step 1: 15 wrong passwords sent (401 then 429 once the rate limiter kicks in)"
wait_alert "1-brute-force" "$t1" rule=brute_force

# --------------------------------------------------- 2. brute force then success
log "waiting 61 s for the login rate-limit window to reset"
sleep 61
t2="$(now)"
token="$(curl -s "${tls[@]}" -X POST "$BASE_URL/auth/login" -H 'Content-Type: application/json' -d "$(creds "$password")" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))')"
[[ -n "$token" ]] || { log "login failed; is the app reachable at $BASE_URL?"; exit 1; }
log "step 2: successful login with the right password"
wait_alert "2-brute-force-then-success" "$t2" rule=brute_force_then_success

# --------------------------------------------------------------- 3. SSRF probe
t3="$(now)"
code="$(curl_app "$BASE_URL/preview?url=http://169.254.169.254/latest/meta-data/" -H "Authorization: Bearer $token")"
log "step 3: /preview -> 169.254.169.254 ($code; blocked by the SSRF guard)"
wait_alert "3-ssrf-probe" "$t3" rule=ssrf_probe

# ------------------------------------------------------- 4. post-exploitation
t4="$(now)"
kubectl -n "$NS" exec deploy/secnotes-api -c api -- sh -c 'id; ls /run/secrets/secnotes; cat /run/secrets/secnotes/jwt_secret >/dev/null' \
  >/dev/null 2>&1 || true
log "step 4: shell exec'd into the API pod and secrets read"
wait_alert "4-shell-in-pod (Falco)" "$t4" rule="Shell spawned in SecNotes pod"
wait_alert "4-post-exploitation-chain (correlator)" "$t4" rule=post_exploitation_chain

python3 - "$timeline" "$out/timeline.json" "$out/timeline.md" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
json.dump(rows, open(sys.argv[2], "w"), indent=2)
with open(sys.argv[3], "w") as md:
    md.write("| Step | Action (UTC) | Alert | Severity | Time to detect |\n|---|---|---|---|---|\n")
    for r in rows:
        ttd = f"{r['time_to_detect_seconds']} s" if r["detected"] else "not detected"
        md.write(f"| {r['step']} | {r['action_at'][11:19]} | {r['alertname'] or '-'} | {r['severity'] or '-'} | {ttd} |\n")
print(open(sys.argv[3]).read())
PY
log "timeline: ${out#"$root"/}/timeline.md; next: scripts/quarantine-pod.sh <pod> and docs/runbooks/container-compromise.md"
