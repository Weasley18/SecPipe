#!/usr/bin/env bash
# DAST with OWASP ZAP against a running SecNotes.
#   zap.sh <base-url> [baseline] [api] [full]      (default: baseline api)
#
#   baseline  spider + passive rules, unauthenticated               (every PR)
#   api       imports /openapi.json and actively attacks every
#             operation as a throwaway, non-admin scan user         (every PR)
#   full      Automation Framework plan (zap/automation.yaml): JSON
#             login, token extraction, re-authentication, spider and
#             full active scan                                      (nightly)
#
# ZAP's exit code is advisory: every report goes to the aggregator, which
# applies policy.yaml like it does for every other scanner. Only a ZAP crash
# (exit 3) or a missing report fails closed.
source "$(dirname "$0")/lib.sh"

base="${1:?usage: zap.sh <base-url> [baseline|api|full]...}"
shift
tiers=("$@")
((${#tiers[@]})) || tiers=(baseline api)
base="${base%/}"
# curl tries ::1 first for "localhost", ZAP (Java) tries 127.0.0.1 first: if two
# different listeners hold those, the health check passes and ZAP scans the
# wrong server. Pin plain-HTTP localhost so both use the same socket.
[[ "$base" =~ ^http://localhost([:/].*)?$ ]] && base="http://127.0.0.1${BASH_REMATCH[1]}"
version="$(tool_version zap)"

work="$WORKSPACE/build/zap"
rm -rf "$work"
mkdir -p "$work"
# ZAP runs as its image user (uid 1000, it needs /home/zap), so the work dir
# must be writable by it. Nothing secret is stored here.
chmod 777 "$work"
cp "$SECPIPE_ROOT/zap/rules.tsv" "$SECPIPE_ROOT/zap/automation.yaml" "$work/"

log "waiting for $base/healthz"
for _ in $(seq 60); do
  curl -fsS -o /dev/null "$base/healthz" && break
  sleep 2
done
curl -fsS -o /dev/null "$base/healthz" || {
  log "target $base is not healthy"
  exit 1
}

# Throwaway scan user: never scan with an admin account.
scan_user="zapscan$(date +%s)"
scan_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
body="$(python3 -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))' \
  "$scan_user" "$scan_password")"
curl -fsS -o /dev/null -X POST "$base/auth/register" -H 'Content-Type: application/json' -d "$body" ||
  log "registering the scan user failed (continuing: it may exist already)"
login() {
  curl -fsS -X POST "$base/auth/login" -H 'Content-Type: application/json' -d "$body" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

# The OpenAPI document, minus /auth/logout: calling it mid-scan revokes the
# scan token and every later request would be tested unauthenticated.
curl -fsS "$base/openapi.json" | python3 -c '
import json, sys
spec = json.load(sys.stdin)
for path in [p for p in spec.get("paths", {}) if p.rstrip("/").endswith("/auth/logout")]:
    del spec["paths"][path]
json.dump(spec, sys.stdout)' >"$work/openapi.json"

# Tokens and passwords reach the container through a 0600 env file, not argv.
envfile="$(mktemp)"
chmod 600 "$envfile"
trap 'rm -f "$envfile"' EXIT
zap_docker() {
  # zap_docker <report-name> <command...>: run ZAP on the host network (the
  # target is a port-forward on localhost) and copy the report to reports/.
  local report=$1
  shift
  # -w: the API scan writes zap.out to its working directory.
  DOCKER_TOOL_ARGS=(--network host -v "$work:/zap/wrk:rw" -w /zap/wrk --env-file "$envfile")
  DOCKER_TOOL_USER=zap DOCKER_TOOL_HOME=/home/zap docker_tool zap "$@"
  local code=$?
  DOCKER_TOOL_ARGS=()
  [[ -s "$work/$report" ]] && cp "$work/$report" "$REPORTS_DIR/$report"
  return "$code"
}

for tier in "${tiers[@]}"; do
  case "$tier" in
    baseline)
      : >"$envfile"
      run_scanner zap-baseline zap-baseline.json "0 1 2" "$version" -- \
        zap_docker zap-baseline.json zap-baseline.py -t "$base/openapi.json" \
        -c rules.tsv -J zap-baseline.json -I -m 3
      ;;
    api)
      token="$(login)"
      host="$(python3 -c 'import sys, urllib.parse as u; print(u.urlsplit(sys.argv[1]).hostname)' "$base")"
      printf 'ZAP_AUTH_HEADER=Authorization\nZAP_AUTH_HEADER_VALUE=Bearer %s\nZAP_AUTH_HEADER_SITE=%s\n' \
        "$token" "$host" >"$envfile"
      run_scanner zap-api zap-api.json "0 1 2" "$version" -- \
        zap_docker zap-api.json zap-api-scan.py -t /zap/wrk/openapi.json -O "$base" -f openapi \
        -c rules.tsv -J zap-api.json -I \
        -z "-config scanner.maxScanDurationInMins=${ZAP_API_MAX_MINUTES:-8} -config scanner.maxRuleDurationInMins=2"
      ;;
    full)
      printf 'TARGET=%s\nSCAN_USER=%s\nSCAN_PASSWORD=%s\nMAX_SCAN_MINUTES=%s\n' \
        "$base" "$scan_user" "$scan_password" "${ZAP_FULL_MAX_MINUTES:-45}" >"$envfile"
      run_scanner zap-full zap-full.json "0 1 2" "$version" -- \
        zap_docker zap-full.json zap.sh -cmd -autorun /zap/wrk/automation.yaml
      ;;
    *)
      log "unknown ZAP tier: $tier"
      exit 2
      ;;
  esac
done
finish
