#!/usr/bin/env bash
# Tests for the monitoring configuration, with the pinned tool images:
#   promtool  rule syntax + unit tests (monitoring/prometheus/tests)
#   amtool    Alertmanager config and the severity routing tree
#   falco     custom rules validated on top of the default ruleset
set -euo pipefail
source "$(dirname "$0")/lib.sh"
mon="$SECPIPE_ROOT/monitoring"

prom="$(tool_image promtool)"
docker run --rm --network none -v "$mon:/m:ro" -w /m/prometheus/tests --entrypoint promtool "$prom" \
  check rules /m/prometheus/rules/secpipe.rules.yaml
docker run --rm --network none -v "$mon:/m:ro" -w /m/prometheus/tests --entrypoint promtool "$prom" \
  test rules secpipe.rules.test.yaml

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
SMTP_SMARTHOST=smtp.example.com:587 SMTP_FROM=secpipe@example.com SMTP_USERNAME=secpipe ALERT_EMAIL=oncall@example.com \
  python3 -c 'import os,sys,string; sys.stdout.write(string.Template(sys.stdin.read()).substitute(os.environ))' \
  <"$mon/alertmanager/alertmanager.yaml" >"$rendered"
chmod 644 "$rendered"
am="$(tool_image amtool)"
amtool() { docker run --rm --network none -v "$rendered:/am.yaml:ro" --entrypoint amtool "$am" "$@"; }
amtool check-config /am.yaml
expect_route() { # expect_route <receiver> <labels...>
  local want=$1 got
  shift
  got="$(amtool config routes test --config.file=/am.yaml "$@" | tail -1)"
  [[ "$got" == "$want" ]] || { log "route for $* is '$got', expected '$want'"; exit 1; }
  log "route ok: $* -> $got"
}
expect_route page severity=critical rule=post_exploitation_chain
expect_route chat severity=high alertname=SecNotesSSRFBlocked
expect_route daily-digest severity=medium alertname=SecNotesLoginFailureSpike
expect_route daily-digest severity=low alertname=SecPipeExceptionExpiringSoon

falco="$(tool_image falco)"
docker run --rm --network none -v "$mon/falco/rules:/r:ro" "$falco" \
  falco -V /etc/falco/falco_rules.yaml -V /r/secnotes-rules.yaml 2>&1 | grep -E ': (Ok|.*[Ee]rror)' || exit 1
