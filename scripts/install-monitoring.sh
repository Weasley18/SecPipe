#!/usr/bin/env bash
# make monitoring: the SIEM-lite stack on the local kind cluster.
#   kube-prometheus-stack  Prometheus, Alertmanager, Grafana (+ SecPipe dashboard, rules)
#   Loki + Grafana Alloy   app, ingress, Falco and API-audit logs
#   Falco + Falcosidekick  runtime detection (modern eBPF), custom SecNotes rules
#   secpipe-tools          metrics exporter + correlator CronJob
#
# Optional alert delivery (otherwise alerts stay visible in Alertmanager/Grafana):
#   ALERT_WEBHOOK_URL  Slack/Discord-compatible webhook for critical and high alerts
#   ALERT_EMAIL, SMTP_SMARTHOST (host:port), SMTP_FROM, SMTP_USERNAME, SMTP_PASSWORD
set -euo pipefail
source "$(dirname "$0")/k8s-lib.sh"
source "$K8S_ROOT/monitoring/versions.sh"
MON="$K8S_ROOT/monitoring"
NS=monitoring
CLUSTER="${CLUSTER:-secpipe}"

command -v helm >/dev/null || {
  klog "helm is required (https://helm.sh/docs/intro/install/)"
  exit 1
}

# Falco needs privileged host access, so this namespace is "privileged" for
# Pod Security Admission and on the Kyverno platform-namespace exclusion list.
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null

# ------------------------------------------------------------ Alertmanager config
render() { python3 -c 'import os,sys,string; sys.stdout.write(string.Template(sys.stdin.read()).substitute(os.environ))'; }
export ALERT_EMAIL="${ALERT_EMAIL:-secpipe-alerts@example.invalid}"
export SMTP_SMARTHOST="${SMTP_SMARTHOST:-localhost:25}"
export SMTP_FROM="${SMTP_FROM:-secpipe@example.invalid}"
export SMTP_USERNAME="${SMTP_USERNAME:-secpipe}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
(
  umask 077
  render <"$MON/alertmanager/alertmanager.yaml" >"$tmp/alertmanager.yaml"
  printf '%s' "${ALERT_WEBHOOK_URL:-http://127.0.0.1:9/webhook-not-configured}" >"$tmp/url"
  printf '%s' "${SMTP_PASSWORD:-unset}" >"$tmp/password"
)
kubectl -n "$NS" create secret generic alertmanager-secpipe --from-file=alertmanager.yaml="$tmp/alertmanager.yaml" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic alertmanager-webhook --from-file=url="$tmp/url" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic alertmanager-smtp --from-file=password="$tmp/password" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# ------------------------------------------------------------------ Helm charts
klog "kube-prometheus-stack $KPS_CHART_VERSION"
helm upgrade --install kps kube-prometheus-stack --repo https://prometheus-community.github.io/helm-charts \
  --version "$KPS_CHART_VERSION" -n "$NS" -f "$MON/kube-prometheus-stack/values.yaml" --wait --timeout 10m

klog "Loki $LOKI_CHART_VERSION"
helm upgrade --install loki loki --repo https://grafana.github.io/helm-charts \
  --version "$LOKI_CHART_VERSION" -n "$NS" -f "$MON/loki/values.yaml" --wait --timeout 10m

klog "Grafana Alloy $ALLOY_CHART_VERSION"
helm upgrade --install alloy alloy --repo https://grafana.github.io/helm-charts \
  --version "$ALLOY_CHART_VERSION" -n "$NS" -f "$MON/alloy/values.yaml" \
  --set-file alloy.configMap.content="$MON/alloy/config.alloy" --wait --timeout 5m

klog "Falco $FALCO_CHART_VERSION (modern eBPF) + Falcosidekick"
helm upgrade --install falco falco --repo https://falcosecurity.github.io/charts \
  --version "$FALCO_CHART_VERSION" -n "$NS" -f "$MON/falco/values.yaml" \
  --set-file 'customRules.secnotes-rules\.yaml'="$MON/falco/rules/secnotes-rules.yaml" --wait --timeout 10m

# ---------------------------------------------------------- rules and dashboard
{
  echo "apiVersion: monitoring.coreos.com/v1"
  echo "kind: PrometheusRule"
  echo "metadata: {name: secpipe, namespace: $NS}"
  echo "spec:"
  sed 's/^/  /' "$MON/prometheus/rules/secpipe.rules.yaml"
} | kubectl apply -f -
kubectl -n "$NS" create configmap secpipe-dashboard \
  --from-file="$MON/grafana/dashboards/secpipe-security-posture.json" --dry-run=client -o yaml |
  kubectl label --local -f - grafana_dashboard=1 -o yaml | kubectl apply -f -

# --------------------------------------------------- exporter + correlator
docker build -f "$K8S_ROOT/tools/secpipe.Dockerfile" -t secpipe-tools:local "$K8S_ROOT"
kind load docker-image secpipe-tools:local --name "$CLUSTER"
kubectl apply -f "$MON/secpipe/secpipe.yaml"

klog "monitoring ready. Grafana: kubectl -n $NS port-forward svc/kps-grafana 3000:80"
klog "  admin password: kubectl -n $NS get secret kps-grafana -o jsonpath='{.data.admin-password}' | base64 -d"
