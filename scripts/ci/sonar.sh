#!/usr/bin/env bash
# SAST (optional): SonarCloud analysis, then open issues exported as
# reports/sonarqube.json for the aggregator. Skipped (and recorded as skipped)
# without SONAR_TOKEN, so the gate only fails closed if it was expected.
#   SONAR_TOKEN        analysis token (GitHub secret); passed by name, never argv
#   SONAR_HOST_URL     default https://sonarcloud.io
#   PR_NUMBER/HEAD_REF/BASE_REF  pull request analysis parameters
source "$(dirname "$0")/lib.sh"
cd "$WORKSPACE"
if [[ -z "${SONAR_TOKEN:-}" ]]; then
  skip_scanner sonarqube "SONAR_TOKEN not set"
  exit 0
fi
host="${SONAR_HOST_URL:-https://sonarcloud.io}"
props=(-Dsonar.host.url="$host")
scope=()
if [[ -n "${PR_NUMBER:-}" ]]; then
  props+=(-Dsonar.pullrequest.key="$PR_NUMBER" -Dsonar.pullrequest.branch="$HEAD_REF" -Dsonar.pullrequest.base="$BASE_REF")
  scope=(--pull-request "$PR_NUMBER")
fi

sonar_run() {
  DOCKER_TOOL_ARGS=(-e SONAR_TOKEN -e SONAR_USER_HOME=/tmp/.sonar)
  docker_tool sonar-scanner sonar-scanner "${props[@]}" || return $?
  DOCKER_TOOL_ARGS=()
  "$PYTHON" - "$host" "${scope[@]}" <<'PY'
import json, os, sys, time, urllib.parse, urllib.request

host = sys.argv[1]
pr = sys.argv[3] if len(sys.argv) > 3 else None
task = dict(line.split("=", 1) for line in open(".scannerwork/report-task.txt").read().split() if "=" in line)
headers = {"Authorization": f"Bearer {os.environ['SONAR_TOKEN']}"}

def get(url: str) -> dict:
    if not url.startswith("https://") and not url.startswith(host):
        raise SystemExit(f"refusing non-https Sonar URL {url}")
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as resp:  # noqa: S310  # nosec B310 -- https enforced above
        return json.load(resp)

for _ in range(60):
    status = get(task["ceTaskUrl"])["task"]["status"]
    if status in {"SUCCESS", "FAILED", "CANCELED"}:
        break
    time.sleep(5)
if status != "SUCCESS":
    raise SystemExit(f"Sonar background task ended with {status}")
issues, page = [], 1
while True:
    query = {"componentKeys": task["projectKey"], "resolved": "false", "ps": 500, "p": page}
    if pr:
        query["pullRequest"] = pr
    data = get(f"{host}/api/issues/search?{urllib.parse.urlencode(query)}")
    issues.extend(data.get("issues", []))
    if page * 500 >= data.get("paging", {}).get("total", 0):
        break
    page += 1
json.dump({"issues": issues, "total": len(issues)}, open(os.path.join(os.environ["REPORTS_DIR"], "sonarqube.json"), "w"))
PY
}
run_scanner sonarqube sonarqube.json "0" "$(tool_version sonar-scanner)" -- sonar_run
finish
