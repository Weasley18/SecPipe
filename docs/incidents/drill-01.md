# Drill 01: brute force, account takeover, SSRF probe, shell in pod

> **Status: not yet run.** This write-up is the template for the first drill.
> Every number below comes from `scripts/drill.sh` output
> (`evidence/drill-<timestamp>/timeline.md`) and the quarantine evidence folder;
> nothing is filled in until the drill has actually been run and recorded.
> (The drill needs a kind cluster with the monitoring stack, which the
> environment this repository was built in could not run.)

## How to run it

```bash
make cluster deploy monitoring     # kind + Calico + Kyverno, SecNotes, SIEM-lite stack
make drill                         # scripts/drill.sh, writes evidence/drill-<ts>/
scripts/quarantine-pod.sh <pod>    # containment, writes evidence/<ts>-<pod>/
```
Record the screen for the 3-minute video while doing it.

## Scenario

| Step | Attacker action | Expected detection |
| --- | --- | --- |
| 1 | 15 wrong passwords for one user from one client | correlator `brute_force` (medium); rate limiter returns 429 after 5/minute |
| 2 | Correct password from the same client | correlator `brute_force_then_success` (critical) |
| 3 | `/preview` aimed at `169.254.169.254` | SSRF guard blocks it; correlator `ssrf_probe` (high); Prometheus `SecNotesSSRFBlocked` |
| 4 | `kubectl exec` a shell into the API pod and read the mounted secrets | Falco `Shell spawned in SecNotes pod` and `SecNotes secret file read by unexpected process` (critical); correlator `post_exploitation_chain` (critical) |

## Timeline (UTC)

_Paste `timeline.md` here: action time, alert, severity, time to detect._

| Step | Action | Alert | Severity | Time to detect |
| --- | --- | --- | --- | --- |
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |

Target: every step detected in under 60 seconds.

## Detection sources

_Which layer fired first for each step (app metrics, correlator over Loki, Falco
via Falcosidekick, API audit log), and which links in the alert (runbook,
Grafana Explore) were actually useful._

## Response

_Containment time from `evidence/<ts>-<pod>/SUMMARY.md`; confirmation that the
quarantined pod could reach nothing and a fresh replica served traffic._

## What worked / what was missed

_Honest notes: missed or late detections, noisy alerts, runbook steps that were
unclear._

## Follow-up actions

| Action | Owner | Due |
| --- | --- | --- |
| | | |
