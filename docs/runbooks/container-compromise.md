# Runbook: container compromise

**Severity:** critical. **Owner:** platform on-call + security.
**Raised by:** Falco (`Shell spawned in SecNotes pod`, `SecNotes secret file read
by unexpected process`, `SecNotes API unexpected outbound connection`, `SecNotes
package manager or download tool run`), correlator `post_exploitation_chain`
(Falco alert in a pod within 10 minutes of a suspicious request routed to it)
and `ssrf_probe`, Prometheus `SecNotesSSRFBlocked`.

## 1. Preparation
- Pods run non-root, read-only root filesystem, no capabilities, seccomp
  RuntimeDefault, no service-account token: a foothold has little to work with.
- Default-deny NetworkPolicies; every allow excludes `quarantine=true`, and a
  `quarantine` policy is pre-installed, so isolation is one label away.
- Falco (modern eBPF) and the API audit log (who ran `kubectl exec`) ship to Loki.

## 2. Detection and analysis
1. From the alert: pod, node, rule, source IP; open its `grafana_explore_url`.
2. Was it us? Check the API audit log for an `exec` into the pod:
   `{job="kubernetes-audit"} |= "pods/exec" |= "<pod>"`. An authorised exec by
   an operator is a policy question; an exec nobody owns, or a shell spawned by
   the Python process (`parent=python`), is a compromise.
3. Correlate: requests routed to the pod in the previous 10 minutes
   (`{namespace="ingress"} |= "<pod IP>"`), SSRF probes, unexpected egress.

## 3. Containment (first five minutes)
```bash
scripts/quarantine-pod.sh <pod> secnotes
```
It labels the pod `quarantine=true` (all traffic cut), changes its app label so
the Service stops routing to it and the Deployment starts a clean replica, and
saves describe/YAML/logs/events/Falco events with a SHA-256 manifest to
`evidence/`. **Leave the pod running**: memory and `/tmp` are evidence.
If the node itself is suspect: `kubectl cordon <node>`.

## 4. Eradication
- Find the entry point (vulnerable dependency, injection, leaked credential) and
  fix it in code; the fix goes through the gate like any other change.
- Rotate every secret the pod could read (see `leaked-secret.md`): the DB
  password and JWT key are mounted in the API pod.
- Rebuild from source; never "clean" a running container. The new image is
  signed by CI and only signed images are admitted.

## 5. Recovery
- Deploy the fixed image by digest; watch Falco and the correlator for recurrence.
- Delete the quarantined pod only after the evidence has been captured:
  `kubectl -n secnotes delete pod <pod>`.

## 6. Lessons learned
- Time to detect and time to contain (from the alert and `evidence/*/SUMMARY.md`).
- Which layer should have stopped it earlier (SAST rule, DAST test, admission)?
- Write it up in `docs/incidents/`, following `drill-01.md`.
