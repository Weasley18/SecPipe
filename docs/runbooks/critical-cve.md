# Runbook: critical CVE in a deployed image

**Severity:** critical when the CVE is on CISA KEV or EPSS > 0.1 and reachable.
**Owner:** service team; security confirms exposure.
**Raised by:** the gate (KEV-listed CVEs block even without a fix; EPSS above
policy bumps severity), `SecPipeCriticalFindingOnMain`, the nightly Grype
re-scan of the last released SBOM (new CVEs against an image already running).

## 1. Preparation
- Every released image has a CycloneDX SBOM attested with Cosign and kept as
  the `secpipe-sbom` artifact, so "are we affected?" is a lookup, not a rebuild.
- `policy.yaml` sets the SLA per severity (critical 7 days) and issues are
  opened automatically on `main` with a due date.

## 2. Detection and analysis
1. Which image digests contain the package? Query the SBOM:
   ```bash
   gh run download <run> -n secpipe-sbom && jq '.components[] | select(.name=="<pkg>") | .version' sbom.cdx.json
   cosign download attestation ghcr.io/weasley18/secnotes@<digest> | jq -r .payload | base64 -d | jq '.predicate.components | length'
   ```
2. Is it reachable? OS package in the base image vs. a Python dependency the
   app imports; network exposure (only the ingress reaches the API; NetworkPolicy
   blocks egress). KEV means exploitation is already happening somewhere.
3. Is a fixed version available? (`fix_version` in the finding.)

## 3. Containment
- If exploitable and no fix yet: reduce exposure (disable the affected feature
  flag/route, tighten NetworkPolicy, WAF rule), and record a time-boxed exception
  in `policy.yaml` (owner, reason, `expires`), reviewed by a code owner.

## 4. Eradication
- Bump the dependency (Dependabot usually has the PR; cooldown can be bypassed
  for security updates) or rebuild on a patched base image digest.
- The gate re-scans; the finding moves to `fixed`, and the Issue auto-closes.

## 5. Recovery
- Deploy the new digest (signed by CI, admitted by Kyverno); confirm the old
  digest is no longer running: `kubectl get pods -A -o jsonpath='{..image}' | tr ' ' '\n' | sort -u`.
- Remove the exception if one was added.

## 6. Lessons learned
- Time from CVE publication to detection (nightly re-scan) and to fix (MTTR panel).
