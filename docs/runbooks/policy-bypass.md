# Runbook: policy bypass

**Severity:** high. **Owner:** platform + security.
**Raised by:** `KyvernoAdmissionDenied` (someone keeps trying to deploy what
policy rejects), Kyverno PolicyReports showing a `fail` for a running workload,
or a workload found running that admission should have rejected (unsigned
image, privileged, root, `:latest`).

## 1. Preparation
- Defence in depth: manifest scanning in CI (Checkov, Kubescape), Pod Security
  Admission `restricted` on the namespace, Kyverno (5 policies incl. keyless
  signature verification), NetworkPolicies, token-less service accounts.
- Kyverno and PSA exclusions are limited to platform namespaces and are
  themselves in git (CODEOWNERS on `policy/`).

## 2. Detection and analysis
1. What was denied or what is running? `kubectl get policyreports -A`,
   `kubectl get pods -A -o jsonpath='{..image}'` vs. the signed digests.
2. How did it get in? Check the API audit log (`{job="kubernetes-audit"}`) for
   who created it, and whether it landed in an excluded namespace, pre-dated the
   policy (background scan reports it), or used a policy exception.
3. Was the webhook down? Kyverno's webhooks fail closed (`failurePolicy: Fail`)
   for `Enforce` rules; a webhook outage blocks deploys rather than admitting.

## 3. Containment
- Quarantine the workload (`scripts/quarantine-pod.sh`) or scale it to zero.
- Remove any RoleBinding that let the actor create workloads in an excluded namespace.

## 4. Eradication
- Close the gap: narrow the exclusion, add a Kyverno rule, add the case to
  `policy/kyverno/tests/` so `kyverno test` fails if it regresses.

## 5. Recovery
- Redeploy through the pipeline (signed, by digest). Confirm the PolicyReport passes.

## 6. Lessons learned
- Which layer should have caught it first? Add a regression test there.
