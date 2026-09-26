# 0004: Kyverno instead of OPA Gatekeeper

- **Status:** accepted

## Context
Admission policies here are the standard hardening set (no `:latest`, non-root,
limits, no privileged/host access) plus image signature verification.

## Decision
Kyverno 1.19. Policies are Kubernetes YAML the platform team can read, it has
built-in `verifyImages` for Sigstore (Gatekeeper needs an external data
provider such as Ratify for signatures), and `kyverno test` gives unit tests in
CI (36 cases in `policy/kyverno/tests`).

## Consequences
- Rego's expressiveness is not needed for these rules; if it were, Gatekeeper
  (or Kyverno's CEL policies) would be reconsidered.
- Kyverno 1.19 marks `kyverno.io/v1 ClusterPolicy` as deprecated in favour of
  the CEL-based `ValidatingPolicy`/`ImageValidatingPolicy`. The policies still
  use ClusterPolicy (widest documentation, autogen for controllers, the spec's
  syntax); migrating them is tracked as a known gap.
- Pod Security Admission (`restricted`) runs first as a second, built-in layer.
