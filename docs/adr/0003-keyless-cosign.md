# 0003: Keyless Cosign signing instead of a key pair

- **Status:** accepted

## Context
Admission control must know that an image came from this repository's CI and
not from someone with registry write access. A signing key pair works, but the
private key becomes the most valuable secret in the system: it must be stored,
rotated, and it can leak.

## Decision
Sign keylessly: the `publish` job requests a GitHub OIDC token, Fulcio issues a
short-lived certificate whose identity is the workflow
(`https://github.com/Weasley18/SecPipe/.github/workflows/secpipe-reusable.yml@refs/heads/main`),
and the signature is recorded in the public Rekor log. The SBOM is attached as
a signed CycloneDX attestation and GitHub build provenance is added. Kyverno
verifies the bundle (`type: SigstoreBundle`) and pins the subject with
`subjectRegExp` (the sigstore-go matcher takes an exact subject or a regular
expression, not a glob). Only the throwaway CI cluster also trusts the pull
request's own merge ref.

## Consequences
- No private key to manage or leak; rotation is automatic.
- Signing depends on Sigstore's public infrastructure being up; signatures and
  the workflow identity are public (fine for a public repo, a consideration for
  private ones, where a private Sigstore or KMS keys fit better).
- The identity is tied to the workflow path: renaming the reusable workflow
  changes the subject and needs a policy update in the same PR.
