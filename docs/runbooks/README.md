# Runbooks

Each runbook follows the NIST SP 800-61 incident lifecycle: preparation,
detection and analysis, containment, eradication, recovery, lessons learned.
(SP 800-61 Rev. 3 maps the same activities onto the CSF 2.0 Detect, Respond
and Recover functions; the steps do not change.) Every alert that SecPipe
raises links to one of these pages through its `runbook_url` annotation.

| Runbook | Raised by |
| --- | --- |
| [leaked-secret.md](leaked-secret.md) | Gitleaks in CI or pre-commit, GitHub push protection, `SecNotesRefreshTokenReuse` |
| [container-compromise.md](container-compromise.md) | Falco (`Shell spawned in SecNotes pod`, secret read, unexpected egress), correlator `post_exploitation_chain`, `ssrf_probe`, `SecNotesSSRFBlocked` |
| [brute-force.md](brute-force.md) | Correlator `brute_force`, `credential_stuffing`, `brute_force_then_success`; `SecNotesLoginFailureSpike` |
| [critical-cve.md](critical-cve.md) | Gate findings with KEV or high EPSS, `SecPipeCriticalFindingOnMain`, nightly Grype SBOM re-scan |
| [policy-bypass.md](policy-bypass.md) | `KyvernoAdmissionDenied`, a workload running that admission should have rejected |

Evidence goes to `evidence/<timestamp>-<name>/` (git-ignored, SHA-256 manifest).
Incident write-ups go to `docs/incidents/`.
