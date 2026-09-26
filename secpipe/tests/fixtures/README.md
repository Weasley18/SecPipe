# Parser test fixtures

Every parser is tested against a report in this folder, plus an empty and a
truncated copy generated at test time.

| File | Provenance |
|---|---|
| `gitleaks.sarif` | Real: Gitleaks 8.30.1 over the `vulnerable` branch history. Author, e-mail and commit message removed; secret values were already redacted by `--redact`. |
| `semgrep.sarif` | Real: Semgrep 1.178.0 with `policy/semgrep/` over the `vulnerable` branch. Code snippets removed. |
| `bandit.json` | Real: Bandit 1.9.4 over the `vulnerable` branch. `code` excerpts replaced with `<redacted>` (they contained the planted fake credentials). |
| `hadolint.sarif` | Real: Hadolint 2.15.1 on the vulnerable Dockerfile. |
| `pip-audit.json` | Real: pip-audit 2.10.1 on the vulnerable `requirements.txt`. |
| `osv.json` | Real: OSV-Scanner 2.6.0 (offline PyPI database) on the vulnerable `requirements.txt`. |
| `licenses.json` | Real: pip-licenses 5.5.5 over the vulnerable dependency set. |
| `trivy-image.json` | Real: Trivy 0.74.0 on the vulnerable image, trimmed from 46 MB (a slice of OS CVEs including multi-package groups, all library CVEs, misconfigurations and secrets; references removed). |
| `checkov-dockerfile.json` | Real: Checkov 3.3.19 on the vulnerable Dockerfile; absolute paths normalised. |
| `zap-api.json`, `zap-baseline.json` | Real: ZAP 2.17 authenticated API scan / baseline scan against the vulnerable app, at most 3 instances per alert. |
| `zizmor.sarif` | Real: zizmor 1.30.1 on a deliberately unsafe sample workflow. |
| `kubescape.json` | Real: Kubescape 4.0.14 (NSA framework, SecPipe controls-inputs) on the rendered `k8s/overlays/ci` of the `vulnerable` branch (flaw #14). |
| `snyk.json`, `sonarqube.json`, `grype.json`, `prowler.json` | Synthesised from each tool's documented JSON schema (they need an account token, a cluster, a blocked database download or a cloud account to run here). Replace with real CI output when available. |

Fixtures are excluded from Semgrep and allowlisted in `.gitleaks.toml` by path.
