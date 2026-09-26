# Triage log

Every finding that needed a human decision: true positive (TP), false positive
(FP), false negative (FN, a scanner missed something) or accepted, with the
evidence and what changed. Scanner numbers come from real runs, linked where
they live in GitHub Actions.

## 1. Planted flaws on the `vulnerable` branch

_Detection per flaw from the demo pull request's gate report; filled in from
that run (see section 4)._

## 2. Findings on `main` while building SecPipe

These came up on SecPipe's own code, in its own pipeline, and were triaged
like any other finding.

| # | Tool / rule | Where | Verdict | Evidence and action |
| --- | --- | --- | --- | --- |
| M1 | Gitleaks `secnotes-hardcoded-jwt-secret` (custom) | `scripts/k8s-lib.sh` | FP | `--from-file=jwt_secret="$tmp/jwt_secret"` is a file path. The custom rule now ignores values containing `$` (shell/template references), like the DB-password rule already did. Found by gate-1 on `main`, run 1. |
| M2 | Gitleaks `generic-api-key` | `sonar-project.properties` | FP | `sonar.projectKey=Weasley18_SecPipe` is a public identifier. Allowlisted for that rule, that file and that exact line shape only (`targetRules` + `condition = "AND"`), never by value. |
| M3 | Semgrep (registry) Dependabot without cooldown ×5 | `.github/dependabot.yml` | TP | A brand-new release is adopted immediately, the window in which hijacked packages are usually live. Added `cooldown: {default-days: 7}` to every ecosystem. |
| M4 | Semgrep "unrestricted GitHub OIDC policy", privileged pods | `policy/checkov-tests/`, `policy/kyverno/tests/` | Expected | Deliberately insecure fixtures that the Checkov/Kyverno test suites must flag. Excluded by path in `.semgrepignore`, with a comment. |
| M5 | Checkov `CKV_AWS_356` | `infra/bootstrap` boundary policy | TP | `kms:TagResource` on `*` is restrictable. Moved into a statement with an `aws:RequestTag/project` condition; `kms:CreateKey` stays unscopable by design. |
| M6 | Trivy config `AWS-0132` (HIGH) | Terraform state bucket | TP | State can contain secrets; it was on the AWS-managed key. Now a customer-managed key with rotation. |
| M7 | Trivy `AWS-0089`, Checkov `CKV_AWS_18/144`, `CKV2_AWS_62` | reports and state buckets | Accepted | Access logging, replication and event notifications cost money in a demo account; skipped inline with a justification ([ADR 0007](adr/0007-aws-profile-cost-tradeoffs.md)). Counted by the suppression inventory. |
| M8 | Kubescape `C-0012` (credentials in config) | `secnotes-config` ConfigMap | FP | Keys `SECNOTES_DB_PASSWORD_FILE` / `SECNOTES_JWT_SECRET_FILE` hold file paths to mounted Secrets. Tuned with `sensitiveKeyNamesAllowed` for those two exact keys in `policy/kubescape/controls-inputs.json` (the rest of Kubescape's defaults unchanged). |
| M9 | Checkov `CKV_K8S_40` (high UID) | Postgres StatefulSet | Accepted | UID 70 is the `postgres` user of the official image; it is non-root. Annotation skip with justification. |
| M10 | zizmor `github-env` | `.github/actions/secpipe-gate` | TP (low confidence) | The action appended to `$GITHUB_PATH`. The value was a fixed path, but writing environment files is a known injection surface; the CLI path is now a step output instead. |
| M11 | actionlint/shellcheck SC2129, SC2016 | workflows | TP (style) | Grouped redirects; replaced a backtick-in-single-quotes `printf`. |
| M12 | Bandit `B105` (hard-coded password) | `secpipe/aggregator/models.py`, `secpipe/reporters/markdown.py` | FP | `"secret": "Secrets"` (a category label) and `"pass": "pass"` (a gate outcome). Suppressed inline with `# nosec B105 -- <reason>`; the suppression inventory shows both as justified. |
| M13 | ZAP `100000-1` "client error response" ×150 (info) | API scan of `main` | Noise | 404/401/422 answers to ZAP's own forced-browse probes. The parser drops `100000-1`; the 5xx variant (`100000-2`) is kept. Result on `main` after that: 2 informational alerts (`10111` authentication request identified, `10104` user-agent fuzzer), nothing low or above. |
| M14 | ZAP `10096`, `10049`, `10027` | baseline/API scans | FP | Timestamps are note metadata; responses already send `Cache-Control: no-store`; "user"/"admin" appear in OpenAPI descriptions. Set to `IGNORE` in `zap/rules.tsv` with those reasons. |
| M15 | Trivy secret scan: JWT in the vulnerable image | `site-packages` of PyJWT (vulnerable image) | FP | An example token in PyJWT's own documentation strings, not a SecNotes secret. The real planted secrets are caught by Gitleaks and Trivy's image-config scan. |

## 3. Scanner blind spots found (false negatives)

| # | Scanner | What it missed | Evidence | Mitigation |
| --- | --- | --- | --- | --- |
| N1 | Checkov `CKV_AWS_358` (GitHub OIDC trust) | `repo:Weasley18/*` and `repo:Weasley18/SecPipe:*` with `StringLike` pass; statements whose principal is a reference (not a literal ARN) are not inspected | Same fixtures, `CKV_AWS_358` vs `CKV_SECPIPE_2`: the built-in check PASSED `fail_owner_wildcard` and `fail_branch_wildcard`; on the vulnerable branch (flaw #13) it reported nothing while `CKV_SECPIPE_2` failed all three roles | Custom Python check `CKV_SECPIPE_2` (`policy/checkov/github_oidc_sub.py`) keyed on the `...:sub` condition, rejecting wildcards and `StringLike`; 9 fixture expectations in `policy/checkov-tests`. The Terraform module also rejects wildcard subjects in variable validation. |
| N2 | Every scanner | IDOR (flaw #3) as a confirmed vulnerability | Scanners have no notion of "owner" | Heuristic Semgrep rule flags lookups by id without an owner filter (severity raised to high by policy); confirmation is manual review, and the fix has a regression test (`app/tests/test_notes.py`). |
| N3 | Every scanner | Missing failed-login logging and rate limiting (flaw #11) | Absence of code is invisible to SAST | Unit tests on `main` assert both; the correlator's ingress-log rules still detect brute force against the vulnerable app. |

## 4. CI runs

_Links to the gate runs these numbers come from; filled in from the runs._

## 5. Manual validation (Burp Suite, Wireshark)

Not performed yet. The procedure (IDOR with two users in Repeater, JWT
tampering with the JWT Editor extension, SSRF against `169.254.169.254` and
`postgres:5432`, Intruder against `/auth/login`, a Wireshark capture of a login
over plain HTTP vs. the TLS ingress) is in the project brief; record each
result here with a screenshot, against your own deployment only. The fixed
behaviour on `main` is already covered by the security regression tests in
`app/tests/` (one per planted flaw).
