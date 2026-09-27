# Triage log

Every finding that needed a human decision: true positive (TP), false positive
(FP), false negative (FN, a scanner missed something) or accepted, with the
evidence and what changed. Scanner numbers come from real runs, linked where
they live in GitHub Actions.

## 1. Planted flaws on the `vulnerable` branch

Source: the gate report of the demo pull request (sticky comment on
[Weasley18/SecPipe#3](https://github.com/Weasley18/SecPipe/pull/3), run 17) and,
for DAST and admission, the forced run on `vulnerable` (run 22); links in
section 4. The report table stops after 80 rows, so the Checkov and Kubescape
rule IDs below come from `scripts/ci/iac.sh` on the same commit with the same
pinned versions (raw counts identical to CI: Checkov Terraform 27,
Kubernetes 15, Dockerfile 3; Kubescape 7).

| # | Planted flaw | Detected by (rule, location) | Gate |
| --- | --- | --- | --- |
| 1 | Fake AWS key and DB password in code and git history | Gitleaks `aws-access-token` (`config.py:21`, also Semgrep), custom `secnotes-hardcoded-db-password` (`config.py:23`), custom `secnotes-api-token` (`config.py:24`, and `app/.env:2`, a file that exists only in history: added in one commit, deleted in the next); Trivy image secret scan (the AWS key inside the image); Bandit `B105` on `config.py:23`, `:24`, `:26` (low) | Critical, blocks (secrets always block) |
| 2 | SQL built with an f-string | Semgrep custom `secnotes-sqlalchemy-raw-sql` and registry `avoid-sqlalchemy-text` (`notes.py:58`, merged into one finding); Bandit `B608` (`notes.py:55`, low confidence, so the gate lowers it to low: reported, not blocking); ZAP `40018` SQL injection at `/notes/search?q='` (a single quote made the query fail with a 500; forced run 22, through the TLS Ingress) | High, blocks |
| 3 | IDOR on `GET /notes/{id}` | Semgrep custom `secnotes-possible-idor` (`notes.py:64`), a heuristic; confirmation is manual (N2) | High, blocks |
| 4 | JWT signature verification off, secret `secret123` | Semgrep custom `secnotes-jwt-verification-disabled` (critical) and registry `unverified-jwt-decode` (`auth.py:116`); Gitleaks custom `secnotes-hardcoded-jwt-secret` (`config.py:26`) | Critical, blocks |
| 5 | `yaml.load` on uploads | Semgrep custom `secnotes-unsafe-yaml-load` and registry `avoid-pyyaml-load`, Bandit `B506` (`imports.py:44`) | High, blocks |
| 6 | SSRF in link previews | Semgrep custom taint rule `secnotes-ssrf-user-url` (`preview.py:21`) | High, blocks |
| 7 | `subprocess` with `shell=True` | Semgrep `subprocess-shell-true` and Bandit `B602` (`admin.py:29`, merged); Bandit `B108` also flagged the hard-coded `/tmp` paths next to it (`admin.py:23`, `:30`) | High, blocks |
| 8 | MD5 password hashing | Bandit `B324`, Semgrep custom `secnotes-weak-password-hash` and registry `md5-used-as-password` (`auth.py:33`) | High, blocks |
| 9 | Old libraries | OSV-Scanner, pip-audit and Trivy each reported them; every CVE became one finding: PyYAML 5.3.1 `CVE-2020-14343` (critical, EPSS 0.06), h11 `CVE-2025-43859` (critical), PyJWT 2.3.0 `CVE-2022-29217` and 4 more, python-multipart ×8, certifi ×2, idna ×2, anyio ×2 | Critical, blocks; the one PyJWT CVE with no fix yet (`CVE-2025-45768`) warns |
| 10 | CORS `*` with credentials, debug tracebacks, no security headers | Semgrep custom `secnotes-fastapi-cors-wildcard-credentials` (`main.py:51`, high) and registry `wildcard-cors` (`main.py:53`); custom `secnotes-fastapi-debug-enabled` (`main.py:42`); on the running app (forced run 22) ZAP `90022` application error disclosure (a debug traceback from `/preview`), `10021` no `X-Content-Type-Options`, `90004` no `Cross-Origin-Resource-Policy`, `10035` no HSTS | High, blocks |
| 11 | No failed-login logging, no rate limit | Nothing (by design, N3) | Not detected |
| 12 | Root user, EOL base, secret in `ENV`, `ADD .` | Hadolint `DL3020`; Checkov `CKV_DOCKER_2/3/4`; Semgrep `missing-user`; Trivy `DS-0002` (root), `DS-0031` (secret in `ENV`, in the Dockerfile and in the image config), "base image OS debian 11.11 is end-of-life"; Gitleaks custom `dockerfile-env-secret`; the EOL base brought 2,055 OS CVEs with a fix (25 critical, 478 high, 1,552 medium), aggregated into one finding | Critical, blocks |
| 13 | Public S3 bucket, SSH from `0.0.0.0/0`, IAM `*`, mutable ECR, `repo:owner/*` OIDC trust | Checkov: `CKV_AWS_20`, `CKV_AWS_53`-`56`, `CKV2_AWS_6`, `CKV2_AWS_65`, `CKV_AWS_145`, custom `CKV2_SECPIPE_1` (bucket); `CKV_AWS_24`, `CKV_AWS_382`, `CKV_AWS_23`, `CKV2_AWS_5`, `CKV_AWS_148` (bastion, default VPC); `CKV_AWS_1`, `CKV_AWS_49`, `CKV_AWS_356`, `CKV_AWS_107`-`111` (IAM `*`); `CKV_AWS_51`, `CKV_AWS_163` (ECR); custom `CKV_SECPIPE_2` on all three OIDC roles (the built-in `CKV_AWS_358` did not fire, N1). Trivy config `AWS-0086/0087/0091/0092/0093`, `AWS-0107`, `AWS-0104`, `AWS-0101`, `AWS-0031`, `AWS-0030`, `AWS-0132` (the rows shown come from the image scan of the copied repository, see below; `trivy-iac` reported 13 results on `infra/`); Semgrep `aws-ecr-mutable-image-tags` | Critical, blocks |
| 14 | Privileged, root, `:latest`, no limits | Checkov `CKV_K8S_10`-`14`, `16`, `20`, `22`, `23`, `28`, `31`, `37`, `38`, `40`, `43`; Kubescape `C-0013`, `C-0016`, `C-0017`, `C-0055`, `C-0057`, `C-0270`, `C-0271`; Semgrep `allow-privilege-escalation`; Trivy `KSV-0014`, `KSV-0017` (image scan of the copied repository); at admission, Kyverno `verify-image-signature` denied the branch's own Deployment: `ghcr.io/weasley18/secnotes:latest` has no verifiable signature (no Sigstore bundle to fetch; runs 11, 18 and 22) | High, blocks |

Totals for that pull request: 18 scanners (Snyk and SonarCloud skipped: no
token), 11,223 raw results, 7,516 unique findings after deduplication,
2,255 blocking and 4,419 warnings. 13 of the 14 flaws were caught by at
least one scanner, 11 of them by two or more tools; flaw #11 is caught only by
the tests on `main` and the runtime rules.

Side effects of flaw #12 worth knowing: because `ADD .` copies the whole
repository into the image, Trivy's image scan also reported the Terraform and
Kubernetes misconfigurations (paths `image:/app/...`) and the deliberately
insecure Checkov test fixtures (`image:/app/policy/checkov-tests/main.tf`). On
`main` the image contains only `app/src`, and none of these appear.

False positives in the demo report:

| # | Tool / rule | Where | Verdict | Evidence and action |
| --- | --- | --- | --- | --- |
| V1 | Trivy secret scan: "JWT token" in the vulnerable image (medium) | `/root/.cache/pip/http-v2/...` (vulnerable image) | FP | A JWT-shaped string inside a package download that pip cached, because the vulnerable Dockerfile installs without `--no-cache-dir`; not a SecNotes secret. The planted secrets are caught by Gitleaks and by Trivy's image-config scan. The hardened image has no pip cache. |
| V2 | Trivy `KSV-0109` "ConfigMap with secrets" | `image:/app/k8s/base/configmap.yaml` (vulnerable image) | FP | The same file-path keys as M8, seen only because flaw #12 copies `k8s/` into the image; `trivy-iac` scans only `infra/`, so it never appears on `main`. No tuning needed. |

## 2. Findings on `main` while building SecPipe

These came up on SecPipe's own code, in its own pipeline, and were triaged
like any other finding.

| # | Tool / rule | Where | Verdict | Evidence and action |
| --- | --- | --- | --- | --- |
| M1 | Gitleaks `secnotes-hardcoded-jwt-secret` (custom) | `scripts/k8s-lib.sh` | FP | `--from-file=jwt_secret="$tmp/jwt_secret"` is a file path. The custom rule now ignores values containing `$` (shell/template references), like the DB-password rule already did. Found by gate-1 on `main`, run 1. |
| M2 | Gitleaks `generic-api-key` | `sonar-project.properties` | FP | The SonarCloud project key (`Weasley18_SecPipe`) is a public identifier. Allowlisted for that rule, that file and that exact line shape only (`targetRules` + `condition = "AND"`), never by value. |
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
| M13 | ZAP `100000-1` "client error response" ×150 (info) | API scan of `main` | Noise | 404/401/422 answers to ZAP's own forced-browse probes. The parser drops `100000-1`; the 5xx variant (`100000-2`) is kept, and it found M17. In CI on `main` (run 16) the baseline then raised only `10111` (authentication request identified, informational) and the API scan only M17. |
| M14 | ZAP `10096`, `10049`, `10027`; `10015` (info) | baseline/API scans | FP | Timestamps are note metadata; responses already send `Cache-Control: no-store`, which forbids any caching (ZAP checks `10015` only over HTTPS, so it appeared once CI scanned through the TLS Ingress, run 19; informational, left visible); "user"/"admin" appear in OpenAPI descriptions. Set to `IGNORE` in `zap/rules.tsv` with those reasons. |
| M16 | Gitleaks `generic-api-key` | `docs/triage-log.md` (commit `215ac2e`) | FP | Row M2 of this log quoted the Sonar property line verbatim, so the gate blocked `main` on its own documentation (run 7). The line was reworded and that one historical finding is accepted by fingerprint in `.gitleaksignore` (history is scanned in full, so the old commit would block every run). |
| M17 | ZAP `100000` "A Server Error response code was returned" (low) | `GET /notes/{id}`, API scan of `main` (run 16) | TP | `GET /notes/508729044883779239` answered 500. SQLAlchemy's psycopg dialect binds the id as `::INTEGER`, and PostgreSQL raises "integer out of range" for anything above 2,147,483,647. The unit tests run on SQLite, which has no such limit, so only DAST against the real stack could see it. Reproduced against PostgreSQL 17 (500 before, 422 after); note ids are now bounded at the API edge (`Path(ge=1, le=2**31 - 1)`), with a regression test in `app/tests/test_notes.py`. Low severity (no data exposure, the hardened app returns a generic 500), so the gate warned instead of blocking. |
| M18 | Code review during DAST triage, confirmed by a ZAP A/B test | Default rate limit, every route except login | TP | The configured 120/minute never applied: a local ZAP scan of `main` at 120/minute and at 100000/minute gave identical results, 0 responses with status 429, and six `GET /notes` at `3/minute` all answered 200. slowapi 0.1.10's ASGI middleware looks the endpoint up in `app.routes`, where FastAPI 0.141 wraps each included router without an `endpoint`; every router route resolved to no handler and was exempt, so only the login decorator throttled anything. The default limit is now an app-wide dependency on the endpoint FastAPI matched, before authentication, with one budget per route (enumerating `/notes/1`, `/notes/2`, ... shares it). Regression tests in `app/tests/test_ratelimit.py`: 429 with `Retry-After` on the 4th request, throttling before authentication, probes never throttled, the `rate_limited` log event and metric. |
| M19 | Grype, nightly SBOM re-scan: 8 blocking, `CVE-2026-82049` (high, `tarfile`), `CVE-2025-12781` and `CVE-2026-3446` (`base64`), `CVE-2026-6019` (`http.cookies`), `CVE-2026-15806` (`urllib.request`), `CVE-2025-15366` (`imaplib`), `CVE-2025-15367` (`poplib`), `CVE-2026-17084` (`stringprep`) | `python@3.12.14` in the released image (nightly run 1) | Accepted (TP, not reachable) | NVD CPE ranges such as `< 3.13.10` or `< 3.15.0rc2` with no 3.12 fixed version. 3.12.14 is the newest 3.12 release and neither its release notes nor 3.12.13's list these fixes, so the matches are real. None is reachable in SecNotes: nothing extracts archives (`admin.py` only writes a tarball), and cookies, `imaplib`, `poplib` and urllib password managers are unused; PyJWT's base64 decoding could at most accept another spelling of a validly signed token, and revocation and refresh-token reuse detection key on `jti`. Moving the runtime to Python 3.14 would fix 5 of the 8 (the other 3 are fixed only in 3.15 pre-releases), so the owner accepted all 8 until 2026-12-31: one exception per CVE in `policy/policy.yaml`, scoped to Grype and `python@3.12.*`, each with its reason; the gate warns from 14 days before and fails once they expire, which forces the re-review. |
| M20 | ZAP `100000` "A Server Error response code was returned" ×3 (low) | `POST /notes`, `PUT /notes/{id}`, `GET /notes/search?q=%00`, API scan of `main` (run 19) | TP | `q=%00` pointed at NUL bytes: psycopg refuses to send them ("PostgreSQL text fields cannot contain NUL (0x00) bytes"), so the request ended in a 500. SQLite stores NUL, so the unit tests could not see it. Reproduced against PostgreSQL: creating, updating and searching notes, logging in (username lookup) and the YAML import all answered 500 with a NUL byte, and 422 after the fix; titles, bodies, the search term and the login username now reject NUL at the API edge. The `PUT` 500 came back in run 20 with a second cause (M21). Regression test `test_nul_bytes_are_rejected`. |
| M21 | ZAP `100000` (low) | `PUT /notes/{id}`, API scan of `main` (run 20) | TP | A race: the active scanner sends requests in parallel, and a `DELETE` of the same note between the PUT's read and its reload made `db.refresh()` fail ("Could not refresh instance"). Against PostgreSQL, 40 PUT/DELETE pairs on one note gave 39 PUT 500s before and none after (each 200 or 404). PUT and DELETE now read the note with `SELECT ... FOR UPDATE` and reload it before the commit, while the lock is held. Regression test `test_update_and_delete_lock_the_note_row` (SQLite has no row locks, so it checks the statements as PostgreSQL receives them). |

## 3. Scanner blind spots found (false negatives)

| # | Scanner | What it missed | Evidence | Mitigation |
| --- | --- | --- | --- | --- |
| N1 | Checkov `CKV_AWS_358` (GitHub OIDC trust) | `repo:Weasley18/*` and `repo:Weasley18/SecPipe:*` with `StringLike` pass; statements whose principal is a reference (not a literal ARN) are not inspected | Same fixtures, `CKV_AWS_358` vs `CKV_SECPIPE_2`: the built-in check PASSED `fail_owner_wildcard` and `fail_branch_wildcard`; on the vulnerable branch (flaw #13) it reported nothing while `CKV_SECPIPE_2` failed all three roles | Custom Python check `CKV_SECPIPE_2` (`policy/checkov/github_oidc_sub.py`) keyed on the `...:sub` condition, rejecting wildcards and `StringLike`; 9 fixture expectations in `policy/checkov-tests`. The Terraform module also rejects wildcard subjects in variable validation. |
| N2 | Every scanner | IDOR (flaw #3) as a confirmed vulnerability | Scanners have no notion of "owner" | Heuristic Semgrep rule flags lookups by id without an owner filter (severity raised to high by policy); confirmation is manual review, and the fix has a regression test (`app/tests/test_notes.py`). |
| N3 | Every scanner | Missing failed-login logging and rate limiting (flaw #11) | Absence of code is invisible to SAST | Unit tests on `main` assert both (for rate limiting only the login limit was tested until M18 showed the default limit never applied); the correlator's ingress-log rules still detect brute force against the vulnerable app. |
| N4 | ZAP in CI (transport) | Everything after the first connection reset in runs 16 and 18, including the planted SQL injection (flaw #2) | The scan went through `kubectl port-forward`, which closes for good at the first stream error, and an active-scan probe that makes the pod reset a connection is enough. Runs 16 and 18 end without the "Terminate orphan process ... (kubectl)" line that runs 11 and 15 (idle forward) show: the forward was already dead. ZAP reached 28 URLs of the vulnerable app in run 18 against 215 locally without a forward (same ZAP 2.17.0, same image), and reported `PASS: SQL Injection [40018]` where the local scan reports `WARN-NEW` at `/notes/search?q='`. | CI scans through the TLS Ingress (Traefik on kind's `127.0.0.1:8443`, verified against the cluster CA), and `zap.sh` fails closed when the target stops answering during a scan. Forced run 22, through the Ingress, reached 209 URLs and reported `40018` at `/notes/search?q='`. |

## 4. CI runs

Runs of the `secpipe` workflow these numbers come from (run number, as shown in
the Actions tab). The `ci` and `terraform` workflows are green on the same
commits.

| Run | Trigger | Commit | Result | What it shows |
| --- | --- | --- | --- | --- |
| [1](https://github.com/Weasley18/SecPipe/actions/runs/36265371937) | push to `main` | `9375888` | fail | First run on SecPipe's own code: the gate blocked its own repository (M1). |
| [7](https://github.com/Weasley18/SecPipe/actions/runs/36267213434) | push to `main` | `215ac2e` | fail | The gate blocked `main` on this log quoting a property line (M16). |
| [11](https://github.com/Weasley18/SecPipe/actions/runs/36267316773) | forced DAST, `vulnerable` | `fd5f82d` | fail | Admission rejected the branch's own Deployment; 12/12 admission and NetworkPolicy tests with the vulnerable image deployed; ZAP hit the port-forward clash fixed in `3d19e98`. |
| [15](https://github.com/Weasley18/SecPipe/actions/runs/36267470099) | push to `main` | `4a5313d` | fail | Publish, keyless signing, deploy by digest and 12/12 admission tests green; ZAP hit the same port-forward clash. |
| [16](https://github.com/Weasley18/SecPipe/actions/runs/36268142173) | push to `main` | `3d19e98` | pass | First fully green end-to-end run. Its ZAP API scan (106 URLs) found M17, but went through a `kubectl port-forward` that died mid-scan (N4). |
| [17](https://github.com/Weasley18/SecPipe/actions/runs/36268158424) | pull request #3 | `b47dd9e` | blocked (intended) | The demo gate report used in section 1. |
| [18](https://github.com/Weasley18/SecPipe/actions/runs/36268158690) | forced DAST, `vulnerable` | `b47dd9e` | blocked (intended) | Admission denied the branch's own Deployment and 12/12 tests passed with the vulnerable image deployed, but ZAP's port-forward died mid-scan: 28 URLs, SQL injection reported as PASS (N4). |
| [19](https://github.com/Weasley18/SecPipe/actions/runs/36305060118) | push to `main` | `48d86f9` | pass | First DAST through the TLS Ingress: 207 URLs in the API scan (106 in run 16), no 429 in the Traefik log; found M20. |
| [20](https://github.com/Weasley18/SecPipe/actions/runs/36305761775) | push to `main` | `3e751ef` | pass | M20 fixed; the API scan found M21. |
| [21](https://github.com/Weasley18/SecPipe/actions/runs/36305791060) | pull request #3 | `d5fe55f` | blocked (intended) | Gate 1 blocked; publish and deploy never ran. |
| [22](https://github.com/Weasley18/SecPipe/actions/runs/36305793177) | forced DAST, `vulnerable` | `d5fe55f` | blocked (intended) | Kyverno denied the branch's own Deployment; 12/12 tests; ZAP through the Ingress, 209 URLs: `40018` (flaw #2), `90022`, `10021`, `90004`, `10035` (flaw #10). |
| [23](https://github.com/Weasley18/SecPipe/actions/runs/36306627036) | push to `main` | `84b9824` | pass | M21 fixed. End to end in 537 s; ZAP through the Ingress: baseline 23 URLs, API scan 207 URLs, no warning above informational. |
| [nightly 1](https://github.com/Weasley18/SecPipe/actions/runs/36278242237) | schedule | `3d19e98` | blocked | The Grype re-scan of the released SBOM found 8 CPython CVEs with fixes on newer Python lines (M19); gate 1 blocked, so publish and the full ZAP scan were skipped. |

## 5. Manual validation (Burp Suite, Wireshark)

Not performed yet. The procedure (IDOR with two users in Repeater, JWT
tampering with the JWT Editor extension, SSRF against `169.254.169.254` and
`postgres:5432`, Intruder against `/auth/login`, a Wireshark capture of a login
over plain HTTP vs. the TLS ingress) is in the project brief; record each
result here with a screenshot, against your own deployment only. The fixed
behaviour on `main` is already covered by the security regression tests in
`app/tests/` (one per planted flaw).
