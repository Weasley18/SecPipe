# Runbook: leaked secret

**Severity:** critical for any live credential. **Owner:** the committer's team + security.
**Raised by:** Gitleaks (`secrets` job, pre-commit), GitHub push protection, the
aggregator (every Gitleaks finding is `critical` and always blocks), and
`SecNotesRefreshTokenReuse` (a stolen refresh token being replayed).

## 1. Preparation
- Secrets live in GitHub encrypted secrets (CI) and Kubernetes Secrets mounted
  as files (runtime); nothing secret is baked into images (`dockerfile-env-secret`
  rule) or committed (`.gitleaks.toml` custom rules for SecNotes tokens, JWT keys,
  DB passwords).
- Three layers: pre-commit hook, CI over full history, GitHub push protection.
- Allowlists are by path for test fixtures only, never by secret value.

## 2. Detection and analysis
1. Open the finding: rule, file, commit, author (`reports/gitleaks.sarif`; values
   are redacted, so fetch the value locally with `git show <commit>:<file>` only
   if you must confirm it).
2. Classify: real credential, test fixture, or false positive? Record the
   decision in `docs/triage-log.md` with the evidence.
3. Scope: when was it committed, is it on a public branch, was it pushed to a
   fork, is it in a released image (`trivy image --scanners secret`)? Assume a
   secret pushed to a public repository is compromised within minutes.
4. Check use: provider audit logs (AWS CloudTrail for keys; SecNotes auth logs
   in Loki for the JWT key: `{namespace="secnotes"} | json | event=~"token_.*"`).

## 3. Containment (revoke and rotate first)
Removing the commit does **not** un-leak the secret.
- **JWT signing key:** generate a new 256-bit key, update the Secret, roll the
  Deployment. Every existing access and refresh token becomes invalid.
  ```bash
  python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' > /tmp/jwt && \
  kubectl -n secnotes create secret generic secnotes-secrets --from-file=jwt_secret=/tmp/jwt \
    --from-literal=db_password="$(kubectl -n secnotes get secret secnotes-secrets -o jsonpath='{.data.db_password}' | base64 -d)" \
    --dry-run=client -o yaml | kubectl apply -f - && rm -f /tmp/jwt && \
  kubectl -n secnotes rollout restart deploy/secnotes-api
  ```
- **Database password:** `ALTER ROLE secnotes PASSWORD '...'` in Postgres, then
  update the Secret and restart the API.
- **Cloud keys / tokens:** revoke in the provider console; there are no
  long-lived AWS keys in this project (GitHub OIDC only), so any AWS key found is
  foreign and must be reported to its owner.
- **Stolen refresh token:** the app already revoked the whole token family on
  reuse; force a password reset for the user.

## 4. Eradication
- Remove the value from code, move it to the right store, add a regression test
  or a Gitleaks rule so the same shape is caught next time.
- Purge history only after rotation (`git filter-repo --replace-text`), then
  force-push and ask collaborators to re-clone. Forks and caches may keep it:
  rotation is the real fix.

## 5. Recovery
- Confirm the old credential fails (e.g. a token signed with the old JWT key
  gets 401) and the gate is green on `main`.
- Watch auth logs for 24 hours for use of the old credential.

## 6. Lessons learned
- Why did pre-commit not stop it (hook not installed, `--no-verify`)?
- Add the pattern to `.gitleaks.toml`; write the incident up in `docs/incidents/`.
