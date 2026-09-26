# Runbook: brute force and credential stuffing

**Severity:** medium (brute force), high (credential stuffing), critical (brute
force then success). **Owner:** security.
**Raised by:** correlator rules `brute_force` (10+ failed logins from one IP in
5 minutes), `credential_stuffing` (5+ distinct usernames failing from one IP in
5 minutes), `brute_force_then_success` (a successful login from a flagged IP
within 30 minutes); Prometheus `SecNotesLoginFailureSpike` (volume only).

## 1. Preparation
- Login is rate limited (5/minute per client IP, HTTP 429 with `Retry-After`);
  rate-limited attempts still count as failures for detection.
- Passwords are Argon2id hashes; failed logins are logged with username, reason
  and client IP; admin accounts can be required to use TOTP MFA.
- The client IP is trustworthy only because uvicorn trusts `X-Forwarded-For`
  from the pod network alone and NetworkPolicy admits only the ingress.

## 2. Detection and analysis
1. Source IP, targeted usernames and counts are in the alert labels and
   `evidence_count`; open `grafana_explore_url`.
2. Was any attempt successful? `{namespace="secnotes"} | json | event="login_success" | client_ip="<ip>"`.
   A `brute_force_then_success` alert means **yes**: treat the account as compromised.
3. One IP many users = stuffing (breached password lists); many IPs one user =
   distributed guessing (per-IP limits will not see it: check the volume alert).

## 3. Containment
- Block the source as far out as possible: the WAF / cloud firewall / load
  balancer in front of the ingress. In-cluster, a NetworkPolicy on the ingress
  controller with `ipBlock.except: [<ip>/32]` works only where the controller
  sees real client IPs (on the local kind setup every client arrives as the
  Docker host, so there the rate limiter is the effective control).
- For a successful login: revoke the user's refresh tokens (log out all
  sessions), force a password reset, require MFA for the account.

## 4. Eradication
- If stuffing succeeded, the password came from another breach: check the user
  against known-breached-password lists and enforce a reset.
- Tighten limits if needed (`SECNOTES_LOGIN_RATE_LIMIT`), add per-username
  throttling if the attack was distributed.

## 5. Recovery
- Remove temporary IP blocks after the campaign stops (they age badly).
- Confirm alerts resolve and legitimate users can log in.

## 6. Lessons learned
- Time from first failed login to alert; was the 10-in-5-minutes threshold right
  for the observed traffic? Record thresholds changed and why.
