# 0002: The gate's rules live in policy.yaml, not in scanner flags

- **Status:** accepted

## Context
The usual way to "gate" is scanner flags: `trivy --exit-code 1 --severity HIGH`,
`semgrep --error`. That spreads the policy over a dozen command lines, makes
every tool disagree on what "high" means, and gives no place for exceptions,
expiry dates or per-branch strictness.

## Decision
Scanners always exit 0 when they ran (`scripts/ci/lib.sh` contract) and write
full reports. One file, `policy/policy.yaml`, validated against a JSON Schema
(`secpipe policy validate`), decides: block/warn thresholds per branch (`main`
blocks at medium, other branches at high), categories that always block
(secrets), KEV and EPSS escalation, "no fix available" handling, only-new-on-PR,
licence allow/deny lists, SLA days, severity overrides, and exceptions that
require `reason`, `owner` and `expires` (an expired exception fails the gate;
one expiring within 14 days warns).

## Consequences
- Changing the bar is a reviewed diff to one file (CODEOWNERS), with its digest
  printed in every PR comment.
- In-code suppressions (`# nosec`, `# nosemgrep`, `checkov:skip`, ...) are
  inventoried and must carry a justification; more than 3 new ones in a PR
  needs the `secpipe:suppressions-approved` label.
- The aggregator must understand every scanner's severity scale; that
  normalisation is tested per parser against real reports.
