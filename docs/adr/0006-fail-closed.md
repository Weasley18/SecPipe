# 0006: Fail closed when a scanner produces no usable report

- **Status:** accepted

## Context
A security gate that passes when a scanner crashes is worse than no gate: it
reports "clean" exactly when it saw nothing. Real failure modes we met while
building this: Gitleaks printing "0 commits scanned, no leaks found" and exiting
0 when git could not read the repository; Syft exiting 1 without output because
it could not write `/tmp` as the runner's UID; a truncated JSON report.

## Decision
The gate takes an explicit `--expect` list. Every expected scanner must have
left a parseable report and a `<tool>.meta.json` with status `ok`; otherwise
the gate exits **2** (error), distinct from **1** (blocked) and **0** (pass).
Scanner scripts add their own guards (Gitleaks refuses shallow clones and
cross-checks the commit count against git). An optional scanner (Snyk,
SonarCloud without a token) is recorded as `skipped`, which is only an error if
it was expected.

## Consequences
- Infrastructure flakiness turns the gate red. That is the point; the PR
  comment says "failed closed" and names the tool, so it is not mistaken for a
  finding.
- The first CI runs of this repository failed closed twice (Syft, missing DAST
  report) until the underlying problems were fixed, rather than passing.
