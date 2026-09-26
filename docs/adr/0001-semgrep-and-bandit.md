# 0001: Run Semgrep and Bandit, not one SAST tool

- **Status:** accepted
- **Date:** 2026-09

## Context
SAST has to catch the SecNotes flaws that live in code: SQL built from strings,
JWT decoding without verification, `yaml.load`, SSRF, `shell=True`, weak
hashing, object access without an owner check. No single open-source tool
covers all of them well. Semgrep is pattern- and taint-based and lets us write
project-specific rules; Bandit knows Python's dangerous APIs deeply but cannot
be taught about SecNotes (routes, ORM, owner checks).

## Decision
Run both. Semgrep with the `p/owasp-top-ten`, `p/python` and `p/secrets` packs
plus seven custom rules in `policy/semgrep/` (each with a `semgrep --test`
file); Bandit over `app/src` and `secpipe`. The aggregator deduplicates: when
two tools report the same code rule at the same location, one finding remains
with `also_reported_by`. SonarCloud is optional (needs a token) and feeds the
same pipeline.

## Consequences
- Overlap is intentional and visible ("raw results -> unique findings" in every
  PR comment) instead of silently doubling the noise.
- Custom rules are code: reviewed, tested in CI, versioned.
- Two tools to keep current (both hash-locked, Dependabot updates them).
- Cross-tool dedupe only merges different tools; a single tool reporting two
  different secrets on adjacent lines stays two findings (a bug we hit and fixed).
