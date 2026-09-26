#!/usr/bin/env bash
# Protect main so the SecPipe gate cannot be skipped: required status checks
# (the gate and the quality workflow), one approving review, code-owner
# review, no force pushes or deletions, admins included.
#   GH_TOKEN with repo admin rights; REPO defaults to the current repository.
set -euo pipefail
repo="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
gh api -X PUT "repos/$repo/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "SecPipe / secpipe-gate"},
      {"context": "SecPipe / gate-1"},
      {"context": "tests, ruff, mypy"},
      {"context": "custom rules and policies"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
echo "main protected in $repo"
# Secret scanning + push protection (public repositories): blocks known token
# formats before they reach the remote, a third layer next to pre-commit and CI.
gh api -X PATCH "repos/$repo" --input - <<'JSON' >/dev/null || echo "enable secret scanning in Settings > Code security"
{"security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
