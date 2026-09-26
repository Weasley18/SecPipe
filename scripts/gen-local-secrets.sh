#!/usr/bin/env bash
# Generate random local-development secrets into .secrets/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p .secrets
for name in db_password jwt_secret; do
  if [[ ! -s ".secrets/${name}" ]]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > ".secrets/${name}"
    echo "generated .secrets/${name}"
  fi
done
# Containers run as non-root UIDs and must be able to read the bind-mounted files.
chmod 0644 .secrets/*
