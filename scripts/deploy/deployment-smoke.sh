#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${1:-http://127.0.0.1:8080}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXPECTED_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"

curl -fsS "$BASE_URL/health" | grep -q "$EXPECTED_VERSION"
curl -fsS "$BASE_URL/ready" | grep -q '"status":"ready"'
curl -fsS "$BASE_URL/api/v1/status" | grep -q "$EXPECTED_VERSION"
curl -fsS "$BASE_URL/api/v1/projects" >/dev/null
printf '[NeverLauncher] canonical deployment smoke OK: %s\n' "$EXPECTED_VERSION"
