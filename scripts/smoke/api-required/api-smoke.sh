#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${1:-http://localhost:8080}"
VERSION="${NEVERLAUNCHER_EXPECTED_VERSION:-}"
[ -n "${VERSION}" ] || VERSION="$(tr -d '[:space:]' < "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/VERSION")"
curl -fsS "${BASE_URL}/health" | grep -q "${VERSION}"
curl -fsS "${BASE_URL}/ready" | grep -q 'ready'
curl -fsS "${BASE_URL}/health" | grep -q "${VERSION}"
curl -fsS "${BASE_URL}/api/v1/status" | grep -q "${VERSION}"
curl -fsS "${BASE_URL}/api/v1/projects" >/dev/null
