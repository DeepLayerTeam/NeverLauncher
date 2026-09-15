#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT="${ROOT_DIR}/dist/preflight/nl"
mkdir -p "$(dirname "${OUT}")"
(cd "${ROOT_DIR}/cli" && go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" ./cmd/neverlauncher)
"${OUT}" version | grep -q "${VERSION}"
