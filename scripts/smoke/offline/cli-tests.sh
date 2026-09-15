#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
cd "${ROOT_DIR}/cli"
go test ./...
go run -ldflags="-X main.version=${VERSION}" ./cmd/neverlauncher version | grep -q "${VERSION}"
