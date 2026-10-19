#!/usr/bin/env bash
# Build Java-free native Prestarter binaries for all supported desktop targets.
# Release root trust is compiled into the binary, never downloaded or TOFU'd.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
OUT="${1:-$ROOT/dist/release-${VERSION}}"
command -v go >/dev/null || { echo "Go 1.22+ is required" >&2; exit 2; }
ROOT_KEY="${NEVERLAUNCHER_PRESTARTER_ROOT_PUBLIC_KEY:-}"
if [[ -z "$ROOT_KEY" && -n "${NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE:-}" ]]; then
  ROOT_KEY="$(tr -d '[:space:]' < "$NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE")"
fi
[[ "$ROOT_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "A provisioned Ed25519 root public key (64 hexadecimal characters) is required" >&2; exit 2; }
ROOT_KEY="${ROOT_KEY,,}"
mkdir -p "$OUT"
(
  cd "$ROOT/prestarter"
  GOPROXY=off go test ./...
  for target in linux:amd64:x64 linux:arm64:arm64 windows:amd64:x64 windows:arm64:arm64 darwin:amd64:x64 darwin:arm64:arm64; do
    IFS=: read -r os arch label <<<"$target"
    case "$os" in windows) suffix=".exe";platform="windows";;darwin) suffix="";platform="macos";;*)suffix="";platform="linux";;esac
    name="neverprestarter-${VERSION}-${platform}-${label}${suffix}"
    echo "Building $name with embedded pinned trust root"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 GOPROXY=off \
      go build -trimpath -ldflags="-s -w -X main.embeddedRootPublicKey=${ROOT_KEY} -X main.version=${VERSION}" \
      -o "$OUT/$name" ./cmd/neverprestarter
  done
)
echo "Native Prestarter binaries: $OUT"
