#!/usr/bin/env bash
# Соберите нативные бинарники Prestarter без Java для всех поддерживаемых целевых
# Desktop. Корневое доверие выпуска компилируется в бинарник, а не загружается и не
# принимается по TOFU.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
OUT="${1:-$ROOT/dist/release-${VERSION}}"
command -v go >/dev/null || { echo "Требуется Go версии 1.22 или новее" >&2; exit 2; }
ROOT_KEY="${LAUNCHER_PRESTARTER_ROOT_PUBLIC_KEY:-}"
if [[ -z "$ROOT_KEY" && -n "${LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE:-}" ]]; then
  ROOT_KEY="$(tr -d '[:space:]' < "$LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE")"
fi
[[ "$ROOT_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Необходим подготовленный корневой открытый ключ Ed25519 (64 шестнадцатеричных символа)" >&2; exit 2; }
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
      -o "$OUT/$name" ./cmd/prestarter
  done
)
echo "Native Prestarter binaries: $OUT"
