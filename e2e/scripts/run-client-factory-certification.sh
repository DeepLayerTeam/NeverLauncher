#!/usr/bin/env bash
# Performs actual Minecraft JVM launch via Runtime on a verified Client Factory build.
# This is NOT a fixture-only check; missing Java, graphics, Minecraft or network fails closed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="${LAUNCHER_CERT_LOADER:?set LAUNCHER_CERT_LOADER}"
MC="${LAUNCHER_CERT_MINECRAFT:?set LAUNCHER_CERT_MINECRAFT}"
JAVA="${LAUNCHER_CERT_JAVA:?set LAUNCHER_CERT_JAVA}"
TARGET="${LAUNCHER_CERT_TARGET:-linux/x86_64}"
LOADER_VERSION="${LAUNCHER_CERT_LOADER_VERSION:-latest-stable}"
DEST="${LAUNCHER_CERT_OUTPUT:-$ROOT/e2e/client-factory-02712-result}"
DURATION="${LAUNCHER_CERT_RUNTIME_SECONDS:-45}"
case "$LOADER" in vanilla|fabric|quilt|forge|neoforge) ;; *) echo "Unsupported loader" >&2; exit 2;; esac
[[ "$MC" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,95}$ ]] || { echo "Invalid version" >&2; exit 2; }
[[ "$DURATION" =~ ^[0-9]+$ ]] || { echo "Invalid duration" >&2; exit 2; }
[[ "$TARGET" =~ ^(linux|windows|osx|macos)/(x86|x86_64|aarch64)$ ]] || { echo "Invalid target" >&2; exit 2; }
[[ -f "$JAVA" ]] || { echo "Java executable not found: $JAVA" >&2; exit 2; }
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd -P)"
BIN="$DEST/launcher"
RT="${LAUNCHER_CERT_RUNTIME_BIN:-$ROOT/runtime/runtime/target/debug/runtime}"
(
 cd "$ROOT/cli"
 go build -o "$BIN" ./cmd/launcher
)
if [[ ! -f "$RT" ]]; then
 cargo build --quiet --manifest-path "$ROOT/runtime/runtime/Cargo.toml" --bin runtime
fi
[[ -f "$RT" ]] || { echo "Runtime binary missing" >&2; exit 2; }
# Runtime itself is pinned before the test; Go checks its hash before and after execution.
RT_SHA="$(python3 - "$RT" <<'PY'
from pathlib import Path
import hashlib,sys
p=Path(sys.argv[1]);h=hashlib.sha256()
with p.open('rb') as stream:
    for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
print(h.hexdigest())
PY
)"
CLIENT="$DEST/client"
PROCESSOR_ARGS=()
if [[ "${LAUNCHER_CERT_PROCESSOR_SANDBOX:-process}" == required ]]; then PROCESSOR_ARGS=(--processor-sandbox required); fi
"$BIN" runtime client-factory build \
 --client-dir "$CLIENT" --loader "$LOADER" --minecraft "$MC" \
 --loader-version "$LOADER_VERSION" --target "$TARGET" --java "$JAVA" \
 --processor-timeout 10m "${PROCESSOR_ARGS[@]}" --output "$DEST/install-plan-result.json"
"$BIN" runtime client-factory verify --client-dir "$CLIENT" --output "$DEST/install-verified.json"
KEY="${LAUNCHER_CERT_SIGNING_KEY:-$DEST/ci-only-private.key}"; PUB="${LAUNCHER_CERT_PUBLIC_KEY:-$DEST/certification.pub}"
if [[ ! -f "$KEY" ]]; then
 [[ -z "${LAUNCHER_CERT_SIGNING_KEY:-}" ]] || { echo "Protected signing key is missing" >&2; exit 2; }
 "$BIN" runtime client-factory certify-keygen --private-key "$KEY" --public-key "$PUB"
fi
CERT="$DEST/runtime-certificate.json"
CMD=("$BIN" runtime client-factory certify-run --client-dir "$CLIENT" --runtime "$RT" \
 --runtime-sha256 "$RT_SHA" --java "$JAVA" --private-key "$KEY" \
 --max-runtime-seconds "$DURATION" --output "$CERT")
if [[ "$(uname -s)" == Linux ]]; then
 command -v xvfb-run >/dev/null || { echo "xvfb-run unavailable" >&2; exit 2; }
 export LIBGL_ALWAYS_SOFTWARE=1
 xvfb-run -a -s '-screen 0 1280x720x24 +extension GLX +render -noreset' "${CMD[@]}" > "$DEST/run-result.json"
else
 "${CMD[@]}" > "$DEST/run-result.json"
fi
"$BIN" runtime client-factory certify-verify --client-dir "$CLIENT" --certificate "$CERT" --public-key "$PUB" --output "$DEST/certificate-verification.json"
# Never publish this ephemeral CI private key as a build artifact.
if [[ -z "${LAUNCHER_CERT_SIGNING_KEY:-}" && "${LAUNCHER_CERT_KEEP_TEST_KEY:-0}" != 1 ]]; then rm -f "$KEY"; fi
printf '[client-factory-certification] certified loader=%s mc=%s target=%s output=%s\n' "$LOADER" "$MC" "$TARGET" "$CERT"
