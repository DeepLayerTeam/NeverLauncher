#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-vanilla-certification}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
MAX_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-30}"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[vanilla-cert] invalid Minecraft version" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[vanilla-cert] invalid Java major" >&2; exit 2; }
[[ -n "$JAVA_BIN" && -x "$JAVA_BIN" ]] || { echo "[vanilla-cert] target Java executable is unavailable: $JAVA_BIN" >&2; exit 2; }
for cmd in go cargo jq xvfb-run; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[vanilla-cert] required command missing: $cmd" >&2; exit 1; }
done

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/materialized-client"

printf '[vanilla-cert] build CLI and NeverRuntime\n'
(
  cd "$ROOT/cli"
  go build -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime"
[[ -x "$NEVERRUNTIME_BIN" ]] || { echo "[vanilla-cert] NeverRuntime binary is missing" >&2; exit 1; }

printf '[vanilla-cert] materialize Mojang Vanilla %s with verified upstream hashes\n' "$MINECRAFT_VERSION"
"$RUNTIME_DIR/nl" runtime vanilla-package \
  --minecraft "$MINECRAFT_VERSION" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --project compatibility-certification \
  --profile "vanilla-$MINECRAFT_VERSION" \
  --channel stable \
  --version "$PRODUCT_VERSION-vanilla-$MINECRAFT_VERSION-cert" \
  --output "$RUNTIME_DIR/client-package.json"

"$RUNTIME_DIR/nl" client verify \
  --package "$RUNTIME_DIR/client-package.json" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"

cp "$RUNTIME_DIR/materialized-client/.neverlauncher/vanilla-install.json" "$RUNTIME_DIR/vanilla-install.json"
jq -e --arg mc "$MINECRAFT_VERSION" --argjson java "$JAVA_MAJOR" \
  '.minecraftVersion == $mc and .javaMajorVersion == $java and .status == "installed-and-verified" and (.files | length) > 10' \
  "$RUNTIME_DIR/vanilla-install.json" >/dev/null
jq -e --arg mc "$MINECRAFT_VERSION" --argjson java "$JAVA_MAJOR" \
  '.status == "valid" and .verify.valid == true and .verify.missing == [] and .verify.corrupted == []' \
  "$RUNTIME_DIR/materialized-client-verify.json" >/dev/null
jq -e --arg mc "$MINECRAFT_VERSION" --argjson java "$JAVA_MAJOR" \
  '.manifestSettings.minecraft.version == $mc and .manifestSettings.minecraft.loader == "vanilla" and .manifestSettings.runtime.java.majorVersion == $java and .manifestSettings.runtime.launch.classpathStrategy == "compatibility"' \
  "$RUNTIME_DIR/client-package.json" >/dev/null

printf '[vanilla-cert] launch actual Mojang client with exact Java %s under Xvfb\n' "$JAVA_MAJOR"
(
  cd "$ROOT"
  export LIBGL_ALWAYS_SOFTWARE=1
  export NEVERLAUNCHER_RESOLUTION_WIDTH=854
  export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
  xvfb-run -a -s '-screen 0 1280x720x24' \
    "$NEVERRUNTIME_BIN" certify-vanilla \
      --root "$RUNTIME_DIR/materialized-client" \
      --version "$MINECRAFT_VERSION" \
      --java "$JAVA_BIN" \
      --required-java-major "$JAVA_MAJOR" \
      --max-runtime-seconds "$MAX_RUNTIME_SECONDS" \
      > "$RUNTIME_DIR/vanilla-certification.json"
)

jq -e --arg mc "$MINECRAFT_VERSION" --argjson java "$JAVA_MAJOR" \
  '.status == "passed" and .minecraftVersion == $mc and .requiredJavaMajor == $java and .detectedJavaMajor == $java and (.timedOut == true or .success == true) and .classpathEntries > 0' \
  "$RUNTIME_DIR/vanilla-certification.json" >/dev/null

jq -n \
  --arg version "$PRODUCT_VERSION" \
  --arg target "$TARGET_ID" \
  --arg minecraft "$MINECRAFT_VERSION" \
  --argjson javaMajor "$JAVA_MAJOR" \
  --argjson runtimeSeconds "$(jq -r '.runtimeSeconds' "$RUNTIME_DIR/vanilla-certification.json")" \
  '{version:$version,status:"passed",targetId:$target,minecraft:{version:$minecraft,loader:"vanilla",client:"actual-mojang-client"},java:{requiredMajor:$javaMajor,detectedMajor:$javaMajor},checks:{materialized:true,packageVerified:true,runtimeResolved:true,javaMatched:true,actualClient:true},runtimeSeconds:$runtimeSeconds,evidence:["client-package.json","materialized-client-verify.json","vanilla-install.json","vanilla-certification.json"]}' \
  > "$RUNTIME_DIR/result.json"

printf '[vanilla-cert] PASS %s / Java %s\n' "$MINECRAFT_VERSION" "$JAVA_MAJOR"
