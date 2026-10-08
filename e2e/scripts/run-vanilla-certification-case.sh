#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-vanilla-certification}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
MAX_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-30}"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[vanilla-cert] invalid Minecraft version" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[vanilla-cert] invalid Java major" >&2; exit 2; }
case "$TARGET_OS" in linux|windows|macos) ;; *) echo "[vanilla-cert] invalid target OS: $TARGET_OS" >&2; exit 2 ;; esac
case "$TARGET_ARCH" in x86_64|aarch64) ;; *) echo "[vanilla-cert] invalid target arch: $TARGET_ARCH" >&2; exit 2 ;; esac
[[ -n "$JAVA_BIN" && -f "$JAVA_BIN" ]] || { echo "[vanilla-cert] target Java executable is unavailable: $JAVA_BIN" >&2; exit 2; }
for cmd in go cargo python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[vanilla-cert] required command missing: $cmd" >&2; exit 1; }
done
if [[ "$TARGET_OS" == "linux" ]]; then
  command -v xvfb-run >/dev/null 2>&1 || { echo "[vanilla-cert] required command missing: xvfb-run" >&2; exit 1; }
fi

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/materialized-client"

EXE_SUFFIX=""
[[ "$TARGET_OS" == "windows" ]] && EXE_SUFFIX=".exe"
NL_BIN="$RUNTIME_DIR/nl$EXE_SUFFIX"
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime$EXE_SUFFIX"

printf '[vanilla-cert] build CLI and NeverRuntime for %s/%s\n' "$TARGET_OS" "$TARGET_ARCH"
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
[[ -f "$NEVERRUNTIME_BIN" ]] || { echo "[vanilla-cert] NeverRuntime binary is missing" >&2; exit 1; }

printf '[vanilla-cert] materialize Mojang Vanilla %s for %s/%s\n' "$MINECRAFT_VERSION" "$TARGET_OS" "$TARGET_ARCH"
"$NL_BIN" runtime vanilla-package \
  --minecraft "$MINECRAFT_VERSION" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --target "$TARGET_OS/$TARGET_ARCH" \
  --project compatibility-certification \
  --profile "vanilla-$MINECRAFT_VERSION-$TARGET_OS-$TARGET_ARCH" \
  --channel stable \
  --version "$PRODUCT_VERSION-vanilla-$MINECRAFT_VERSION-cert" \
  --output "$RUNTIME_DIR/client-package.json"

"$NL_BIN" client verify \
  --package "$RUNTIME_DIR/client-package.json" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"

cp "$RUNTIME_DIR/materialized-client/.neverlauncher/vanilla-install.json" "$RUNTIME_DIR/vanilla-install.json"
python3 - "$RUNTIME_DIR/vanilla-install.json" "$RUNTIME_DIR/materialized-client-verify.json" "$RUNTIME_DIR/client-package.json" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH" <<'PY'
import json, sys
install_p, verify_p, package_p, mc, java, os_name, arch = sys.argv[1:]
java = int(java)
install = json.load(open(install_p, encoding='utf-8'))
verify = json.load(open(verify_p, encoding='utf-8'))
package = json.load(open(package_p, encoding='utf-8'))
if not (install.get('minecraftVersion') == mc and install.get('javaMajorVersion') == java and install.get('status') == 'installed-and-verified' and len(install.get('files') or []) > 10):
    raise SystemExit('invalid vanilla-install evidence')
internal_os = 'osx' if os_name == 'macos' else os_name
if {'os': internal_os, 'arch': arch} not in (install.get('targets') or []):
    raise SystemExit(f'vanilla install target mismatch: expected {internal_os}/{arch}')
if not (verify.get('status') == 'valid' and (verify.get('verify') or {}).get('valid') is True and (verify.get('verify') or {}).get('missing') == [] and (verify.get('verify') or {}).get('corrupted') == []):
    raise SystemExit('invalid materialized package verification')
settings = package.get('manifestSettings') or {}
minecraft = settings.get('minecraft') or {}
runtime = settings.get('runtime') or {}
if not (minecraft.get('version') == mc and minecraft.get('loader') == 'vanilla' and (runtime.get('java') or {}).get('majorVersion') == java and (runtime.get('launch') or {}).get('classpathStrategy') == 'compatibility'):
    raise SystemExit('invalid client package runtime settings')
PY

printf '[vanilla-cert] launch actual Mojang client with Java %s on %s/%s\n' "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH"
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
if [[ "$TARGET_OS" == "linux" ]]; then
  export LIBGL_ALWAYS_SOFTWARE=1
  xvfb-run -a -s '-screen 0 1280x720x24' \
    "$NEVERRUNTIME_BIN" certify-vanilla \
      --root "$RUNTIME_DIR/materialized-client" \
      --version "$MINECRAFT_VERSION" \
      --java "$JAVA_BIN" \
      --required-java-major "$JAVA_MAJOR" \
      --max-runtime-seconds "$MAX_RUNTIME_SECONDS" \
      > "$RUNTIME_DIR/vanilla-certification.json"
else
  "$NEVERRUNTIME_BIN" certify-vanilla \
    --root "$RUNTIME_DIR/materialized-client" \
    --version "$MINECRAFT_VERSION" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --max-runtime-seconds "$MAX_RUNTIME_SECONDS" \
    > "$RUNTIME_DIR/vanilla-certification.json"
fi

python3 - "$RUNTIME_DIR/vanilla-certification.json" "$MINECRAFT_VERSION" "$JAVA_MAJOR" <<'PY'
import json, sys
p=json.load(open(sys.argv[1], encoding='utf-8'))
mc=sys.argv[2]; java=int(sys.argv[3])
if not (p.get('status') == 'passed' and p.get('minecraftVersion') == mc and p.get('requiredJavaMajor') == java and p.get('detectedJavaMajor') == java and (p.get('timedOut') is True or p.get('success') is True) and int(p.get('classpathEntries') or 0) > 0):
    raise SystemExit('actual client certification failed')
PY

python3 - "$RUNTIME_DIR/result.json" "$RUNTIME_DIR/vanilla-certification.json" "$PRODUCT_VERSION" "$TARGET_ID" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH" <<'PY'
import json, sys
out, cert_p, version, target, mc, java, os_name, arch = sys.argv[1:]
java=int(java)
cert=json.load(open(cert_p, encoding='utf-8'))
payload={
  'version': version, 'status':'passed', 'targetId':target,
  'minecraft':{'version':mc,'loader':'vanilla','client':'actual-mojang-client'},
  'platform':{'os':os_name,'arch':arch},
  'java':{'requiredMajor':java,'detectedMajor':cert.get('detectedJavaMajor')},
  'checks':{'materialized':True,'packageVerified':True,'runtimeResolved':True,'javaMatched':True,'actualClient':True},
  'runtimeSeconds':cert.get('runtimeSeconds'),
  'evidence':['client-package.json','materialized-client-verify.json','vanilla-install.json','vanilla-certification.json']
}
open(out,'w',encoding='utf-8').write(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
PY

printf '[vanilla-cert] PASS %s / Java %s / %s/%s\n' "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH"
