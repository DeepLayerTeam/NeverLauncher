#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
LOADER_SELECTOR="${NEVERLAUNCHER_E2E_LOADER_VERSION:-latest-stable}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-forge-certification}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
MAX_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-30}"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[forge-cert] invalid Minecraft version" >&2; exit 2; }
[[ "$LOADER_SELECTOR" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[forge-cert] invalid Forge loader selector" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[forge-cert] invalid Java major" >&2; exit 2; }
[[ "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ]] || { echo "[forge-cert] 0.17.3 certification requires linux/x86_64" >&2; exit 2; }
[[ -n "$JAVA_BIN" && -f "$JAVA_BIN" ]] || { echo "[forge-cert] target Java executable is unavailable: $JAVA_BIN" >&2; exit 2; }
for cmd in go cargo python3 xvfb-run; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[forge-cert] required command missing: $cmd" >&2; exit 1; }
done

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/materialized-client"

NL_BIN="$RUNTIME_DIR/nl"
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime"

printf '[forge-cert] build CLI and NeverRuntime\n'
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
[[ -f "$NEVERRUNTIME_BIN" ]] || { echo "[forge-cert] NeverRuntime binary is missing" >&2; exit 1; }

printf '[forge-cert] materialize Forge %s / %s\n' "$MINECRAFT_VERSION" "$LOADER_SELECTOR"
"$NL_BIN" runtime forge-package \
  --minecraft "$MINECRAFT_VERSION" \
  --loader-version "$LOADER_SELECTOR" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --java "$JAVA_BIN" \
  --target "$TARGET_OS/$TARGET_ARCH" \
  --project compatibility-certification \
  --profile "forge-$MINECRAFT_VERSION-$TARGET_OS-$TARGET_ARCH" \
  --channel stable \
  --version "$PRODUCT_VERSION-forge-$MINECRAFT_VERSION-cert" \
  --output "$RUNTIME_DIR/client-package.json"

"$NL_BIN" client verify \
  --package "$RUNTIME_DIR/client-package.json" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"

python3 - "$RUNTIME_DIR/client-package.json" "$RUNTIME_DIR/materialized-client-verify.json" "$RUNTIME_DIR/forge-install.json" "$MINECRAFT_VERSION" "$JAVA_MAJOR" <<'PY'
import json, re, sys
package_p, verify_p, install_p, mc, java = sys.argv[1:]
java = int(java)
package = json.load(open(package_p, encoding='utf-8'))
verify = json.load(open(verify_p, encoding='utf-8'))
install = package.get('forge') or {}
settings = package.get('manifestSettings') or {}
minecraft = settings.get('minecraft') or {}
runtime = settings.get('runtime') or {}
if not (install.get('status') == 'installed-and-verified' and install.get('loader') == 'forge' and install.get('minecraftVersion') == mc and install.get('javaMajorVersion') == java):
    raise SystemExit('invalid Forge materialization evidence')
if not (install.get('loaderVersion') and install.get('artifactVersion') and install.get('profileId') and install.get('profilePath') and install.get('mainClass')):
    raise SystemExit('Forge profile was not fully materialized')
client_processors = int(install.get('clientProcessorCount') or 0)
ran = int(install.get('processorRan') or 0)
skipped = int(install.get('processorSkipped') or 0)
mode = str(install.get('installMode') or '')
if mc == '1.12.2':
    if mode not in ('legacy-v1-universal', 'legacy-v2-empty-processors'):
        raise SystemExit(f'Forge 1.12.2 did not use a legacy universal installer path: {mode!r}')
    if client_processors != 0 or ran != 0 or skipped != 0:
        raise SystemExit('Forge 1.12.2 legacy installer unexpectedly reported processors')
    if not str(install.get('legacyUniversalPath') or '').startswith('libraries/net/minecraftforge/forge/'):
        raise SystemExit('Forge 1.12.2 universal JAR was not materialized under libraries/')
    if not re.fullmatch(r'[0-9a-f]{40}', str(install.get('legacyUniversalSha1') or '')):
        raise SystemExit('invalid Forge 1.12.2 universal SHA-1')
    if not re.fullmatch(r'[0-9a-f]{64}', str(install.get('legacyUniversalSha256') or '')):
        raise SystemExit('invalid Forge 1.12.2 universal SHA-256')
    if install.get('mainClass') != 'net.minecraft.launchwrapper.Launch':
        raise SystemExit('Forge 1.12.2 legacy mainClass mismatch')
else:
    if mode != 'processors':
        raise SystemExit(f'Forge modern target did not use processor mode: {mode!r}')
    if client_processors <= 0 or ran + skipped != client_processors:
        raise SystemExit(f'Forge processor execution evidence is incomplete: client={client_processors} ran={ran} skipped={skipped}')
for key in ('installerSha256', 'profileSha256'):
    if not re.fullmatch(r'[0-9a-f]{64}', str(install.get(key) or '')):
        raise SystemExit(f'invalid Forge {key}')
if int(install.get('libraryCount') or 0) <= 0:
    raise SystemExit('Forge runtime libraries were not materialized')
if not (verify.get('status') == 'valid' and (verify.get('verify') or {}).get('valid') is True and (verify.get('verify') or {}).get('missing') == [] and (verify.get('verify') or {}).get('corrupted') == []):
    raise SystemExit('invalid materialized package verification')
if not (minecraft.get('version') == mc and minecraft.get('loader') == 'forge' and minecraft.get('loaderVersion') == install.get('loaderVersion') and minecraft.get('mainClass') == install.get('mainClass')):
    raise SystemExit('Forge package metadata mismatch')
if not ((runtime.get('java') or {}).get('majorVersion') == java and (runtime.get('launch') or {}).get('classpathStrategy') == 'compatibility' and (runtime.get('launch') or {}).get('versionMetadataPath') == install.get('profilePath')):
    raise SystemExit('Forge package runtime settings mismatch')
open(install_p, 'w', encoding='utf-8').write(json.dumps(install, indent=2, ensure_ascii=False) + '\n')
print(install['profileId'])
PY

PROFILE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["profileId"])' "$RUNTIME_DIR/forge-install.json")"
RESOLVED_LOADER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["loaderVersion"])' "$RUNTIME_DIR/forge-install.json")"
MAIN_CLASS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["mainClass"])' "$RUNTIME_DIR/forge-install.json")"

[[ -n "$PROFILE_ID" && -n "$RESOLVED_LOADER" && -n "$MAIN_CLASS" ]] || { echo "[forge-cert] incomplete Forge profile evidence" >&2; exit 1; }
case "$RESOLVED_LOADER" in latest|latest-stable|stable|recommended) echo "[forge-cert] mutable loader selector leaked into resolved version" >&2; exit 1 ;; esac

printf '[forge-cert] launch actual Forge client profile %s with Java %s\n' "$PROFILE_ID" "$JAVA_MAJOR"
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
export LIBGL_ALWAYS_SOFTWARE=1
xvfb-run -a -s '-screen 0 1280x720x24' \
  "$NEVERRUNTIME_BIN" certify-vanilla \
    --root "$RUNTIME_DIR/materialized-client" \
    --version "$PROFILE_ID" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --max-runtime-seconds "$MAX_RUNTIME_SECONDS" \
    > "$RUNTIME_DIR/forge-certification.json"

python3 - "$RUNTIME_DIR/forge-certification.json" "$RUNTIME_DIR/forge-install.json" "$PROFILE_ID" "$JAVA_MAJOR" <<'PY'
import json, sys
cert_p, install_p, profile, java = sys.argv[1:]
java = int(java)
cert = json.load(open(cert_p, encoding='utf-8'))
install = json.load(open(install_p, encoding='utf-8'))
if not (cert.get('status') == 'passed' and cert.get('minecraftVersion') == profile and cert.get('requiredJavaMajor') == java and cert.get('detectedJavaMajor') == java):
    raise SystemExit('actual Forge client certification failed')
if not ((cert.get('timedOut') is True or cert.get('success') is True) and int(cert.get('classpathEntries') or 0) > 0):
    raise SystemExit('Forge client did not stay alive or exit successfully')
if cert.get('mainClass') != install.get('mainClass'):
    raise SystemExit('Forge launch mainClass mismatch')
PY

python3 - "$RUNTIME_DIR/result.json" "$RUNTIME_DIR/forge-certification.json" "$PRODUCT_VERSION" "$TARGET_ID" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH" "$RESOLVED_LOADER" "$PROFILE_ID" <<'PY'
import json, sys
out, cert_p, version, target, mc, java, os_name, arch, loader_version, profile = sys.argv[1:]
java = int(java)
cert = json.load(open(cert_p, encoding='utf-8'))
payload = {
  'version': version, 'status': 'passed', 'targetId': target,
  'minecraft': {'version': mc, 'loader': 'forge', 'resolvedLoaderVersion': loader_version, 'profileId': profile, 'client': 'actual-mojang-client'},
  'platform': {'os': os_name, 'arch': arch},
  'java': {'requiredMajor': java, 'detectedMajor': cert.get('detectedJavaMajor')},
  'checks': {'materialized': True, 'packageVerified': True, 'runtimeResolved': True, 'javaMatched': True, 'actualClient': True},
  'runtimeSeconds': cert.get('runtimeSeconds'),
  'evidence': ['client-package.json', 'materialized-client-verify.json', 'forge-install.json', 'forge-certification.json']
}
open(out, 'w', encoding='utf-8').write(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
PY

printf '[forge-cert] PASS Forge %s / loader %s / Java %s\n' "$MINECRAFT_VERSION" "$RESOLVED_LOADER" "$JAVA_MAJOR"
