#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
LOADER_SELECTOR="${NEVERLAUNCHER_E2E_LOADER_VERSION:-latest-stable}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-fabric-certification}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
MAX_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-30}"
source "$ROOT/e2e/scripts/lib/certification-platform.sh"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[fabric-cert] invalid Minecraft version" >&2; exit 2; }
[[ "$LOADER_SELECTOR" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[fabric-cert] invalid Fabric loader selector" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[fabric-cert] invalid Java major" >&2; exit 2; }
certification_platform_validate "fabric-cert" "$TARGET_OS" "$TARGET_ARCH" "$JAVA_BIN"

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/materialized-client"

EXE_SUFFIX="$(certification_exe_suffix "$TARGET_OS")"
NL_BIN="$RUNTIME_DIR/nl$EXE_SUFFIX"
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime$EXE_SUFFIX"

printf '[fabric-cert] build CLI and NeverRuntime\n'
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
[[ -f "$NEVERRUNTIME_BIN" ]] || { echo "[fabric-cert] NeverRuntime binary is missing" >&2; exit 1; }

printf '[fabric-cert] materialize Fabric %s / %s\n' "$MINECRAFT_VERSION" "$LOADER_SELECTOR"
materialize_loader_package() {
  "$NL_BIN" runtime fabric-package \
    --minecraft "$MINECRAFT_VERSION" \
    --loader-version "$LOADER_SELECTOR" \
    --client-dir "$RUNTIME_DIR/materialized-client" \
    --resolution-lock "$RUNTIME_DIR/materialized-client/.neverlauncher/fabric-resolution-lock.json" \
    --target "$TARGET_OS/$TARGET_ARCH" \
    --project compatibility-certification \
    --profile "fabric-$MINECRAFT_VERSION-$TARGET_OS-$TARGET_ARCH" \
    --channel stable \
    --version "$PRODUCT_VERSION-fabric-$MINECRAFT_VERSION-cert" \
    --output "$RUNTIME_DIR/client-package.json"
}

materialize_loader_package
FIRST_REPRODUCIBILITY_SHA256="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1],encoding="utf-8")).get("fabric") or {}).get("reproducibilitySha256") or "")' "$RUNTIME_DIR/client-package.json")"
FIRST_LOCK_SHA256="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1],encoding="utf-8")).get("fabric") or {}).get("resolutionLockSha256") or "")' "$RUNTIME_DIR/client-package.json")"
# Replay the same mutable selector through the generated lock. This must not re-resolve latest-stable.
materialize_loader_package
cp "$RUNTIME_DIR/materialized-client/.neverlauncher/fabric-resolution-lock.json" "$RUNTIME_DIR/fabric-resolution-lock.json"

python3 - "$RUNTIME_DIR/client-package.json" "$RUNTIME_DIR/fabric-resolution-lock.json" "$FIRST_REPRODUCIBILITY_SHA256" "$FIRST_LOCK_SHA256" <<'PY'
import hashlib, json, re, sys
package_p, lock_p, first_repro, first_lock = sys.argv[1:]
package = json.load(open(package_p, encoding="utf-8"))
install = package.get("fabric") or {}
raw = open(lock_p, "rb").read()
lock = json.loads(raw.decode("utf-8"))
lock_sha = hashlib.sha256(raw).hexdigest()
for key in ("resolutionLockSha256", "resolutionSourceSha256", "reproducibilitySha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", str(install.get(key) or "")):
        raise SystemExit(f"invalid loader pin {key}")
if install.get("resolutionPinned") is not True:
    raise SystemExit("second materialization did not reuse loader resolution lock")
if lock_sha != install.get("resolutionLockSha256") or lock_sha != first_lock:
    raise SystemExit("loader resolution lock SHA-256 changed between materializations")
if install.get("reproducibilitySha256") != first_repro or lock.get("reproducibilitySha256") != first_repro:
    raise SystemExit("loader reproducibility identity changed between materializations")
if lock.get("resolvedVersion") != install.get("loaderVersion"):
    raise SystemExit("loader lock resolvedVersion mismatch")
if lock.get("selector") in ("", None) or lock.get("resolvedVersion") in ("latest", "latest-stable", "stable", "recommended"):
    raise SystemExit("loader lock is not immutable")
PY

bash "$ROOT/e2e/scripts/run-loader-hardening-probe.sh" "fabric" "$NL_BIN" "$RUNTIME_DIR"

"$NL_BIN" client verify \
  --package "$RUNTIME_DIR/client-package.json" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"

python3 - "$RUNTIME_DIR/client-package.json" "$RUNTIME_DIR/materialized-client-verify.json" "$RUNTIME_DIR/fabric-install.json" "$MINECRAFT_VERSION" "$JAVA_MAJOR" <<'PY'
import json, sys
package_p, verify_p, install_p, mc, java = sys.argv[1:]
java = int(java)
package = json.load(open(package_p, encoding='utf-8'))
verify = json.load(open(verify_p, encoding='utf-8'))
install = package.get('fabric') or {}
settings = package.get('manifestSettings') or {}
minecraft = settings.get('minecraft') or {}
runtime = settings.get('runtime') or {}
if not (install.get('status') == 'installed-and-verified' and install.get('minecraftVersion') == mc and install.get('javaMajorVersion') == java):
    raise SystemExit('invalid Fabric materialization evidence')
if not (install.get('loaderVersion') and install.get('profileId') and install.get('mainClass') and int(install.get('libraryCount') or 0) > 0):
    raise SystemExit('Fabric profile was not fully materialized')
if not (verify.get('status') == 'valid' and (verify.get('verify') or {}).get('valid') is True and (verify.get('verify') or {}).get('missing') == [] and (verify.get('verify') or {}).get('corrupted') == []):
    raise SystemExit('invalid materialized package verification')
if not (minecraft.get('version') == mc and minecraft.get('loader') == 'fabric' and minecraft.get('loaderVersion') == install.get('loaderVersion') and minecraft.get('mainClass') == install.get('mainClass')):
    raise SystemExit('Fabric package metadata mismatch')
if not ((runtime.get('java') or {}).get('majorVersion') == java and (runtime.get('launch') or {}).get('classpathStrategy') == 'compatibility' and (runtime.get('launch') or {}).get('versionMetadataPath') == install.get('profilePath')):
    raise SystemExit('Fabric package runtime settings mismatch')
open(install_p, 'w', encoding='utf-8').write(json.dumps(install, indent=2, ensure_ascii=False) + '\n')
print(install['profileId'])
PY

PROFILE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["profileId"])' "$RUNTIME_DIR/fabric-install.json")"
RESOLVED_LOADER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["loaderVersion"])' "$RUNTIME_DIR/fabric-install.json")"
MAIN_CLASS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["mainClass"])' "$RUNTIME_DIR/fabric-install.json")"

[[ -n "$PROFILE_ID" && -n "$RESOLVED_LOADER" && -n "$MAIN_CLASS" ]] || { echo "[fabric-cert] incomplete Fabric profile evidence" >&2; exit 1; }
case "$RESOLVED_LOADER" in latest|latest-stable|stable|recommended) echo "[fabric-cert] mutable loader selector leaked into resolved version" >&2; exit 1 ;; esac

printf '[fabric-cert] launch actual Fabric client profile %s with Java %s\n' "$PROFILE_ID" "$JAVA_MAJOR"
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
certification_run_client "$TARGET_OS" "$NEVERRUNTIME_BIN" "$RUNTIME_DIR/fabric-certification.json" \
  certify-vanilla \
    --root "$RUNTIME_DIR/materialized-client" \
    --version "$PROFILE_ID" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --max-runtime-seconds "$MAX_RUNTIME_SECONDS"

python3 - "$RUNTIME_DIR/fabric-certification.json" "$RUNTIME_DIR/fabric-install.json" "$PROFILE_ID" "$JAVA_MAJOR" <<'PY'
import json, sys
cert_p, install_p, profile, java = sys.argv[1:]
java = int(java)
cert = json.load(open(cert_p, encoding='utf-8'))
install = json.load(open(install_p, encoding='utf-8'))
if not (cert.get('status') == 'passed' and cert.get('minecraftVersion') == profile and cert.get('requiredJavaMajor') == java and cert.get('detectedJavaMajor') == java):
    raise SystemExit('actual Fabric client certification failed')
if not ((cert.get('timedOut') is True or cert.get('success') is True) and int(cert.get('classpathEntries') or 0) > 0):
    raise SystemExit('Fabric client did not stay alive or exit successfully')
if cert.get('mainClass') != install.get('mainClass'):
    raise SystemExit('Fabric launch mainClass mismatch')
PY

python3 "$ROOT/scripts/compatibility/verify-loader-platform.py" \
  --install "$RUNTIME_DIR/fabric-install.json" \
  --certification "$RUNTIME_DIR/fabric-certification.json" \
  --loader "fabric" \
  --os "$TARGET_OS" \
  --arch "$TARGET_ARCH" \
  --output "$RUNTIME_DIR/loader-platform.json"

python3 - "$RUNTIME_DIR/result.json" "$RUNTIME_DIR/fabric-certification.json" "$PRODUCT_VERSION" "$TARGET_ID" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH" "$RESOLVED_LOADER" "$PROFILE_ID" <<'PY'
import json, sys
out, cert_p, version, target, mc, java, os_name, arch, loader_version, profile = sys.argv[1:]
java = int(java)
cert = json.load(open(cert_p, encoding='utf-8'))
payload = {
  'version': version, 'status': 'passed', 'targetId': target,
  'minecraft': {'version': mc, 'loader': 'fabric', 'resolvedLoaderVersion': loader_version, 'profileId': profile, 'client': 'actual-mojang-client'},
  'platform': {'os': os_name, 'arch': arch},
  'java': {'requiredMajor': java, 'detectedMajor': cert.get('detectedJavaMajor')},
  'checks': {'materialized': True, 'packageVerified': True, 'runtimeResolved': True, 'javaMatched': True, 'actualClient': True},
  'runtimeSeconds': cert.get('runtimeSeconds'),
  'evidence': ['client-package.json', 'materialized-client-verify.json', 'fabric-install.json', 'fabric-certification.json', 'fabric-resolution-lock.json', 'loader-platform.json']
}
open(out, 'w', encoding='utf-8').write(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
PY

printf '[fabric-cert] PASS Fabric %s / loader %s / Java %s\n' "$MINECRAFT_VERSION" "$RESOLVED_LOADER" "$JAVA_MAJOR"
