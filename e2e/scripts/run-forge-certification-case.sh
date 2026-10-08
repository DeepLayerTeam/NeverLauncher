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
source "$ROOT/e2e/scripts/lib/certification-platform.sh"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[forge-cert] invalid Minecraft version" >&2; exit 2; }
[[ "$LOADER_SELECTOR" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[forge-cert] invalid Forge loader selector" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[forge-cert] invalid Java major" >&2; exit 2; }
certification_platform_validate "forge-cert" "$TARGET_OS" "$TARGET_ARCH" "$JAVA_BIN"

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/materialized-client"

EXE_SUFFIX="$(certification_exe_suffix "$TARGET_OS")"
NL_BIN="$RUNTIME_DIR/nl$EXE_SUFFIX"
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime$EXE_SUFFIX"

printf '[Forge-cert] сборка CLI и NeverRuntime\n'
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
[[ -f "$NEVERRUNTIME_BIN" ]] || { echo "[forge-cert] NeverRuntime binary is missing" >&2; exit 1; }

printf '[Forge-cert] материализовать Forge %s / %s\n' "$MINECRAFT_VERSION" "$LOADER_SELECTOR"
materialize_loader_package() {
  "$NL_BIN" runtime forge-package \
    --minecraft "$MINECRAFT_VERSION" \
    --loader-version "$LOADER_SELECTOR" \
    --client-dir "$RUNTIME_DIR/materialized-client" \
    --resolution-lock "$RUNTIME_DIR/materialized-client/.neverlauncher/forge-resolution-lock.json" \
    --java "$JAVA_BIN" \
    --target "$TARGET_OS/$TARGET_ARCH" \
    --project compatibility-certification \
    --profile "forge-$MINECRAFT_VERSION-$TARGET_OS-$TARGET_ARCH" \
    --channel stable \
    --version "$PRODUCT_VERSION-forge-$MINECRAFT_VERSION-cert" \
    --output "$RUNTIME_DIR/client-package.json"
}

materialize_loader_package
FIRST_REPRODUCIBILITY_SHA256="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1],encoding="utf-8")).get("forge") or {}).get("reproducibilitySha256") or "")' "$RUNTIME_DIR/client-package.json")"
FIRST_LOCK_SHA256="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1],encoding="utf-8")).get("forge") or {}).get("resolutionLockSha256") or "")' "$RUNTIME_DIR/client-package.json")"
# Повторное воспроизведение одинаковый изменяемый селектор через сгенерированный блокировка. Этот должен не re-разрешать последний-стабильный.
materialize_loader_package
cp "$RUNTIME_DIR/materialized-client/.neverlauncher/forge-resolution-lock.json" "$RUNTIME_DIR/forge-resolution-lock.json"

python3 - "$RUNTIME_DIR/client-package.json" "$RUNTIME_DIR/forge-resolution-lock.json" "$FIRST_REPRODUCIBILITY_SHA256" "$FIRST_LOCK_SHA256" <<'PY'
import hashlib, json, re, sys
package_p, lock_p, first_repro, first_lock = sys.argv[1:]
package = json.load(open(package_p, encoding="utf-8"))
install = package.get("forge") or {}
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

bash "$ROOT/e2e/scripts/run-loader-hardening-probe.sh" "forge" "$NL_BIN" "$RUNTIME_DIR"

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
if mc in ('1.7.10', '1.12.2'):
    allowed_modes = ('legacy-v1-universal',) if mc == '1.7.10' else ('legacy-v1-universal', 'legacy-v2-empty-processors')
    if mode not in allowed_modes:
        raise SystemExit(f'Forge {mc} did not use the required legacy universal installer path: {mode!r}')
    if client_processors != 0 or ran != 0 or skipped != 0:
        raise SystemExit(f'Forge {mc} legacy installer unexpectedly reported processors')
    if not str(install.get('legacyUniversalPath') or '').startswith('libraries/net/minecraftforge/forge/'):
        raise SystemExit(f'Forge {mc} universal JAR was not materialized under libraries/')
    if not re.fullmatch(r'[0-9a-f]{40}', str(install.get('legacyUniversalSha1') or '')):
        raise SystemExit(f'invalid Forge {mc} universal SHA-1')
    if not re.fullmatch(r'[0-9a-f]{64}', str(install.get('legacyUniversalSha256') or '')):
        raise SystemExit(f'invalid Forge {mc} universal SHA-256')
    if install.get('mainClass') != 'net.minecraft.launchwrapper.Launch':
        raise SystemExit(f'Forge {mc} legacy mainClass mismatch')
    expected_tweaker = 'cpw.mods.fml.common.launcher.FMLTweaker' if mc == '1.7.10' else 'net.minecraftforge.fml.common.launcher.FMLTweaker'
    if install.get('legacyTweaker') != expected_tweaker or install.get('legacyBaseVersion') != mc:
        raise SystemExit(f'Forge {mc} legacy LaunchWrapper/FML evidence mismatch')
    if mc == '1.7.10' and install.get('legacyProfileNormalized') is not True:
        raise SystemExit('Forge 1.7.10 V1 profile was not normalized to inherit Vanilla 1.7.10')
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

printf '[Forge-cert] запускать фактический Forge клиент профиль %s с Java %s\n' "$PROFILE_ID" "$JAVA_MAJOR"
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
certification_run_client "$TARGET_OS" "$NEVERRUNTIME_BIN" "$RUNTIME_DIR/forge-certification.json" \
  certify-vanilla \
    --root "$RUNTIME_DIR/materialized-client" \
    --version "$PROFILE_ID" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --max-runtime-seconds "$MAX_RUNTIME_SECONDS"

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

python3 "$ROOT/scripts/compatibility/verify-loader-platform.py" \
  --install "$RUNTIME_DIR/forge-install.json" \
  --certification "$RUNTIME_DIR/forge-certification.json" \
  --loader "forge" \
  --os "$TARGET_OS" \
  --arch "$TARGET_ARCH" \
  --output "$RUNTIME_DIR/loader-platform.json"

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
  'evidence': ['client-package.json', 'materialized-client-verify.json', 'forge-install.json', 'forge-certification.json', 'forge-resolution-lock.json', 'loader-platform.json']
}
open(out, 'w', encoding='utf-8').write(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
PY

printf '[Forge-cert] PASS Forge %s / загрузчик %s / Java %s\n' "$MINECRAFT_VERSION" "$RESOLVED_LOADER" "$JAVA_MAJOR"
