#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${NEVERLAUNCHER_COMPAT_RESULT_DIR:-$ROOT/e2e/compatibility-result}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-}"
MINECRAFT="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
LOADER="${NEVERLAUNCHER_E2E_LOADER:-}"
LOADER_SELECTOR="${NEVERLAUNCHER_E2E_LOADER_VERSION:-}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-x86_64}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
SCOPE="${NEVERLAUNCHER_COMPAT_SCOPE:-integration}"
MATCHING_SERVER="${NEVERLAUNCHER_COMPAT_MATCHING_SERVER:-false}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
COMMIT="${GITHUB_SHA:-local}"
RUN_ID="${GITHUB_RUN_ID:-local}"

mkdir -p "$OUT_DIR"
RESULT="$OUT_DIR/compatibility-result.json"
JAVA_EVIDENCE="$OUT_DIR/java-runtime.json"
PLATFORM_EVIDENCE="$OUT_DIR/platform-runtime.json"

valid_id() { [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{2,95}$ ]]; }
valid_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]]; }

if ! valid_id "$TARGET_ID" || ! valid_version "$MINECRAFT"; then
  echo "[compat] invalid target metadata" >&2
  exit 2
fi
case "$LOADER" in vanilla|fabric|quilt|forge|neoforge) ;; *) echo "[compat] invalid loader" >&2; exit 2 ;; esac
case "$SCOPE" in client|integration) ;; *) echo "[compat] invalid certification scope" >&2; exit 2 ;; esac
case "$MATCHING_SERVER" in true|false) ;; *) echo "[compat] matchingServer must be true/false" >&2; exit 2 ;; esac
if [[ "$MATCHING_SERVER" == "true" && ! ( "$SCOPE" == "client" && "$LOADER" == "vanilla" && "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ) ]]; then
  echo "[compat] matchingServer requires Vanilla client scope on linux/x86_64" >&2
  exit 2
fi
case "$TARGET_OS" in linux|windows|macos) ;; *) echo "[compat] unsupported target OS" >&2; exit 2 ;; esac
case "$TARGET_ARCH" in x86_64|aarch64) ;; *) echo "[compat] unsupported target architecture" >&2; exit 2 ;; esac
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[compat] java major is required" >&2; exit 2; }
[[ -n "$JAVA_BIN" ]] || { echo "[compat] target Java executable is unavailable" >&2; exit 2; }
if [[ "$SCOPE" == "integration" && ! ( "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ) ]]; then
  echo "[compat] integration scope currently requires linux/x86_64; cross-platform targets use client scope" >&2
  exit 2
fi
if [[ "$SCOPE" == "client" && "$LOADER" != "vanilla" && "$LOADER" != "fabric" && "$LOADER" != "quilt" && "$LOADER" != "forge" && "$LOADER" != "neoforge" ]]; then
  echo "[compat] client scope is supported for Vanilla, Fabric, Quilt and Forge targets" >&2
  exit 2
fi

python3 - "$TARGET_OS" "$TARGET_ARCH" > "$PLATFORM_EVIDENCE" <<'PY'
import json, platform, sys
expected_os, expected_arch = sys.argv[1:3]
system = platform.system().lower()
actual_os = {"linux":"linux", "windows":"windows", "darwin":"macos"}.get(system, system)
machine = platform.machine().lower()
actual_arch = {"x86_64":"x86_64", "amd64":"x86_64", "aarch64":"aarch64", "arm64":"aarch64"}.get(machine, machine)
matched = actual_os == expected_os and actual_arch == expected_arch
payload = {"expectedOS":expected_os,"expectedArch":expected_arch,"detectedOS":actual_os,"detectedArch":actual_arch,"matched":matched}
print(json.dumps(payload, indent=2))
if not matched:
    raise SystemExit(f"runner mismatch: expected {expected_os}/{expected_arch}, detected {actual_os}/{actual_arch}")
PY
if [[ $? -ne 0 ]]; then
  exit 2
fi

python3 "$ROOT/scripts/compatibility/certify-jre.py" \
  --java "$JAVA_BIN" \
  --major "$JAVA_MAJOR" \
  --os "$TARGET_OS" \
  --arch "$TARGET_ARCH" \
  --output "$JAVA_EVIDENCE"
if [[ $? -ne 0 ]]; then
  exit 2
fi

export NEVERLAUNCHER_E2E_MODE=compatibility
export NEVERLAUNCHER_E2E_PROFILE_ID="$LOADER"

set +e
if [[ "$SCOPE" == "client" && "$MATCHING_SERVER" == "true" ]]; then
  bash "$ROOT/e2e/scripts/run-vanilla-matching-e2e.sh"
elif [[ "$SCOPE" == "client" && "$LOADER" == "vanilla" ]]; then
  bash "$ROOT/e2e/scripts/run-vanilla-certification-case.sh"
elif [[ "$SCOPE" == "client" && "$LOADER" == "fabric" ]]; then
  bash "$ROOT/e2e/scripts/run-fabric-certification-case.sh"
elif [[ "$SCOPE" == "client" && "$LOADER" == "quilt" ]]; then
  bash "$ROOT/e2e/scripts/run-quilt-certification-case.sh"
elif [[ "$SCOPE" == "client" && "$LOADER" == "forge" ]]; then
  bash "$ROOT/e2e/scripts/run-forge-certification-case.sh"
elif [[ "$SCOPE" == "client" && "$LOADER" == "neoforge" ]]; then
  bash "$ROOT/e2e/scripts/run-neoforge-certification-case.sh"
else
  bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
fi
rc=$?
set -e

python3 - "$ROOT" "$RESULT" "$JAVA_EVIDENCE" "$PLATFORM_EVIDENCE" "$TARGET_ID" "$PRODUCT_VERSION" "$MINECRAFT" "$LOADER" "$LOADER_SELECTOR" "$TARGET_OS" "$TARGET_ARCH" "$JAVA_MAJOR" "$SCOPE" "$MATCHING_SERVER" "$COMMIT" "$RUN_ID" "$rc" <<'PY'
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
java_evidence_path = Path(sys.argv[3])
platform_evidence_path = Path(sys.argv[4])
target_id, product_version, minecraft, loader, selector, os_name, arch = sys.argv[5:12]
java_major = int(sys.argv[12])
scope, matching_server_raw, commit, run_id = sys.argv[13:17]
matching_server = matching_server_raw == "true"
rc = int(sys.argv[17])
runtime = root / "e2e" / "runtime"

def read(name: str):
    p = runtime / name
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def read_path(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

def valid_sha256(value) -> bool:
    return bool(SHA256_RE.fullmatch(str(value or "").lower()))

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

java_evidence = read_path(java_evidence_path) or {}
platform_evidence = read_path(platform_evidence_path) or {}
detected_java = java_evidence.get("detectedMajor")
java_matched = java_evidence.get("matched") is True and detected_java == java_major
platform_matched = platform_evidence.get("matched") is True and platform_evidence.get("detectedOS") == os_name and platform_evidence.get("detectedArch") == arch

if scope == "client":
    base = read("result.json") or {}
    package = read("client-package.json") or {}
    verify = read("materialized-client-verify.json") or {}
    if loader in ("fabric", "quilt", "forge", "neoforge"):
        install_name = f"{loader}-install.json"
        probe_name = f"{loader}-certification.json"
    else:
        install_name = "vanilla-install.json"
        probe_name = "vanilla-certification.json"
    install = read(install_name) or {}
    probe = read(probe_name) or {}
    resolution_lock_sha = str(install.get("resolutionLockSha256") or "")
    resolution_source_sha = str(install.get("resolutionSourceSha256") or "")
    reproducibility_sha = str(install.get("reproducibilitySha256") or "")
    resolution_pinned = install.get("resolutionPinned") is True
    resolution_lock_path = runtime / f"{loader}-resolution-lock.json"
    resolution_lock_matches = loader == "vanilla" or (
        resolution_lock_path.is_file()
        and valid_sha256(resolution_lock_sha)
        and file_sha256(resolution_lock_path) == resolution_lock_sha.lower()
    )
    manifest_settings = package.get("manifestSettings") if isinstance(package.get("manifestSettings"), dict) else {}
    minecraft_settings = manifest_settings.get("minecraft") if isinstance(manifest_settings.get("minecraft"), dict) else {}
    materialized = install.get("status") == "installed-and-verified" and install.get("minecraftVersion") == minecraft
    if loader in ("fabric", "quilt", "forge", "neoforge"):
        profile_id = str(install.get("profileId") or "")
        runtime_resolved = profile_id != "" and probe.get("minecraftVersion") == profile_id and probe.get("mainClass") == install.get("mainClass") and int(probe.get("classpathEntries") or 0) > 0
        resolved = str(install.get("loaderVersion") or ((base.get("minecraft") or {}).get("resolvedLoaderVersion")) or "")
        materialized = materialized and install.get("loader") == loader and resolved not in ("", "latest", "latest-stable", "stable", "recommended")
    else:
        runtime_resolved = probe.get("minecraftVersion") == minecraft and probe.get("mainClass") not in (None, "") and int(probe.get("classpathEntries") or 0) > 0
        resolved = ""
    checks = {
        "materialized": materialized,
        "packageVerified": verify.get("status") == "valid" and (verify.get("verify") or {}).get("valid") is True,
        "runtimeResolved": runtime_resolved,
        "javaMatched": java_matched and probe.get("requiredJavaMajor") == java_major and probe.get("detectedJavaMajor") == java_major,
        "jreCertified": java_evidence.get("certified") is True,
        "actualClient": probe.get("status") == "passed" and (probe.get("timedOut") is True or probe.get("success") is True),
        "platformMatched": platform_matched,
    }
    if loader != "vanilla":
        checks.update({
            "loaderPinned": resolution_pinned and valid_sha256(resolution_lock_sha),
            "reproducibleResolution": resolution_lock_matches and valid_sha256(resolution_source_sha) and valid_sha256(reproducibility_sha),
        })
    matching = read("matching-server.json") or {}
    server_install = read("vanilla-server-install.json") or {}
    if matching_server:
        checks.update({
            "matchingServer": matching.get("status") == "passed" and matching.get("minecraftVersion") == minecraft,
            "serverVersionMatched": matching.get("serverVersionMatched") is True and matching.get("serverVersion") == minecraft and server_install.get("minecraftVersion") == minecraft,
            "serverHealthy": matching.get("serverProcessAlive") is True,
            "clientJoinedServer": matching.get("clientJoinedServer") is True,
        })
    manifest_loader = str(minecraft_settings.get("loader", ""))
    evidence_files = [name for name in [
        "client-package.json", "materialized-client-verify.json", install_name, "vanilla-server-install.json",
        probe_name, f"{loader}-resolution-lock.json", "matching-server.json", "matching-server.log", "result.json"
    ] if (runtime / name).is_file()]
else:
    base = read("result.json") or {}
    manifest = read("manifest.json") or {}
    verify = read("materialized-client-verify.json") or {}
    runtime_verify = read("runtime-verify.json") or {}
    sync = read("runtime-sync.json") or {}
    launch = read("runtime-launch-minecraft.json") or {}
    health = read("health-paper.json") or {}
    resolved = str(((base.get("minecraft") or {}).get("resolvedLoaderVersion")) or ((manifest.get("minecraft") or {}).get("loaderVersion")) or "")
    loader_resolution = ((base.get("minecraft") or {}).get("loaderResolution") or {})
    resolution_lock_sha = str(loader_resolution.get("lockSha256") or "")
    resolution_source_sha = str(loader_resolution.get("sourceSha256") or "")
    reproducibility_sha = str(loader_resolution.get("reproducibilitySha256") or "")
    resolution_pinned = loader_resolution.get("pinned") is True
    resolution_lock_path = runtime / f"{loader}-resolution-lock.json"
    resolution_lock_matches = loader == "vanilla" or (
        resolution_lock_path.is_file()
        and valid_sha256(resolution_lock_sha)
        and file_sha256(resolution_lock_path) == resolution_lock_sha.lower()
    )
    checks = {
        "packageVerified": verify.get("status") == "valid" and (verify.get("verify") or {}).get("valid") is True,
        "signedManifest": (runtime_verify.get("signature") or {}).get("valid") is True,
        "cleanSync": sync.get("status") == "ready" and (sync.get("download") or {}).get("failed") == 0,
        "actualClient": (base.get("minecraft") or {}).get("client") == "actual-mojang-client" and (launch.get("timedOut") is True or launch.get("success") is True),
        "paperJoin": (base.get("minecraft") or {}).get("paperJoin") == "passed",
        "sessionRevokeDeny": (base.get("checks") or {}).get("sessionRevokeDeny") is True,
        "paperHealthy": health.get("Status") == "healthy" and health.get("FailingStreak") == 0,
        "javaMatched": java_matched,
        "jreCertified": java_evidence.get("certified") is True,
        "platformMatched": platform_matched,
    }
    if loader != "vanilla":
        checks.update({
            "loaderPinned": resolution_pinned and valid_sha256(resolution_lock_sha),
            "reproducibleResolution": resolution_lock_matches and valid_sha256(resolution_source_sha) and valid_sha256(reproducibility_sha),
        })
    manifest_loader = str((manifest.get("minecraft") or {}).get("loader", ""))
    evidence_files = [name for name in [
        "result.json", "materialized-client-verify.json", "manifest.json", "runtime-verify.json",
        "runtime-sync.json", "runtime-launch-minecraft.json", "health-paper.json", "bridge-diagnostics.json",
        f"{loader}-resolution-lock.json"
    ] if (runtime / name).is_file()]

status = "passed" if rc == 0 and all(checks.values()) else "failed"
payload = {
    "schemaVersion": "1.0",
    "productVersion": product_version,
    "targetId": target_id,
    "status": status,
    "minecraftVersion": minecraft,
    "loader": loader,
    "loaderSelector": selector,
    "resolvedLoaderVersion": resolved,
    "resolutionLockSha256": resolution_lock_sha if loader != "vanilla" else "",
    "resolutionSourceSha256": resolution_source_sha if loader != "vanilla" else "",
    "reproducibilitySha256": reproducibility_sha if loader != "vanilla" else "",
    "os": os_name,
    "arch": arch,
    "javaMajor": java_major,
    "detectedJavaMajor": detected_java,
    "jreVendor": str(java_evidence.get("vendor") or ""),
    "jreRuntimeVersion": str(java_evidence.get("runtimeVersion") or ""),
    "jreExecutableSha256": str(java_evidence.get("executableSha256") or ""),
    "scope": scope,
    "matchingServer": matching_server,
    "commit": commit,
    "runId": run_id,
    "exitCode": rc,
    "checks": checks,
    "evidence": {
        "manifestLoader": manifest_loader,
        "javaRuntime": java_evidence,
        "platformRuntime": platform_evidence,
        "files": evidence_files + ["platform-runtime.json", "java-runtime.json"],
        "matchingServer": matching_server,
    },
}
out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(payload, ensure_ascii=False))
PY

if [[ $rc -ne 0 ]]; then
  exit "$rc"
fi
python3 - "$RESULT" <<'PY'
import json, sys
p=json.load(open(sys.argv[1], encoding='utf-8'))
if p.get('status') != 'passed':
    raise SystemExit('compatibility result failed post-validation')
PY
