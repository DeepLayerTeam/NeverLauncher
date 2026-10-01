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
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
COMMIT="${GITHUB_SHA:-local}"
RUN_ID="${GITHUB_RUN_ID:-local}"

mkdir -p "$OUT_DIR"
RESULT="$OUT_DIR/compatibility-result.json"
JAVA_EVIDENCE="$OUT_DIR/java-runtime.json"

valid_id() { [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{2,95}$ ]]; }
valid_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]]; }

if ! valid_id "$TARGET_ID" || ! valid_version "$MINECRAFT"; then
  echo "[compat] invalid target metadata" >&2
  exit 2
fi
case "$LOADER" in vanilla|fabric|quilt|forge|neoforge) ;; *) echo "[compat] invalid loader" >&2; exit 2 ;; esac
case "$SCOPE" in client|integration) ;; *) echo "[compat] invalid certification scope" >&2; exit 2 ;; esac
[[ "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ]] || { echo "[compat] unsupported runner target" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[compat] java major is required" >&2; exit 2; }
[[ -n "$JAVA_BIN" && -x "$JAVA_BIN" ]] || { echo "[compat] target Java executable is unavailable" >&2; exit 2; }
if [[ "$SCOPE" == "client" && "$LOADER" != "vanilla" ]]; then
  echo "[compat] client scope is reserved for Vanilla baseline targets" >&2
  exit 2
fi

python3 - "$JAVA_BIN" "$JAVA_MAJOR" > "$JAVA_EVIDENCE" <<'PY'
import json, re, subprocess, sys
java, expected = sys.argv[1], int(sys.argv[2])
proc = subprocess.run([java, "-version"], capture_output=True, text=True)
text = (proc.stdout or "") + (proc.stderr or "")
match = re.search(r'version\s+"([^"]+)"', text)
detected = None
if match:
    parts = match.group(1).split('.')
    try:
        detected = int(parts[1] if parts[0] == '1' else parts[0])
    except (ValueError, IndexError):
        detected = None
payload = {
    "java": java,
    "expectedMajor": expected,
    "detectedMajor": detected,
    "exitCode": proc.returncode,
    "matched": proc.returncode == 0 and detected == expected,
    "versionOutput": text.strip(),
}
print(json.dumps(payload, indent=2, ensure_ascii=False))
if not payload["matched"]:
    raise SystemExit(f"target Java mismatch: expected {expected}, detected {detected}")
PY
if [[ $? -ne 0 ]]; then
  exit 2
fi

export NEVERLAUNCHER_E2E_MODE=compatibility
export NEVERLAUNCHER_E2E_PROFILE_ID="$LOADER"

set +e
if [[ "$SCOPE" == "client" ]]; then
  bash "$ROOT/e2e/scripts/run-vanilla-certification-case.sh"
else
  bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
fi
rc=$?
set -e

python3 - "$ROOT" "$RESULT" "$JAVA_EVIDENCE" "$TARGET_ID" "$PRODUCT_VERSION" "$MINECRAFT" "$LOADER" "$LOADER_SELECTOR" "$TARGET_OS" "$TARGET_ARCH" "$JAVA_MAJOR" "$SCOPE" "$COMMIT" "$RUN_ID" "$rc" <<'PY'
from __future__ import annotations
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
java_evidence_path = Path(sys.argv[3])
target_id, product_version, minecraft, loader, selector, os_name, arch = sys.argv[4:11]
java_major = int(sys.argv[11])
scope, commit, run_id = sys.argv[12:15]
rc = int(sys.argv[15])
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

java_evidence = read_path(java_evidence_path) or {}
detected_java = java_evidence.get("detectedMajor")
java_matched = java_evidence.get("matched") is True and detected_java == java_major

if scope == "client":
    base = read("result.json") or {}
    package = read("client-package.json") or {}
    verify = read("materialized-client-verify.json") or {}
    install = read("vanilla-install.json") or {}
    probe = read("vanilla-certification.json") or {}
    manifest_settings = package.get("manifestSettings") if isinstance(package.get("manifestSettings"), dict) else {}
    minecraft_settings = manifest_settings.get("minecraft") if isinstance(manifest_settings.get("minecraft"), dict) else {}
    checks = {
        "materialized": install.get("status") == "installed-and-verified" and install.get("minecraftVersion") == minecraft,
        "packageVerified": verify.get("status") == "valid" and (verify.get("verify") or {}).get("valid") is True,
        "runtimeResolved": probe.get("mainClass") not in (None, "") and int(probe.get("classpathEntries") or 0) > 0,
        "javaMatched": java_matched and probe.get("requiredJavaMajor") == java_major and probe.get("detectedJavaMajor") == java_major,
        "actualClient": probe.get("status") == "passed" and (probe.get("timedOut") is True or probe.get("success") is True),
    }
    resolved = ""
    manifest_loader = str(minecraft_settings.get("loader", ""))
    evidence_files = [name for name in [
        "client-package.json", "materialized-client-verify.json", "vanilla-install.json", "vanilla-certification.json", "result.json"
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
    checks = {
        "packageVerified": verify.get("status") == "valid" and (verify.get("verify") or {}).get("valid") is True,
        "signedManifest": (runtime_verify.get("signature") or {}).get("valid") is True,
        "cleanSync": sync.get("status") == "ready" and (sync.get("download") or {}).get("failed") == 0,
        "actualClient": (base.get("minecraft") or {}).get("client") == "actual-mojang-client" and (launch.get("timedOut") is True or launch.get("success") is True),
        "paperJoin": (base.get("minecraft") or {}).get("paperJoin") == "passed",
        "sessionRevokeDeny": (base.get("checks") or {}).get("sessionRevokeDeny") is True,
        "paperHealthy": health.get("Status") == "healthy" and health.get("FailingStreak") == 0,
        "javaMatched": java_matched,
    }
    manifest_loader = str((manifest.get("minecraft") or {}).get("loader", ""))
    evidence_files = [name for name in [
        "result.json", "materialized-client-verify.json", "manifest.json", "runtime-verify.json",
        "runtime-sync.json", "runtime-launch-minecraft.json", "health-paper.json", "bridge-diagnostics.json"
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
    "os": os_name,
    "arch": arch,
    "javaMajor": java_major,
    "detectedJavaMajor": detected_java,
    "scope": scope,
    "commit": commit,
    "runId": run_id,
    "exitCode": rc,
    "checks": checks,
    "evidence": {
        "manifestLoader": manifest_loader,
        "javaRuntime": java_evidence,
        "files": evidence_files,
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
