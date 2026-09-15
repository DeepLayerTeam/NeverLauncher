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
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
COMMIT="${GITHUB_SHA:-local}"
RUN_ID="${GITHUB_RUN_ID:-local}"

mkdir -p "$OUT_DIR"
RESULT="$OUT_DIR/compatibility-result.json"

valid_id() { [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{2,95}$ ]]; }
valid_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]]; }

if ! valid_id "$TARGET_ID" || ! valid_version "$MINECRAFT"; then
  echo "[compat] invalid target metadata" >&2
  exit 2
fi
case "$LOADER" in vanilla|fabric|quilt|forge|neoforge) ;; *) echo "[compat] invalid loader" >&2; exit 2 ;; esac
[[ "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ]] || { echo "[compat] unsupported runner target" >&2; exit 2; }

export NEVERLAUNCHER_E2E_MODE=compatibility
export NEVERLAUNCHER_E2E_PROFILE_ID="$LOADER"

set +e
bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
rc=$?
set -e

python3 - "$ROOT" "$RESULT" "$TARGET_ID" "$PRODUCT_VERSION" "$MINECRAFT" "$LOADER" "$LOADER_SELECTOR" "$TARGET_OS" "$TARGET_ARCH" "$COMMIT" "$RUN_ID" "$rc" <<'PY'
from __future__ import annotations
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
target_id, product_version, minecraft, loader, selector, os_name, arch, commit, run_id = sys.argv[3:12]
rc = int(sys.argv[12])
runtime = root / "e2e" / "runtime"

def read(name: str):
    p = runtime / name
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

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
}
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
    "commit": commit,
    "runId": run_id,
    "exitCode": rc,
    "checks": checks,
    "evidence": {
        "manifestVersion": manifest.get("version", ""),
        "manifestLoader": (manifest.get("minecraft") or {}).get("loader", ""),
        "files": [name for name in [
            "result.json", "materialized-client-verify.json", "manifest.json", "runtime-verify.json",
            "runtime-sync.json", "runtime-launch-minecraft.json", "health-paper.json", "bridge-diagnostics.json"
        ] if (runtime / name).is_file()],
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
