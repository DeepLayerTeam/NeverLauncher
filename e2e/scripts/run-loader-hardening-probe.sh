#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="${1:-}"
NL_BIN="${2:-}"
RUNTIME_DIR="${3:-$ROOT/e2e/runtime}"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
LOADER_SELECTOR="${NEVERLAUNCHER_E2E_LOADER_VERSION:-latest-stable}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
CLIENT_DIR="$RUNTIME_DIR/materialized-client"
LOCK="$CLIENT_DIR/.neverlauncher/${LOADER}-resolution-lock.json"
OUT_PACKAGE="$RUNTIME_DIR/loader-hardening-package.json"
OUT_EVIDENCE="$RUNTIME_DIR/loader-hardening.json"

case "$LOADER" in fabric|quilt|forge|neoforge) ;; *) echo "[loader-hardening] unsupported loader: $LOADER" >&2; exit 2 ;; esac
[[ -x "$NL_BIN" ]] || { echo "[loader-hardening] CLI binary unavailable: $NL_BIN" >&2; exit 2; }
[[ -f "$LOCK" ]] || { echo "[loader-hardening] resolution lock unavailable: $LOCK" >&2; exit 1; }

# Forge/NeoForge must prove two recovery paths, not just a warm installer file:
# remove the installer and mark one completed processor as interrupted. The
# cache-only replay must restore the exact pinned installer and adopt only an
# output whose installer-declared digest still verifies.
if [[ "$LOADER" == "forge" || "$LOADER" == "neoforge" ]]; then
  find "$CLIENT_DIR/.neverlauncher/installers/$LOADER" -type f -name installer.jar -delete 2>/dev/null || true
  python3 - "$CLIENT_DIR" "$LOADER" "$RUNTIME_DIR/client-package.json" <<'PY'
import json, sys
from pathlib import Path
root, loader, initial_package = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
initial = json.loads(initial_package.read_text(encoding='utf-8')).get(loader) or {}
processor_count = int(initial.get('clientProcessorCount') or 0)
install_mode = str(initial.get('installMode') or '')
legacy_without_processors = loader == 'forge' and install_mode in (
    'legacy-v1-universal', 'legacy-v2-empty-processors'
) and processor_count == 0
journals = sorted((root / '.neverlauncher' / 'installers' / loader).glob('*/processor-journal.json'))
if not journals:
    if legacy_without_processors:
        print('legacy Forge without client processors: recovery journal is not applicable')
        raise SystemExit(0)
    raise SystemExit('processor recovery journal is missing')
path = journals[-1]
data = json.loads(path.read_text(encoding='utf-8'))
entries = data.get('entries') or {}
for key in sorted(entries, key=lambda x: int(x) if str(x).isdigit() else str(x)):
    row = entries[key]
    if row.get('state') == 'completed':
        row['state'] = 'running'
        row['recovered'] = False
        row.pop('lastError', None)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        break
else:
    raise SystemExit('processor journal has no completed client processor to recover')
PY
fi

args=(runtime "${LOADER}-package"
  --minecraft "$MINECRAFT_VERSION"
  --loader-version "$LOADER_SELECTOR"
  --client-dir "$CLIENT_DIR"
  --resolution-lock "$LOCK"
  --loader-cache-only true
  --target "$TARGET_OS/$TARGET_ARCH"
  --project compatibility-hardening
  --profile "${LOADER}-${MINECRAFT_VERSION}-${TARGET_OS}-${TARGET_ARCH}-hardening"
  --channel stable
  --version "$PRODUCT_VERSION-${LOADER}-${MINECRAFT_VERSION}-hardening"
  --output "$OUT_PACKAGE")
if [[ "$LOADER" == "forge" || "$LOADER" == "neoforge" ]]; then
  [[ -n "$JAVA_BIN" ]] || { echo "[loader-hardening] Java is required for $LOADER" >&2; exit 2; }
  args+=(--java "$JAVA_BIN")
fi

"$NL_BIN" "${args[@]}"

python3 - "$OUT_PACKAGE" "$LOCK" "$OUT_EVIDENCE" "$LOADER" "$MINECRAFT_VERSION" "$CLIENT_DIR" <<'PY'
import hashlib, json, re, sys
from pathlib import Path
package_p, lock_p, out_p, loader, minecraft, client_dir = sys.argv[1:]
package = json.load(open(package_p, encoding='utf-8'))
result = package.get(loader) or {}
lock_raw = Path(lock_p).read_bytes()
lock = json.loads(lock_raw.decode('utf-8'))
sha_re = re.compile(r'^[0-9a-f]{64}$')
payload_sha = str(lock.get('payloadSha256') or '').lower()
if not sha_re.fullmatch(payload_sha):
    raise SystemExit('resolution lock has no valid pinned payload SHA-256')
cache_path = Path(client_dir) / '.neverlauncher' / 'loader-cache' / 'sha256' / payload_sha[:2] / (payload_sha + '.payload')
if not cache_path.is_file():
    raise SystemExit(f'content-addressed loader cache payload is missing: {cache_path}')
h = hashlib.sha256(cache_path.read_bytes()).hexdigest()
if h != payload_sha:
    raise SystemExit('content-addressed loader cache SHA-256 mismatch')
if result.get('status') != 'installed-and-verified' or result.get('resolutionPinned') is not True or result.get('loaderCacheOnly') is not True:
    raise SystemExit('cache-only replay did not complete through immutable resolution lock')
if result.get('reproducibilitySha256') != lock.get('reproducibilitySha256'):
    raise SystemExit('cache-only replay changed reproducibility identity')
cache_hit = result.get('payloadCacheHit') is True if loader in ('fabric','quilt') else result.get('installerCacheHit') is True
if not cache_hit or result.get('upstreamRecoveryUsed') is not True:
    raise SystemExit('cache-only replay did not prove upstream-independent cache recovery')
processor_verified = True
processor_applicable = False
client_count = 0
processor_recovered = 0
journal_sha = ''
if loader in ('forge','neoforge'):
    processor_recovered = int(result.get('processorRecovered') or 0)
    journal_sha = str(result.get('processorJournalSha256') or '').lower()
    client_count = int(result.get('clientProcessorCount') or 0)
    ran = int(result.get('processorRan') or 0)
    skipped = int(result.get('processorSkipped') or 0)
    mode = str(result.get('installMode') or '')
    processor_applicable = client_count > 0
    if not processor_applicable:
        processor_verified = (
            loader == 'forge'
            and minecraft in ('1.7.10', '1.12.2')
            and mode in ('legacy-v1-universal', 'legacy-v2-empty-processors')
            and ran == 0 and skipped == 0 and processor_recovered == 0
        )
    else:
        processor_verified = (
            mode == 'processors' and processor_recovered > 0
            and ran + skipped == client_count
            and bool(sha_re.fullmatch(journal_sha))
        )
    if not processor_verified:
        raise SystemExit(
            f'processor crash recovery evidence is incomplete: mode={mode!r}, '
            f'client={client_count}, ran={ran}, skipped={skipped}, '
            f'recovered={processor_recovered}, journalSha={journal_sha!r}'
        )
evidence = {
    'schemaVersion': '1.0',
    'status': 'passed',
    'loader': loader,
    'minecraftVersion': minecraft,
    'resolvedLoaderVersion': result.get('loaderVersion'),
    'resolutionLockSha256': result.get('resolutionLockSha256'),
    'reproducibilitySha256': result.get('reproducibilitySha256'),
    'cacheOnly': True,
    'contentAddressedCache': True,
    'cachePayloadSha256': payload_sha,
    'cachePayloadPath': cache_path.relative_to(Path(client_dir)).as_posix(),
    'cacheHit': cache_hit,
    'upstreamIndependentRecovery': result.get('upstreamRecoveryUsed') is True,
    'installerRecovered': result.get('installerCacheHit') is True if loader in ('forge','neoforge') else None,
    'processorRecoveryVerified': processor_verified,
    'processorRecoveryApplicable': processor_applicable,
    'clientProcessorCount': client_count,
    'processorRecovered': processor_recovered,
    'processorJournalSha256': journal_sha,
}
Path(out_p).write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps(evidence, ensure_ascii=False))
PY

echo "[loader-hardening] PASS $LOADER $MINECRAFT_VERSION content-addressed cache/upstream/installers/processors recovery"
