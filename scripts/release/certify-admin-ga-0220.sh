#!/usr/bin/env bash
# Runs actual compile, race tests, PostgreSQL/ServerBridge integration and live browser against staging.
# Aborts on ANY failure or missing credential; no stub/mock fallbacks and no "skipped means passed".
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
RELEASE_VERSION="$(< VERSION)"
python3 scripts/release/release_policy.py ga-mode --version "$RELEASE_VERSION" >/dev/null || exit 2

: "${NEVERLAUNCHER_GA_SOURCE_SHA:?set the exact candidate commit SHA}"
[[ "$NEVERLAUNCHER_GA_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'invalid release commit SHA' >&2; exit 2; }
command -v git >/dev/null || { echo 'git is required for source attestation' >&2; exit 2; }
COMMIT="$(git rev-parse --verify HEAD)"
export NEVERLAUNCHER_SOURCE_COMMIT="$NEVERLAUNCHER_GA_SOURCE_SHA"
export E2E_EXPECTED_COMMIT="$NEVERLAUNCHER_GA_SOURCE_SHA"
[[ "$COMMIT" == "$NEVERLAUNCHER_GA_SOURCE_SHA" ]] || { echo 'candidate SHA does not match checkout HEAD' >&2; exit 2; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo 'candidate checkout is modified' >&2; exit 2; }

for var in E2E_ADMIN_URL E2E_API_URL E2E_ADMIN_TOKEN E2E_OPERATOR_TOKEN E2E_PROJECT_ID E2E_FOREIGN_PROJECT_ID E2E_SERVERBRIDGE_NODE_ID E2E_DESTRUCTIVE_STAGING_ACK; do
  [[ -n "${!var:-}" ]] || { echo "missing live staging variable $var" >&2; exit 2; }
done
for cmd in go node npm python3 docker; do
  command -v "$cmd" >/dev/null || { echo "missing certification tool: $cmd" >&2; exit 2; }
done

python3 scripts/release/check-admin-ga-0220.py
(
  cd apps/admin
  npm ci --no-audit --no-fund
  npm test
  npm run build
)
(
  cd services/api
  go test -race -count=1 ./...
  go vet ./...
  go build -trimpath -ldflags="-X main.version=${RELEASE_VERSION} -X main.commit=${COMMIT}" -o /tmp/neverlauncher-ga-api ./cmd/neverlauncher-api
)
(
  cd cli
  go test -race -count=1 ./...
  go vet ./...
  go build -trimpath -o /tmp/neverlauncher-ga-cli ./cmd/neverlauncher
)
# Covers live pgx migration, CAS, durable/ServerBridge enqueue, lease and signed ACK.
bash e2e/scripts/run-admin-hardening-02112-e2e.sh
python3 e2e/scripts/admin-hardening-02112-browser.py
python3 e2e/scripts/admin-ga-0220-serverbridge.py

# Emit evidence only AFTER all processes return success; an incomplete run has no PASS file.
mkdir -p dist/ga-certification
python3 - "$COMMIT" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path.cwd()
assets = sorted(p for p in (root / 'apps/admin/dist').rglob('*') if p.is_file())
if not assets or not (root / 'apps/admin/dist/index.html').is_file():
    raise SystemExit('Vite did not produce a deployable Admin bundle')
hash_of = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
payload = {
    'status': 'passed', 'productVersion': (root / 'VERSION').read_text().strip(), 'commit': sys.argv[1],
    'checks': ['openapi', 'version', 'repository-policy', 'migration-parity', 'sdk-reproducibility',
               'admin-node-tests', 'vite-production-build', 'api-go-race', 'api-go-vet',
               'api-production-build', 'cli-go-race', 'cli-go-vet', 'cli-production-build',
               'postgresql-serverbridge-integration', 'live-playwright-rbac-two-tabs-recovery', 'live-serverbridge-v3-save-drain-ack'],
    'adminBundle': {str(p.relative_to(root / 'apps/admin/dist')): hash_of(p) for p in assets},
    'openapiSha256': hash_of(root / 'schemas/openapi.yaml'),
}
result = root / 'dist/ga-certification/admin-0220.json'
result.write_text(json.dumps(payload, indent=2, sort_keys=True)+'\n')
print(f'Admin GA certification PASS for exact source commit {sys.argv[1]}')
PY
