#!/usr/bin/env bash
# Выполняются реальные компиляция, race-тесты, интеграция PostgreSQL/ServerBridge и живой браузер против
# staging. При ЛЮБОЙ ошибке или отсутствии учётных данных процесс останавливается; никаких заглушек, имитаций
# или правила «пропуск означает успех».
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# Неудачная предварительная проверка никогда не должна оставлять прежний зелёный
# сертификат GA.
rm -f dist/ga-certification/admin-0220.json dist/ga-certification/owner-cycle-0390.json
RELEASE_VERSION="$(< VERSION)"
python3 scripts/release/release_policy.py ga-mode --version "$RELEASE_VERSION" >/dev/null || exit 2

: "${LAUNCHER_GA_SOURCE_SHA:?укажите точный SHA коммита кандидата}"
[[ "$LAUNCHER_GA_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Некорректный SHA коммита релиза' >&2; exit 2; }
command -v git >/dev/null || { echo 'Для подтверждения происхождения исходников требуется git' >&2; exit 2; }
COMMIT="$(git rev-parse --verify HEAD)"
export LAUNCHER_SOURCE_COMMIT="$LAUNCHER_GA_SOURCE_SHA"
export E2E_EXPECTED_COMMIT="$LAUNCHER_GA_SOURCE_SHA"
[[ "$COMMIT" == "$LAUNCHER_GA_SOURCE_SHA" ]] || { echo 'SHA кандидата не совпадает с HEAD рабочей копии' >&2; exit 2; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo 'Рабочая копия кандидата содержит изменения' >&2; exit 2; }

for var in E2E_ADMIN_URL E2E_API_URL E2E_ADMIN_TOKEN E2E_OPERATOR_TOKEN E2E_PROJECT_ID E2E_FOREIGN_PROJECT_ID E2E_SERVERBRIDGE_NODE_ID E2E_DESTRUCTIVE_STAGING_ACK; do
  [[ -n "${!var:-}" ]] || { echo "Не задана переменная действующего staging-окружения $var" >&2; exit 2; }
done
for cmd in go node npm python3 docker; do
  command -v "$cmd" >/dev/null || { echo "Отсутствует утилита сертификации: $cmd" >&2; exit 2; }
done

python3 - "$RELEASE_VERSION" "$COMMIT" <<'PYRUN'
import pathlib, sys
sys.path.insert(0, 'scripts/release')
from certification_run import identity
identity(sys.argv[1], sys.argv[2], root=pathlib.Path.cwd())
PYRUN
rm -f dist/ga-certification/admin-0220.json
python3 scripts/release/check-admin-ga-0220.py
python3 -m unittest scripts/release/test_owner_cycle_0390.py -v
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
  go build -trimpath -ldflags="-X main.version=${RELEASE_VERSION} -X main.commit=${COMMIT}" -o /tmp/launcher-ga-api ./cmd/launcher-api
)
(
  cd cli
  go test -race -count=1 ./...
  go vet ./...
  go build -trimpath -o /tmp/launcher-ga-cli ./cmd/launcher
)
# Охватывает живую миграцию pgx, CAS, устойчивую постановку задач/ServerBridge в очередь,
# аренду и подписанный ACK.
bash e2e/scripts/run-admin-hardening-02112-e2e.sh
python3 e2e/scripts/admin-hardening-02112-browser.py
# С версии 0.39.0 обязателен НАСТОЯЩИЙ браузерный цикл владельца, а не квитанция
# манифеста.
if python3 - "$RELEASE_VERSION" <<'PYVERSION'
import sys
raise SystemExit(0 if tuple(map(int,sys.argv[1].split('-',1)[0].split('+',1)[0].split('.')[:3])) >= (0,39,0) else 1)
PYVERSION
then
  python3 e2e/scripts/owner-cycle-0390-browser.py
  python3 - "$RELEASE_VERSION" "$COMMIT" <<'PYOWNER'
import importlib.util,json,sys,pathlib
p=pathlib.Path('e2e/scripts/owner-cycle-0390-browser.py')
s=importlib.util.spec_from_file_location('owner0390',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=pathlib.Path('dist/ga-certification/owner-cycle-0390.json')
m.verify_receipt(json.loads(r.read_text()),version=sys.argv[1],commit=sys.argv[2])
PYOWNER
fi
python3 e2e/scripts/admin-ga-0220-serverbridge.py

# Формируйте доказательства ТОЛЬКО ПОСЛЕ успешного завершения всех процессов; неполный запуск не
# имеет файла PASS.
mkdir -p dist/ga-certification
python3 - "$COMMIT" <<'PY'
import hashlib, json, pathlib, sys
sys.path.insert(0, 'scripts/release')
from certification_run import identity
root = pathlib.Path.cwd()
assets = sorted(p for p in (root / 'apps/admin/dist').rglob('*') if p.is_file())
if not assets or not (root / 'apps/admin/dist/index.html').is_file():
    raise SystemExit('Vite не создал пакет Admin, пригодный для развёртывания')
hash_of = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
payload = {
    'status': 'passed', 'productVersion': (root / 'VERSION').read_text().strip(), 'commit': sys.argv[1],
    'checks': ['openapi', 'version', 'repository-policy', 'migration-parity', 'sdk-reproducibility',
               'admin-node-tests', 'vite-production-build', 'api-go-race', 'api-go-vet',
               'api-production-build', 'cli-go-race', 'cli-go-vet', 'cli-production-build',
               'postgresql-serverbridge-integration', 'live-playwright-rbac-two-tabs-recovery', 'live-serverbridge-v3-save-drain-ack'] +
              (['live-playwright-owner-cycle-0390'] if tuple(map(int,(root / 'VERSION').read_text().strip().split('-',1)[0].split('+',1)[0].split('.')[:3])) >= (0,39,0) else []),
    'adminBundle': {str(p.relative_to(root / 'apps/admin/dist')): hash_of(p) for p in assets},
    'openapiSha256': hash_of(root / 'schemas/openapi.yaml'),
    **({'ownerCycleReceiptSha256': hash_of(root / 'dist/ga-certification/owner-cycle-0390.json')} if
       tuple(map(int,(root / 'VERSION').read_text().strip().split('-',1)[0].split('+',1)[0].split('.')[:3])) >= (0,39,0) else {}),
    'certificationRun': identity((root / 'VERSION').read_text().strip(), sys.argv[1], root=root),
}
result = root / 'dist/ga-certification/admin-0220.json'
result.write_text(json.dumps(payload, indent=2, sort_keys=True)+'\n')
print(f'Admin GA certification PASS for exact source commit {sys.argv[1]}')
PY
