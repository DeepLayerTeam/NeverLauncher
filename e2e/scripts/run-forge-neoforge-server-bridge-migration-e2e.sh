#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/forge-neoforge-migration-runtime"
RESULT_DIR="$ROOT/e2e/forge-neoforge-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-forge-neoforge-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
need(){ command -v "$1" >/dev/null 2>&1 || { echo "[forge-neoforge-migration] required command missing: $1" >&2; exit 1; }; }
for cmd in docker psql go python3 sha256sum jq; do need "$cmd"; done
docker compose version >/dev/null
rm -rf "$RUNTIME_DIR" "$RESULT_DIR"; mkdir -p "$RUNTIME_DIR" "$RESULT_DIR"; chmod 0700 "$RUNTIME_DIR"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
ENV
chmod 0600 "$ENV_FILE"
compose(){ docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup(){ if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then compose down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$RUNTIME_DIR"; fi; }
trap cleanup EXIT
compose up -d postgres redis volume-init
for _ in $(seq 1 60); do psql "$DB_DSN" -Atqc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
psql "$DB_DSN" -Atqc 'select 1' >/dev/null
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
SQL
for migration in "$ROOT"/services/api/internal/dbmigrate/sql/*.sql; do
  base="$(basename "$migration")"; ordinal="${base%%_*}"; (( 10#$ordinal > 26 )) && continue
  migration_version="${base%.sql}"; checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description) VALUES(:'version',:'checksum',:'version');
SQL
done
latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"; [[ "$latest_before" == "0026_fabric_server_bridge_0146" ]]
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO projects(id,name,default_channel) VALUES ('forge-family-project','Forge Family Project','stable');
INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,created_at)
VALUES ('fabric-before-0147','Fabric Before 0147','fabric','forge-family-project','vanilla','','','','active',2,'ed25519',repeat('A',43),repeat('a',64),1,now(),now());
SQL
( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"; grep -q verified "$RUNTIME_DIR/migrate-verify.log"
latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"; [[ "$latest_after" == "0027_forge_neoforge_server_bridge_0147" ]]
[[ "$(psql "$DB_DSN" -Atqc "SELECT kind FROM server_bridge_nodes_v2 WHERE id='fabric-before-0147'")" == fabric ]]
for kind in forge neoforge; do
  fp="$(printf '%s-0147' "$kind" | sha256sum | awk '{print $1}')"
  psql "$DB_DSN" -v ON_ERROR_STOP=1 -v id="${kind}-0147" -v name="${kind}-0147" -v kind="$kind" -v fingerprint="$fp" <<'SQL' >/dev/null
INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,created_at)
VALUES(:'id',:'name',:'kind','forge-family-project','vanilla','','','','active',2,'ed25519',repeat('B',43),:'fingerprint',1,now(),now());
SQL
done
if psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null 2>&1
INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,created_at)
VALUES('invalid-neoforge','invalid','neo-forge','forge-family-project','vanilla','','','','active',2,'ed25519',repeat('C',43),repeat('c',64),1,now(),now());
SQL
then echo '[forge-neoforge-migration] non-canonical kind bypassed constraint' >&2; exit 1; fi
count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM server_bridge_nodes_v2 WHERE kind IN ('forge','neoforge')")"; [[ "$count" == 2 ]]
jq -n --arg version "$VERSION" --arg before "$latest_before" --arg after "$latest_after" --argjson count "$count" '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after},existingNodePreserved:true,forgeNeoForgeKindsAccepted:true,nonCanonicalKindRejected:true,nodeCount:$count}' > "$RESULT_DIR/forge-neoforge-server-bridge-migration.json"
printf '[forge-neoforge-migration] PASS 0.14.6 -> 0.14.7 Forge + NeoForge schema semantics\n'
