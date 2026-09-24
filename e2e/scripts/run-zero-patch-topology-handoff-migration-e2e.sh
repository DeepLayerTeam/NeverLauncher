#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/topology-handoff-migration-runtime"
RESULT_DIR="$ROOT/e2e/topology-handoff-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-topology-handoff-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
need(){ command -v "$1" >/dev/null 2>&1 || { echo "[topology-handoff-migration] required command missing: $1" >&2; exit 1; }; }
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
  base="$(basename "$migration")"; ordinal="${base%%_*}"; (( 10#$ordinal > 27 )) && continue
  migration_version="${base%.sql}"; checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description) VALUES(:'version',:'checksum',:'version');
SQL
done
latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"; [[ "$latest_before" == "0027_forge_neoforge_server_bridge_0147" ]]
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO projects(id,name,default_channel) VALUES ('topology-project','Topology Project','stable');
INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,created_at)
VALUES
 ('proxy-main','proxy-main','velocity','topology-project','vanilla','','','','active',2,'ed25519',repeat('A',43),repeat('a',64),1,now(),now()),
 ('survival','survival','paper','topology-project','vanilla','','','','active',2,'ed25519',repeat('B',43),repeat('b',64),1,now(),now());
SQL
( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"; grep -q verified "$RUNTIME_DIR/migrate-verify.log"
latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"; [[ "$latest_after" == "0028_zero_patch_topology_handoff_0148" ]]
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM server_bridge_nodes_v2 WHERE id IN ('proxy-main','survival')")" == 2 ]]
for table in server_bridge_topology_edges_v2 server_bridge_handoffs_v2; do
  [[ "$(psql "$DB_DSN" -Atqc "SELECT to_regclass('public.$table') IS NOT NULL")" == t ]]
done
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO server_bridge_topology_edges_v2(source_node_id,target_node_id,backend_name,project_id,profile_id,status,created_at,last_seen_at)
VALUES('proxy-main','survival','survival','topology-project','vanilla','active',now(),now());
SQL
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM server_bridge_topology_edges_v2 WHERE source_node_id='proxy-main' AND target_node_id='survival' AND status='active'")" == 1 ]]
jq -n --arg version "$VERSION" --arg before "$latest_before" --arg after "$latest_after" '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after},existingNodesPreserved:true,topologyTable:true,handoffTable:true}' > "$RESULT_DIR/zero-patch-topology-handoff-migration.json"
printf '[topology-handoff-migration] PASS 0.14.7 -> 0.14.8 topology/handoff schema semantics\n'
