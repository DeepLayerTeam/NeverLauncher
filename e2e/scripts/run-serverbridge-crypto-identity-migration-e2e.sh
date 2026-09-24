#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/serverbridge-crypto-migration-runtime"
RESULT_DIR="$ROOT/e2e/serverbridge-crypto-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-serverbridge-crypto-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[serverbridge-crypto-migration] required command missing: $1" >&2; exit 1; }; }
for cmd in docker psql go python3 sha256sum jq; do need "$cmd"; done
docker compose version >/dev/null

rm -rf "$RUNTIME_DIR" "$RESULT_DIR"
mkdir -p "$RUNTIME_DIR" "$RESULT_DIR"
chmod 0700 "$RUNTIME_DIR"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
ENV
chmod 0600 "$ENV_FILE"
compose() { docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUNTIME_DIR"
  fi
}
trap cleanup EXIT

printf '[serverbridge-crypto-migration] materialize exact 0.14.1 database through migration 0021\n'
compose up -d postgres redis volume-init
for _ in $(seq 1 60); do
  if psql "$DB_DSN" -Atqc 'select 1' >/dev/null 2>&1; then break; fi
  sleep 1
done
psql "$DB_DSN" -Atqc 'select 1' >/dev/null
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  checksum TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SQL
for migration in "$ROOT"/services/api/internal/dbmigrate/sql/*.sql; do
  base="$(basename "$migration")"
  ordinal="${base%%_*}"
  (( 10#$ordinal > 21 )) && continue
  migration_version="${base%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description)
VALUES(:'version',:'checksum',:'version');
SQL
done
latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_before" == "0021_serverbridge_protocol_v2_0141" ]]

printf '[serverbridge-crypto-migration] seed active 0.14.1 bearer node and live join ticket\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO projects(id,name,default_channel) VALUES ('crypto-project','Crypto Project','stable');
INSERT INTO users(id,email,display_name,role_id,status) VALUES ('crypto-user','crypto-user@example.invalid','Crypto User','player','active');
INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,device,status,refresh_family_id,expires_at)
VALUES ('crypto-session','crypto-user','crypto-user@example.invalid','player','','e2e','active','crypto-family',now()+interval '1 hour');
INSERT INTO server_bridge_nodes_v2(
  id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,
  plugin_version,plugin_sha256,integrity_status,integrity_verified_at,last_heartbeat_at,created_at,rotated_at
) VALUES (
  'paper-0141','Paper 0141','paper','crypto-project','vanilla','host-fingerprint',
  repeat('a',64),'nlsrv_0141','active',2,'0.14.1',repeat('b',64),'verified',now(),now(),now()-interval '5 minutes',now()-interval '1 minute'
);
INSERT INTO server_bridge_nodes_v2(
  id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,created_at
) VALUES (
  'paper-disabled-0141','Disabled Paper 0141','paper','crypto-project','vanilla','disabled-host',
  repeat('d',64),'nlsrv_disabled','disabled',2,now()-interval '10 minutes'
);
INSERT INTO server_bridge_join_tickets_v2(
  id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,
  access_token_hash,binding_epoch,protocol_version,status,created_at,expires_at
) VALUES (
  'join-0141','CryptoPlayer','cryptoplayer','00000000-0000-0000-0000-000000000142',
  'crypto-user','crypto-session','paper-0141','crypto-project','vanilla','stable',repeat('c',64),1,2,'active',now(),now()+interval '2 minutes'
);
SQL

( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.log"
latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_after" == "0022_serverbridge_crypto_node_identities_0142" ]]

node_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT status,token_hash,token_prefix,key_algorithm,public_key,key_fingerprint,identity_epoch,plugin_version,plugin_sha256,integrity_status,(integrity_verified_at IS NULL)::text,(last_heartbeat_at IS NULL)::text FROM server_bridge_nodes_v2 WHERE id='paper-0141'")"
# psql renders empty text columns as adjacent delimiters.
[[ "$node_state" == "identity-enrollment-required||||||0||||t|t" ]] || { echo "unexpected migrated node state: $node_state" >&2; exit 1; }
disabled_legacy_secret="$(psql "$DB_DSN" -AtF '|' -qc "SELECT token_hash,token_prefix,status FROM server_bridge_nodes_v2 WHERE id='paper-disabled-0141'")"
[[ "$disabled_legacy_secret" == "||disabled" ]] || { echo "disabled node retained legacy bearer material: $disabled_legacy_secret" >&2; exit 1; }
join_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT status,(invalidated_at IS NOT NULL)::text FROM server_bridge_join_tickets_v2 WHERE id='join-0141'")"
[[ "$join_state" == "invalidated|t" ]] || { echo "0.14.1 active join survived identity boundary: $join_state" >&2; exit 1; }
nonce_table="$(psql "$DB_DSN" -Atqc "SELECT to_regclass('server_bridge_node_nonces_v2') IS NOT NULL")"
[[ "$nonce_table" == "t" ]] || { echo "node nonce table missing" >&2; exit 1; }
identity_index="$(psql "$DB_DSN" -Atqc "SELECT to_regclass('uq_server_bridge_nodes_v2_key_fingerprint') IS NOT NULL")"
[[ "$identity_index" == "t" ]] || { echo "node fingerprint uniqueness index missing" >&2; exit 1; }

jq -n --arg version "$VERSION" --arg before "$latest_before" --arg after "$latest_after" \
  '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after},legacyBearerRetired:true,nodeStatus:"identity-enrollment-required",activeJoinInvalidated:true,nonceReplayStoreCreated:true}' \
  > "$RESULT_DIR/serverbridge-crypto-identity-migration.json"
printf '[serverbridge-crypto-migration] PASS 0.14.1 -> 0.14.2 bearer retirement + identity enrollment semantics\n'
