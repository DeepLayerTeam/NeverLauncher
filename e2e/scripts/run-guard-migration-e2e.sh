#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/guard-migration-runtime"
RESULT_DIR="$ROOT/e2e/guard-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-guard-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[guard-migration-e2e] required command missing: $1" >&2; exit 1; }; }
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

printf '[guard-migration-e2e] materialize exact 0.13.9 database (0001..0019)\n'
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
  (( 10#$ordinal > 19 )) && continue
  migration_version="${base%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description)
VALUES(:'version',:'checksum',:'version');
SQL
done

latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_before" == "0019_minecraft_serverbridge_integrity_0135" ]] || { echo "unexpected pre-upgrade migration: $latest_before" >&2; exit 1; }

printf '[guard-migration-e2e] seed valid 0.13.9 state plus an ambiguous partial Guard snapshot\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO users(id,email,display_name,role_id,status) VALUES
 ('gmig-user','gmig@example.invalid','Guard Migration','player','active');
INSERT INTO auth_identities(id,user_id,provider,subject) VALUES
 ('identity-local-gmig-user','gmig-user','local','gmig-user');
INSERT INTO trusted_devices(
 id,user_id,name,status,trust_state,assurance,key_algorithm,key_binding,hardware_provider,
 attestation_state,attestation_method,public_key,key_fingerprint,platform,client_version,
 created_at,updated_at,last_ip,last_user_agent,revoked_reason,replaced_at,replaced_by_device_id,replacement_reason
) VALUES
 ('gmig-device','gmig-user','Guard migration device','active','verified','proof-of-possession','ed25519','software','',
  'unattested','','legacy-public-key',repeat('1',64),'linux','0.13.9',now(),now(),'127.0.0.1','guard-migration-e2e','',NULL,NULL,'');
INSERT INTO auth_sessions(
 id,user_id,email,role_id,device_id,device,status,refresh_family_id,created_at,last_seen_at,expires_at,
 trusted_device_id,device_trust_state,device_verified_at,binding_epoch
) VALUES
 ('gmig-session','gmig-user','gmig@example.invalid','player','legacy','Guard Migration','active','gmig-family',now(),now(),now()+interval '1 day','gmig-device','verified',now(),2);
INSERT INTO refresh_token_families(id,session_id,user_id,status) VALUES
 ('gmig-family','gmig-session','gmig-user','active');
INSERT INTO minecraft_profiles(user_id,uuid,name) VALUES
 ('gmig-user','00000000-0000-0000-0000-000000001310','GMigUser');
INSERT INTO minecraft_sessions(
 id,user_id,never_session_id,profile_uuid,trusted_device_id,binding_epoch,client_token,access_token_hash,
 integrity_verified,guard_attestation_sha256,guard_evidence_sha256,guard_sha256,launcher_sha256,launcher_version,integrity_verified_at,
 status,created_at,last_seen_at,expires_at
) VALUES
 ('gmig-valid','gmig-user','gmig-session','00000000-0000-0000-0000-000000001310','gmig-device',2,'valid-client',repeat('2',64),
  TRUE,repeat('3',64),repeat('4',64),repeat('5',64),repeat('6',64),'0.13.9',now()-interval '30 seconds',
  'active',now(),now(),now()+interval '1 hour'),
 ('gmig-partial','gmig-user','gmig-session','00000000-0000-0000-0000-000000001310','gmig-device',2,'partial-client',repeat('7',64),
  FALSE,'','',repeat('8',64),'','',NULL,
  'active',now(),now(),now()+interval '1 hour');
COMMIT;
SQL

( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )

printf '[guard-migration-e2e] prove 0020 refuses ambiguous 0.13.9 state\n'
if "$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" >"$RUNTIME_DIR/migrate-invalid.log" 2>&1; then
  echo '[guard-migration-e2e] 0020 unexpectedly accepted a partial Guard snapshot' >&2
  exit 1
fi
if psql "$DB_DSN" -Atqc "SELECT count(*) FROM schema_migrations WHERE version='0020_guard_migration_compatibility_stabilization_01310'" | grep -qx '1'; then
  echo '[guard-migration-e2e] failed migration was recorded as applied' >&2
  exit 1
fi

printf '[guard-migration-e2e] repair ambiguous legacy row explicitly, then apply and verify through current migration\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE minecraft_sessions SET guard_sha256='' WHERE id='gmig-partial'" >/dev/null
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.log"

latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_after" == "0023_one_time_join_tickets_0143" ]] || { echo "unexpected post-upgrade migration: $latest_after" >&2; exit 1; }
sealed="$(psql "$DB_DSN" -Atqc "SELECT (checksum<>'')::text FROM schema_migrations WHERE version='0020_guard_migration_compatibility_stabilization_01310'")"
[[ "$sealed" == "true" ]]
serverbridge_sealed="$(psql "$DB_DSN" -Atqc "SELECT (checksum<>'')::text FROM schema_migrations WHERE version='0021_serverbridge_protocol_v2_0141'")"
identity_sealed="$(psql "$DB_DSN" -Atqc "SELECT (checksum<>'')::text FROM schema_migrations WHERE version='0022_serverbridge_crypto_node_identities_0142'")"
[[ "$serverbridge_sealed" == "true" ]]
serverbridge_table_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('server_bridge_nodes_v2','server_bridge_join_tickets_v2','server_bridge_textures_v2')")"
[[ "$serverbridge_table_count" == "3" ]]

printf '[guard-migration-e2e] prove snapshot shape/freshness constraints are live\n'
if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE minecraft_sessions SET integrity_verified=FALSE WHERE id='gmig-valid'" >/dev/null 2>&1; then
  echo '[guard-migration-e2e] snapshot shape constraint allowed verified flag downgrade with hashes retained' >&2
  exit 1
fi
if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE minecraft_sessions SET integrity_verified_at=created_at-interval '10 minutes' WHERE id='gmig-valid'" >/dev/null 2>&1; then
  echo '[guard-migration-e2e] snapshot freshness constraint allowed stale attestation' >&2
  exit 1
fi
constraint_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM pg_constraint WHERE conname IN ('minecraft_sessions_guard_snapshot_shape_01310','minecraft_sessions_guard_snapshot_freshness_01310')")"
[[ "$constraint_count" == "2" ]]

jq -n \
  --arg version "$VERSION" \
  --arg before "$latest_before" \
  --arg after "$latest_after" \
  --argjson constraints "$constraint_count" \
  '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after,sealedChecksum:true},failClosedPartialSnapshot:true,guardSnapshotConstraints:$constraints,serverBridgeV2Tables:3}' \
  > "$RESULT_DIR/migration-compatibility-stabilization.json"

printf '[guard-migration-e2e] PASS 0.13.9 -> current Guard migration + ServerBridge v2 schema\n'
