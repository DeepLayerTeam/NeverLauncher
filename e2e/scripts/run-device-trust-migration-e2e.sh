#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/device-trust-migration-runtime"
RESULT_DIR="$ROOT/e2e/device-trust-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-device-trust-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[device-trust-migration-e2e] required command missing: $1" >&2; exit 1; }; }
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

printf '[device-trust-migration-e2e] start PostgreSQL and materialize exact 0.12.9 schema (0001..0017)\n'
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
  (( 10#$ordinal > 17 )) && continue
  version="${base%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description)
VALUES(:'version',:'checksum',:'version');
SQL
done

latest_before="$(psql "$DB_DSN" -Atqc "SELECT max(version) FROM schema_migrations")"
[[ "$latest_before" == "0017_device_key_recovery_rotation_0128" ]] || { echo "unexpected pre-upgrade migration: $latest_before" >&2; exit 1; }

printf '[device-trust-migration-e2e] seed valid 0.12.9 legacy states and prove replacement challenge is blocked before 0018\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO users(id,email,display_name,role_id,status) VALUES
 ('dtmig-user','dtmig@example.invalid','DT Migration','player','active'),
 ('dtmig-other','dtmig-other@example.invalid','DT Migration Other','player','active');
INSERT INTO auth_identities(id,user_id,provider,subject) VALUES
 ('identity-local-dtmig-user','dtmig-user','local','dtmig-user'),
 ('identity-local-dtmig-other','dtmig-other','local','dtmig-other');

INSERT INTO trusted_devices(
 id,user_id,name,status,trust_state,assurance,key_algorithm,key_binding,hardware_provider,
 attestation_state,attestation_method,public_key,key_fingerprint,platform,client_version,
 created_at,updated_at,last_ip,last_user_agent,revoked_reason,replaced_at,replaced_by_device_id,replacement_reason
) VALUES
 ('dtmig-new','dtmig-user','Current device','active','verified','proof-of-possession','ed25519','software','',
  'unattested','','legacy-public-key-new',repeat('1',64),'linux','0.12.9',now(),now(),'127.0.0.1','migration-e2e','',NULL,'',''),
 ('dtmig-old','dtmig-user','Legacy rotated device','revoked','revoked','proof-of-possession','ed25519','software','',
  'unattested','','legacy-public-key-old',repeat('2',64),'linux','0.12.8',now()-interval '1 day',now()-interval '1 hour','','','',now()-interval '1 hour','dtmig-new','rotate'),
 ('dtmig-other-device','dtmig-other','Other device','active','verified','proof-of-possession','ed25519','software','',
  'unattested','','legacy-public-key-other',repeat('3',64),'linux','0.12.9',now(),now(),'','','',NULL,'','');

INSERT INTO auth_sessions(
 id,user_id,email,role_id,device_id,device,status,refresh_family_id,created_at,last_seen_at,expires_at,
 trusted_device_id,device_trust_state,device_verified_at,binding_epoch
) VALUES
 ('dtmig-session','dtmig-user','dtmig@example.invalid','player','legacy','Migration E2E','active','dtmig-family',now(),now(),now()+interval '1 day','dtmig-new','verified',now(),2),
 ('dtmig-other-session','dtmig-other','dtmig-other@example.invalid','player','legacy','Other E2E','active','dtmig-other-family',now(),now(),now()+interval '1 day',NULL,'unverified',NULL,1);
INSERT INTO refresh_token_families(id,session_id,user_id,status) VALUES
 ('dtmig-family','dtmig-session','dtmig-user','active'),
 ('dtmig-other-family','dtmig-other-session','dtmig-other','active');
INSERT INTO minecraft_profiles(user_id,uuid,name) VALUES
 ('dtmig-user','00000000-0000-0000-0000-000000000101','DTMigUser');
INSERT INTO minecraft_sessions(
 id,user_id,never_session_id,profile_uuid,trusted_device_id,binding_epoch,client_token,access_token_hash,status,created_at,last_seen_at,expires_at
) VALUES
 ('dtmig-mc-unbound','dtmig-user','dtmig-session','00000000-0000-0000-0000-000000000101','',1,'legacy-client',repeat('a',64),'active',now(),now(),now()+interval '1 hour');
INSERT INTO device_challenges(id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at)
VALUES('dtmig-expired','dtmig-user','dtmig-new','attest',repeat('b',64),'{}'::jsonb,now()-interval '2 hours',now()-interval '1 hour');
COMMIT;
SQL

if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "INSERT INTO device_challenges(id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at) VALUES('dtmig-pre-rotate','dtmig-user','dtmig-old','key-rotate',repeat('c',64),'{}'::jsonb,now(),now()+interval '5 minutes')" >/dev/null 2>&1; then
  echo '[device-trust-migration-e2e] 0.12.9 unexpectedly accepted key-rotate purpose' >&2
  exit 1
fi

printf '[device-trust-migration-e2e] upgrade with shipping CLI and verify sealed 0018\n'
( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.json"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.json"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.json"

latest_after="$(psql "$DB_DSN" -Atqc "SELECT max(version) FROM schema_migrations")"
shipping_latest="$(find "$ROOT/services/api/internal/dbmigrate/sql" -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | sort | tail -n1 | sed 's/\.sql$//')"
[[ -n "$shipping_latest" && "$latest_after" == "$shipping_latest" ]] || { echo "unexpected post-upgrade migration: db=$latest_after shipping=$shipping_latest" >&2; exit 1; }
sealed="$(psql "$DB_DSN" -Atqc "SELECT (checksum<>'' AND description<>'')::text FROM schema_migrations WHERE version='0018_device_trust_stabilization_01210'")"
[[ "$sealed" == "true" ]]

printf '[device-trust-migration-e2e] verify normalization and new relational boundaries\n'
legacy_revoked="$(psql "$DB_DSN" -Atqc "SELECT (attestation_state='revoked' AND assurance='proof-of-possession' AND revoked_at IS NOT NULL AND revoked_reason<>'')::text FROM trusted_devices WHERE id='dtmig-old'")"
[[ "$legacy_revoked" == "true" ]]
replacement_null="$(psql "$DB_DSN" -Atqc "SELECT (replaced_by_device_id IS NULL)::text FROM trusted_devices WHERE id='dtmig-new'")"
[[ "$replacement_null" == "true" ]]
legacy_mc_null="$(psql "$DB_DSN" -Atqc "SELECT (trusted_device_id IS NULL)::text FROM minecraft_sessions WHERE id='dtmig-mc-unbound'")"
[[ "$legacy_mc_null" == "true" ]]
expired_consumed="$(psql "$DB_DSN" -Atqc "SELECT (consumed_at IS NOT NULL)::text FROM device_challenges WHERE id='dtmig-expired'")"
[[ "$expired_consumed" == "true" ]]

psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "INSERT INTO device_challenges(id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at) VALUES('dtmig-post-rotate','dtmig-user','dtmig-old','key-rotate',repeat('d',64),'{}'::jsonb,now(),now()+interval '5 minutes')" >/dev/null
psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "INSERT INTO device_challenges(id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at) VALUES('dtmig-post-recover','dtmig-user','dtmig-old','key-recover',repeat('e',64),'{}'::jsonb,now(),now()+interval '5 minutes')" >/dev/null

if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE auth_sessions SET trusted_device_id='dtmig-new',device_trust_state='verified',device_verified_at=now() WHERE id='dtmig-other-session'" >/dev/null 2>&1; then
  echo '[device-trust-migration-e2e] cross-user auth session/device binding unexpectedly succeeded' >&2
  exit 1
fi
if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE trusted_devices SET replaced_by_device_id='dtmig-other-device' WHERE id='dtmig-old'" >/dev/null 2>&1; then
  echo '[device-trust-migration-e2e] cross-user replacement link unexpectedly succeeded' >&2
  exit 1
fi
if psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "UPDATE minecraft_sessions SET trusted_device_id='dtmig-other-device' WHERE id='dtmig-mc-unbound'" >/dev/null 2>&1; then
  echo '[device-trust-migration-e2e] cross-user Minecraft device snapshot unexpectedly succeeded' >&2
  exit 1
fi

constraint_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM pg_constraint WHERE conname IN ('auth_sessions_trusted_device_owner_fk','trusted_devices_replacement_owner_fk','minecraft_sessions_never_session_owner_fk','minecraft_sessions_device_owner_fk','minecraft_sessions_profile_owner_fk','trusted_devices_replacement_shape_check','auth_sessions_device_binding_shape_check')")"
[[ "$constraint_count" == "7" ]]

jq -n \
  --arg version "$VERSION" \
  --arg before "$latest_before" \
  --arg after "$latest_after" \
  --argjson constraints "$constraint_count" \
  '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after,sealedChecksum:true},normalization:{revokedDevice:true,emptyReplacementToNull:true,emptyMinecraftDeviceToNull:true,expiredChallengeConsumed:true},replacementChallenges:{pre01210Rejected:true,keyRotateAccepted:true,keyRecoverAccepted:true},ownershipEnforcement:{authSessionDevice:true,replacementChain:true,minecraftDevice:true,constraints:$constraints}}' \
  > "$RESULT_DIR/migration-stabilization.json"

printf '[device-trust-migration-e2e] PASS 0.12.9 -> 0.12.10 migration + stabilization\n'
