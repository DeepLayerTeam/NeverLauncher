#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/one-time-join-migration-runtime"
RESULT_DIR="$ROOT/e2e/one-time-join-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-one-time-join-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[one-time-join-migration] required command missing: $1" >&2; exit 1; }; }
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

printf '[one-time-join-migration] materialize exact 0.14.2 database through migration 0022\n'
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
  (( 10#$ordinal > 22 )) && continue
  migration_version="${base%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description)
VALUES(:'version',:'checksum',:'version');
SQL
done
latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_before" == "0022_serverbridge_crypto_node_identities_0142" ]]

printf '[one-time-join-migration] seed replayable 0.14.2 ServerBridge and Yggdrasil joins\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO projects(id,name,default_channel) VALUES ('ticket-project','Ticket Project','stable');
INSERT INTO users(id,email,display_name,role_id,status) VALUES ('ticket-user','ticket-user@example.invalid','Ticket User','player','active');
INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,device,status,refresh_family_id,expires_at)
VALUES ('ticket-session','ticket-user','ticket-user@example.invalid','player','','e2e','active','ticket-family',now()+interval '1 hour');
INSERT INTO minecraft_profiles(user_id,uuid,name)
VALUES ('ticket-user','00000000-0000-0000-0000-000000000143','TicketPlayer');
INSERT INTO minecraft_sessions(id,user_id,never_session_id,profile_uuid,access_token_hash,status,expires_at)
VALUES ('minecraft-ticket-session','ticket-user','ticket-session','00000000-0000-0000-0000-000000000143',repeat('d',64),'active',now()+interval '1 hour');
INSERT INTO server_bridge_nodes_v2(
  id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,
  key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,created_at
) VALUES (
  'paper-0142','Paper 0142','paper','ticket-project','vanilla','host-fingerprint','','','active',2,
  'ed25519',repeat('A',43),repeat('a',64),1,now(),now()-interval '5 minutes'
);
INSERT INTO server_bridge_join_tickets_v2(
  id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,
  access_token_hash,binding_epoch,minecraft_session_id,protocol_version,status,created_at,expires_at
) VALUES (
  'legacy-ticket-0142','TicketPlayer','ticketplayer','00000000-0000-0000-0000-000000000143',
  'ticket-user','ticket-session','paper-0142','ticket-project','vanilla','stable',repeat('c',64),1,
  'minecraft-ticket-session',2,'active',now(),now()+interval '2 minutes'
);
INSERT INTO minecraft_joins(username,username_normalized,profile_uuid,user_id,minecraft_session_id,server_id,ip,created_at,expires_at)
VALUES ('TicketPlayer','ticketplayer','00000000-0000-0000-0000-000000000143','ticket-user','minecraft-ticket-session','legacy-yggdrasil-0142','127.0.0.1',now(),now()+interval '2 minutes');
SQL

( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.log"
latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_after" == "0023_one_time_join_tickets_0143" ]]

legacy_bridge_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT ticket_version,status,(invalidated_at IS NOT NULL)::text,issued_identity_epoch,issued_key_fingerprint FROM server_bridge_join_tickets_v2 WHERE id='legacy-ticket-0142'")"
[[ "$legacy_bridge_state" == "1|invalidated|t|0|" ]] || { echo "0.14.2 ServerBridge ticket survived one-time boundary: $legacy_bridge_state" >&2; exit 1; }
legacy_yggdrasil_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM minecraft_joins")"
[[ "$legacy_yggdrasil_count" == "0" ]] || { echo "replayable 0.14.2 Yggdrasil joins survived migration" >&2; exit 1; }

bridge_nonce_index="$(psql "$DB_DSN" -Atqc "SELECT to_regclass('uq_server_bridge_join_v2_redemption_nonce_0143') IS NOT NULL")"
[[ "$bridge_nonce_index" == "t" ]] || { echo "ServerBridge redemption nonce index missing" >&2; exit 1; }
yggdrasil_index="$(psql "$DB_DSN" -Atqc "SELECT to_regclass('idx_minecraft_joins_active_expires_0143') IS NOT NULL")"
[[ "$yggdrasil_index" == "t" ]] || { echo "Yggdrasil active expiry index missing" >&2; exit 1; }

printf '[one-time-join-migration] prove new v2 ticket identity binding and redemption constraints\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO server_bridge_join_tickets_v2(
  id,ticket_version,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,
  access_token_hash,binding_epoch,minecraft_session_id,protocol_version,issued_identity_epoch,issued_key_fingerprint,
  status,created_at,expires_at
) VALUES (
  'ticket-v2-0143',2,'TicketPlayer','ticketplayer','00000000-0000-0000-0000-000000000143',
  'ticket-user','ticket-session','paper-0142','ticket-project','vanilla','stable',repeat('c',64),1,
  'minecraft-ticket-session',2,1,repeat('a',64),'active',now(),now()+interval '2 minutes'
);
UPDATE server_bridge_join_tickets_v2
SET status='consumed', consumed_at=now(), redeemed_identity_epoch=1,
    redeemed_key_fingerprint=repeat('a',64), redeemed_nonce_hash=repeat('b',64), redeemed_by_ip='127.0.0.1'
WHERE id='ticket-v2-0143';
SQL
v2_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT ticket_version,status,issued_identity_epoch,(issued_key_fingerprint=redeemed_key_fingerprint)::text,length(redeemed_nonce_hash) FROM server_bridge_join_tickets_v2 WHERE id='ticket-v2-0143'")"
[[ "$v2_state" == "2|consumed|1|t|64" ]] || { echo "unexpected v2 one-time ticket state: $v2_state" >&2; exit 1; }

jq -n --arg version "$VERSION" --arg before "$latest_before" --arg after "$latest_after" \
  '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after},legacyServerBridgeTicketInvalidated:true,legacyYggdrasilJoinsDiscarded:true,identityBoundTicketVersion:2,redemptionProofPersisted:true}' \
  > "$RESULT_DIR/one-time-join-ticket-migration.json"
printf '[one-time-join-migration] PASS 0.14.2 -> 0.14.3 one-time join ticket migration semantics\n'
