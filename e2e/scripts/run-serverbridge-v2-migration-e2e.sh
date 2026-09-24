#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/serverbridge-v2-migration-runtime"
RESULT_DIR="$ROOT/e2e/serverbridge-v2-migration-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
PROJECT_NAME="neverlauncher-serverbridge-v2-migration"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[serverbridge-v2-migration] required command missing: $1" >&2; exit 1; }; }
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

printf '[serverbridge-v2-migration] materialize exact 0.14.0 database (0001..0020)\n'
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
  (( 10#$ordinal > 20 )) && continue
  migration_version="${base%.sql}"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  psql "$DB_DSN" -X -v ON_ERROR_STOP=1 -v version="$migration_version" -v checksum="$checksum" <<'SQL' >/dev/null
INSERT INTO schema_migrations(version,checksum,description)
VALUES(:'version',:'checksum',:'version');
SQL
done
latest_before="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_before" == "0020_guard_migration_compatibility_stabilization_01310" ]]

printf '[serverbridge-v2-migration] seed recoverable 0.14.0 snapshot state\n'
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO projects(id,name,default_channel) VALUES ('legacy-project','Legacy Project','stable');
INSERT INTO neverlauncher_persistence_snapshots_950(kind,schema_version,payload,created_at)
VALUES ('all','0.10.0', $json$
{
  "authSessions":[],
  "security":{"mfa":{},"failedLogins":{},"passwordResets":{},"emailTokens":{},"emailVerified":{},"recoveryUseLog":[]},
  "serverBridge":{
    "servers":{
      "legacy-paper":{"id":"legacy-paper","name":"Legacy Paper","kind":"paper","projectId":"legacy-project","profileId":"vanilla","fingerprint":"legacy-host","tokenPrefix":"nlsrv_legacy","status":"active","pluginVersion":"0.14.0","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","integrityStatus":"verified","createdAt":"2026-09-23T12:00:00Z"}
    },
    "joins":{
      "LegacyPlayer@legacy-paper":{"id":"legacy-join","username":"LegacyPlayer","uuid":"00000000-0000-0000-0000-000000000141","userId":"legacy-user","sessionId":"legacy-session","serverId":"legacy-paper","projectId":"legacy-project","profileId":"vanilla","channel":"stable","status":"active","createdAt":"2026-09-23T12:00:00Z","expiresAt":"2026-09-23T12:02:00Z"}
    },
    "textures":{
      "00000000-0000-0000-0000-000000000141":{"uuid":"00000000-0000-0000-0000-000000000141","username":"LegacyPlayer","skinUrl":"https://assets.invalid/skin.png","capeUrl":"","model":"slim","updatedAt":"2026-09-23T12:00:00Z"}
    }
  },
  "exportedAt":"2026-09-23T12:00:00Z"
}
$json$::jsonb, now());
SQL

( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.log"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.log"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.log"

latest_after="$(psql "$DB_DSN" -Atqc 'SELECT max(version) FROM schema_migrations')"
[[ "$latest_after" == "0022_serverbridge_crypto_node_identities_0142" ]]
node_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT protocol_version,status,token_hash,token_prefix,key_algorithm,public_key,key_fingerprint,identity_epoch,project_id,profile_id FROM server_bridge_nodes_v2 WHERE id='legacy-paper'")"
[[ "$node_state" == "2|identity-enrollment-required||||||0|legacy-project|vanilla" ]] || { echo "unexpected migrated node state: $node_state" >&2; exit 1; }
texture_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT username,model,skin_url FROM server_bridge_textures_v2 WHERE player_uuid='00000000-0000-0000-0000-000000000141'")"
[[ "$texture_state" == "LegacyPlayer|slim|https://assets.invalid/skin.png" ]] || { echo "unexpected migrated texture: $texture_state" >&2; exit 1; }
join_count="$(psql "$DB_DSN" -Atqc 'SELECT count(*) FROM server_bridge_join_tickets_v2')"
[[ "$join_count" == "0" ]] || { echo "legacy active join was migrated unsafely" >&2; exit 1; }

jq -n --arg version "$VERSION" --arg before "$latest_before" --arg after "$latest_after" \
  '{schemaVersion:"1",status:"passed",version:$version,upgrade:{fromMigration:$before,toMigration:$after},legacyNode:{status:"identity-enrollment-required",protocolVersion:2,bearerCredentialRetired:true,identityEnrollmentRequired:true},legacyTexturesImported:true,legacyActiveJoinsImported:false}' \
  > "$RESULT_DIR/serverbridge-v2-migration.json"
printf '[serverbridge-v2-migration] PASS 0.14.0 -> 0.14.2 snapshot + cryptographic identity migration semantics\n'
