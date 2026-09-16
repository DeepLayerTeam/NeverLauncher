#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/runtime-federation"
ENV_FILE="$RUNTIME_DIR/e2e.env"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
ADMIN_EMAIL="federation-e2e@neverlauncher.local"
ADMIN_PASSWORD="$(python3 -c 'import secrets; print("E2E-" + secrets.token_urlsafe(24))')"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[federation-postgres-e2e] required command missing: $1" >&2; exit 1; }; }
for cmd in docker curl jq go psql python3; do need "$cmd"; done
docker compose version >/dev/null

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
ENV
compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_http() {
  local url="$1" service="$2"
  for _ in $(seq 1 90); do
    if curl -fsS "$url/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  compose logs "$service" >&2 || true
  echo "[federation-postgres-e2e] timeout waiting for $url" >&2
  return 1
}
json_post() {
  local url="$1" token="$2" body="$3"
  curl -fsS -H 'Content-Type: application/json' ${token:+-H "Authorization: Bearer $token"} -d "$body" "$url"
}

printf '[federation-postgres-e2e] build CLI and start PostgreSQL/Redis\n'
( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
compose up -d postgres redis volume-init
for _ in $(seq 1 60); do
  if psql "$DB_DSN" -Atqc 'select 1' >/dev/null 2>&1; then break; fi
  sleep 1
done
psql "$DB_DSN" -Atqc 'select 1' >/dev/null

printf '[federation-postgres-e2e] explicit migration apply + sealed verification\n'
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.json"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.json"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.json"
psql "$DB_DSN" -Atqc "SELECT 1 FROM schema_migrations WHERE version='0011_auth_federation_release_0120' AND checksum<>''" | grep -qx '1'

printf '[federation-postgres-e2e] start three Backend instances sharing PostgreSQL/Redis\n'
compose up -d --build api-a api-b api-c
wait_http http://127.0.0.1:18081 api-a
wait_http http://127.0.0.1:18082 api-b
wait_http http://127.0.0.1:18083 api-c

curl -fsS -H 'Content-Type: application/json' -H "X-NeverLauncher-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"displayName\":\"Federation E2E\",\"password\":\"$ADMIN_PASSWORD\",\"actor\":\"federation-e2e\"}" \
  http://127.0.0.1:18081/api/v1/install/bootstrap-admin > "$RUNTIME_DIR/bootstrap.json"

local_identity_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM users u JOIN auth_identities ai ON ai.user_id=u.id AND ai.provider='local' AND ai.subject=u.id WHERE lower(u.email)=lower('$ADMIN_EMAIL') AND btrim(u.password_hash)<>''")"
[[ "$local_identity_count" == "1" ]] || { echo "canonical local identity invariant failed: $local_identity_count" >&2; exit 1; }

login="$(curl -fsS -H 'Content-Type: application/json' -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"deviceId\":\"e2e-a\"}" http://127.0.0.1:18081/api/v1/auth/login)"
access_a="$(jq -er '.data.tokens.accessToken' <<<"$login")"
refresh_a="$(jq -er '.data.tokens.refreshToken' <<<"$login")"

printf '[federation-postgres-e2e] promote external-only user to local password auth transactionally\n'
EXTERNAL_USER_ID="user-federation-external-e2e"
psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "INSERT INTO users(id,email,display_name,role_id,status,project_roles,password_hash,created_at,updated_at) VALUES('$EXTERNAL_USER_ID','external-e2e@neverlauncher.local','External E2E','player','active','{}'::jsonb,'',now(),now()) ON CONFLICT(id) DO NOTHING; INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at) VALUES('identity-http-e2e','$EXTERNAL_USER_ID','http-e2e','subject-e2e','external-e2e@neverlauncher.local','external-e2e','External E2E','{}'::jsonb,now(),now()) ON CONFLICT DO NOTHING;" >/dev/null
json_post http://127.0.0.1:18081/api/v1/admin/users/$EXTERNAL_USER_ID/password "$access_a" '{"password":"Federation-E2E-Local-Password-0120"}' > "$RUNTIME_DIR/password-promotion.json"
promoted_local_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM auth_identities WHERE user_id='$EXTERNAL_USER_ID' AND provider='local' AND subject='$EXTERNAL_USER_ID'")"
[[ "$promoted_local_count" == "1" ]] || { echo "password promotion did not create canonical local identity: $promoted_local_count" >&2; exit 1; }

printf '[federation-postgres-e2e] restart login instance and refresh persisted session\n'
compose restart api-a >/dev/null
wait_http http://127.0.0.1:18081 api-a
rotated="$(json_post http://127.0.0.1:18081/api/v1/auth/refresh '' "{\"refreshToken\":\"$refresh_a\"}")"
access_1="$(jq -er '.data.tokens.accessToken' <<<"$rotated")"
refresh_1="$(jq -er '.data.tokens.refreshToken' <<<"$rotated")"
[[ "$refresh_1" != "$refresh_a" ]]

printf '[federation-postgres-e2e] refresh on Backend-B and validate access on Backend-C\n'
rotated_b="$(json_post http://127.0.0.1:18082/api/v1/auth/refresh '' "{\"refreshToken\":\"$refresh_1\"}")"
access_b="$(jq -er '.data.tokens.accessToken' <<<"$rotated_b")"
refresh_b="$(jq -er '.data.tokens.refreshToken' <<<"$rotated_b")"
curl -fsS -H "Authorization: Bearer $access_b" http://127.0.0.1:18083/api/v1/auth/accounts > "$RUNTIME_DIR/accounts-c.json"

printf '[federation-postgres-e2e] replay old refresh on Backend-C must compromise family globally\n'
code="$(curl -sS -o "$RUNTIME_DIR/replay.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$refresh_1\"}" http://127.0.0.1:18083/api/v1/auth/refresh)"
[[ "$code" == "401" ]]
for base in http://127.0.0.1:18081 http://127.0.0.1:18082 http://127.0.0.1:18083; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $access_b" "$base/api/v1/auth/accounts")"
  [[ "$code" == "401" ]] || { echo "compromised family accepted on $base: $code" >&2; exit 1; }
done
code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$refresh_b\"}" http://127.0.0.1:18082/api/v1/auth/refresh)"
[[ "$code" == "401" ]]

printf '[federation-postgres-e2e] verify database remains migration-clean after runtime traffic\n'
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify-after.json"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify-after.json"

jq -n --arg version "$VERSION" '{schemaVersion:"1",toolVersion:$version,status:"passed",checks:{migrationApply:true,migrationVerify:true,restartPersistence:true,multiInstanceRefresh:true,replayCompromisePropagation:true,localIdentityInvariant:true,passwordPromotionIdentityInvariant:true}}' > "$RUNTIME_DIR/result.json"
printf '[federation-postgres-e2e] PASS %s\n' "$(cat "$RUNTIME_DIR/result.json")"
