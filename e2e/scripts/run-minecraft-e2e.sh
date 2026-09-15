#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.minecraft-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/runtime"
ENV_FILE="$RUNTIME_DIR/e2e.env"
API="${NEVERLAUNCHER_E2E_API:-http://127.0.0.1:18080}"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55432/neverlauncher?sslmode=disable"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PINNED_PUBLIC_KEY="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
ADMIN_EMAIL="admin@neverlauncher.local"
ADMIN_PASSWORD="$(python3 -c 'import secrets; print("E2E-" + secrets.token_urlsafe(24))')"
PLAYER_USERNAME="E2EPlayer"
VERSION="0.10.4"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[e2e] required command missing: $1" >&2; exit 1; }; }
for cmd in docker curl jq go javac jar cargo python3 gradle; do need "$cmd"; done
docker compose version >/dev/null

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/plugins/velocity" "$RUNTIME_DIR/plugins/paper" "$RUNTIME_DIR/plugins/purpur" "$RUNTIME_DIR/client" "$RUNTIME_DIR/fixture/src/ru/neverlauncher/e2e"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
VELOCITY_SERVER_TOKEN=token-not-initialized
PAPER_SERVER_TOKEN=token-not-initialized
PURPUR_SERVER_TOKEN=token-not-initialized
ENV

compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_http() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "[e2e] timeout waiting for $url" >&2
  compose logs neverlauncher-api >&2 || true
  return 1
}
wait_healthy() {
  local service="$1" id status
  id="$(compose ps -q "$service")"
  [[ -n "$id" ]] || { echo "[e2e] $service container not found" >&2; return 1; }
  for _ in $(seq 1 120); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)"
    [[ "$status" == "healthy" ]] && return 0
    [[ "$status" == "exited" || "$status" == "dead" ]] && break
    sleep 3
  done
  echo "[e2e] $service did not become healthy" >&2
  compose logs "$service" >&2 || true
  return 1
}
capture_health_evidence() {
  local service="$1" id out
  id="$(compose ps -q "$service")"
  [[ -n "$id" ]] || { echo "[e2e] $service container not found for health evidence" >&2; return 1; }
  out="$RUNTIME_DIR/health-$service.json"
  docker inspect --format '{{json .State.Health}}' "$id" > "$out"
  jq -e '.Status == "healthy" and .FailingStreak == 0 and (.Log | length) > 0 and .Log[-1].ExitCode == 0' "$out" >/dev/null || {
    echo "[e2e] $service health evidence is not healthy" >&2
    cat "$out" >&2
    return 1
  }
}

wait_log() {
  local service="$1" pattern="$2"
  for _ in $(seq 1 30); do
    if compose logs --no-color "$service" 2>&1 | grep -Fq "$pattern"; then return 0; fi
    sleep 1
  done
  echo "[e2e] $service log marker missing: $pattern" >&2
  compose logs "$service" >&2 || true
  return 1
}
json_post() {
  local url="$1" token="$2" body="$3"
  curl -fsS -H 'Content-Type: application/json' ${token:+-H "Authorization: Bearer $token"} -d "$body" "$url"
}

printf '[e2e] build real ServerBridge artifacts\n'
bash "$ROOT/scripts/build/bridge-plugins.sh"
cp "$ROOT/artifacts/plugins/neverlauncher-velocity-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/velocity/neverlauncher-velocity-bridge.jar"
cp "$ROOT/artifacts/plugins/neverlauncher-paper-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/paper/neverlauncher-paper-bridge.jar"
cp "$ROOT/artifacts/plugins/neverlauncher-purpur-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/purpur/neverlauncher-purpur-bridge.jar"

printf '[e2e] start PostgreSQL and apply production migrations explicitly\n'
compose up -d postgres
wait_healthy postgres
(
  cd "$ROOT/cli"
  go build -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher
)
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN"

printf '[e2e] start production-configured API with auto-migrate disabled\n'
compose up -d --build neverlauncher-api
wait_http "$API/health"

printf '[e2e] one-time bootstrap and canonical /api/v1 login\n'
curl -fsS -H 'Content-Type: application/json' -H "X-NeverLauncher-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"displayName\":\"E2E Owner\",\"password\":\"$ADMIN_PASSWORD\",\"actor\":\"github-actions\"}" \
  "$API/api/v1/install/bootstrap-admin" > "$RUNTIME_DIR/bootstrap.json"
LOGIN="$(curl -fsS -H 'Content-Type: application/json' -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "$API/api/v1/admin/login")"
ACCESS_TOKEN="$(jq -er '.token' <<<"$LOGIN")"
json_post "$API/api/v1/install/first-project" "$ACCESS_TOKEN" '{"projectId":"e2e-project","profileId":"vanilla","channel":"stable","version":"0.0.1-bootstrap","actor":"github-actions"}' > "$RUNTIME_DIR/first-project.json"

register_server() {
  local id="$1" kind="$2"
  json_post "$API/api/v1/server-bridge/servers/register" "$ACCESS_TOKEN" "{\"id\":\"$id\",\"name\":\"$id\",\"kind\":\"$kind\",\"projectId\":\"e2e-project\",\"profileId\":\"vanilla\"}" | jq -er '.data.serverToken'
}
VELOCITY_TOKEN="$(register_server velocity-e2e-p3 velocity)"
PAPER_TOKEN="$(register_server paper-e2e-p3 paper)"
PURPUR_TOKEN="$(register_server purpur-e2e-p3 purpur)"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
VELOCITY_SERVER_TOKEN=$VELOCITY_TOKEN
PAPER_SERVER_TOKEN=$PAPER_TOKEN
PURPUR_SERVER_TOKEN=$PURPUR_TOKEN
ENV

printf '[e2e] start real Velocity 3.4.0, Paper 1.21.1 and Purpur 1.21.1\n'
compose up -d velocity paper purpur
wait_healthy velocity
wait_healthy paper
wait_healthy purpur
for service in velocity paper purpur; do
  capture_health_evidence "$service"
done
for service in velocity paper purpur; do
  if ! compose logs "$service" | grep -Eqi 'NeverLauncher .* Bridge .*heartbeat=true'; then
    echo "[e2e] $service NeverLauncher bridge did not report successful heartbeat" >&2
    compose logs "$service" >&2
    exit 1
  fi
done

printf '[e2e] build a real Java launch fixture JAR\n'
cat > "$RUNTIME_DIR/fixture/src/ru/neverlauncher/e2e/LaunchFixture.java" <<'JAVA'
package ru.neverlauncher.e2e;
public final class LaunchFixture {
    public static void main(String[] args) {
        System.out.println("NEVERLAUNCHER_E2E_FIXTURE_OK");
    }
}
JAVA
mkdir -p "$RUNTIME_DIR/fixture/classes"
javac --release 17 -d "$RUNTIME_DIR/fixture/classes" "$RUNTIME_DIR/fixture/src/ru/neverlauncher/e2e/LaunchFixture.java"
jar --create --file "$RUNTIME_DIR/fixture/neverlauncher-e2e-fixture.jar" -C "$RUNTIME_DIR/fixture/classes" .

printf '[e2e] publish package through canonical API\n'
RELEASE="$(json_post "$API/api/v1/admin/projects/e2e-project/versions" "$ACCESS_TOKEN" '{"profileId":"vanilla","channel":"stable","version":"0.10.4-e2e"}')"
VERSION_ID="$(jq -er '.id' <<<"$RELEASE")"
json_post "$API/api/v1/admin/projects/e2e-project/versions/$VERSION_ID/manifest" "$ACCESS_TOKEN" '{"minecraft":{"version":"1.21.1","loader":"fixture","mainClass":"ru.neverlauncher.e2e.LaunchFixture","gameArgs":[]},"runtime":{"java":{"majorVersion":17,"distribution":"temurin","allowCustomPath":true},"jvmArgs":[],"memory":{"minimumMb":64,"recommendedMb":128,"maximumMb":256},"launch":{"mainClass":"ru.neverlauncher.e2e.LaunchFixture","classpathStrategy":"manifest","nativesDirectory":"natives","offlineMode":true}},"directories":{"game":".","assets":"assets","libraries":"libraries","natives":"natives"}}' > "$RUNTIME_DIR/manifest-draft.json"
curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" \
  -F 'path=libraries/neverlauncher-e2e-fixture.jar' \
  -F "file=@$RUNTIME_DIR/fixture/neverlauncher-e2e-fixture.jar;type=application/java-archive" \
  "$API/api/v1/admin/projects/e2e-project/versions/$VERSION_ID/files" > "$RUNTIME_DIR/upload.json"
curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" -X POST \
  "$API/api/v1/admin/projects/e2e-project/versions/$VERSION_ID/publish" > "$RUNTIME_DIR/published.json"
MANIFEST_URL="$API/api/v1/projects/e2e-project/profiles/vanilla/manifest?channel=stable"
curl -fsS "$MANIFEST_URL" > "$RUNTIME_DIR/manifest.json"
jq -e --arg key "$PINNED_PUBLIC_KEY" '.signature.algorithm == "Ed25519" and .signature.publicKey == $key and (.signature.signature|length == 128)' "$RUNTIME_DIR/manifest.json" >/dev/null

printf '[e2e] NeverRuntime pinned Ed25519 verify -> download/SHA-256 -> launch fixture\n'
(
  cd "$ROOT"
  cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- verify \
    --manifest "$RUNTIME_DIR/manifest.json" --pinned-public-key "$PINNED_PUBLIC_KEY" > "$RUNTIME_DIR/runtime-verify.json"
  cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- sync \
    --manifest-url "$MANIFEST_URL" --pinned-public-key "$PINNED_PUBLIC_KEY" --root "$RUNTIME_DIR/client" > "$RUNTIME_DIR/runtime-sync.json"
  cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- launch \
    --manifest "$RUNTIME_DIR/manifest.json" --pinned-public-key "$PINNED_PUBLIC_KEY" --root "$RUNTIME_DIR/client" \
    --java "$(command -v java)" --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/runtime-launch.json"
)
jq -e '.status == "ready" and .download.failed == 0' "$RUNTIME_DIR/runtime-sync.json" >/dev/null
jq -e '.success == true and (.stdout | contains("NEVERLAUNCHER_E2E_FIXTURE_OK"))' "$RUNTIME_DIR/runtime-launch.json" >/dev/null

printf '[e2e] join -> allow -> revoke -> deny on all real bridge registrations\n'
validate_join() {
  local id="$1" token="$2" expect="$3" out="$RUNTIME_DIR/validate-$id-$expect.json" code
  code="$(curl -sS -o "$out" -w '%{http_code}' -H 'Content-Type: application/json' -H "X-NeverLauncher-Server-Token: $token" \
    -d "{\"serverId\":\"$id\",\"username\":\"$PLAYER_USERNAME\",\"projectId\":\"e2e-project\",\"profileId\":\"vanilla\",\"channel\":\"stable\"}" \
    "$API/api/v1/server-bridge/validate-join")"
  if [[ "$expect" == allow ]]; then
    [[ "$code" == 200 ]] && jq -e '.data.allowed == true' "$out" >/dev/null
  else
    [[ "$code" == 403 ]] && jq -e '.data.allowed == false and .data.reason == "launcher_session_missing_or_expired"' "$out" >/dev/null
  fi
}
flow_for_server() {
  local id="$1" token="$2" service="$3" port="$4"
  json_post "$API/api/v1/session/join" "$ACCESS_TOKEN" "{\"username\":\"$PLAYER_USERNAME\",\"serverId\":\"$id\",\"projectId\":\"e2e-project\",\"profileId\":\"vanilla\",\"channel\":\"stable\"}" > "$RUNTIME_DIR/join-$id.json"
  validate_join "$id" "$token" allow
  python3 "$ROOT/e2e/scripts/minecraft-login-probe.py" --port "$port" --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/probe-$id-allow.txt"
  wait_log "$service" "neverlauncher.join.allowed username=$PLAYER_USERNAME"
  json_post "$API/api/v1/session/invalidate" "$ACCESS_TOKEN" "{\"serverId\":\"$id\",\"reason\":\"e2e-revoke\"}" > "$RUNTIME_DIR/revoke-$id.json"
  validate_join "$id" "$token" deny
  python3 "$ROOT/e2e/scripts/minecraft-login-probe.py" --port "$port" --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/probe-$id-deny.txt"
  wait_log "$service" "neverlauncher.join.denied username=$PLAYER_USERNAME"
}

flow_for_server velocity-e2e-p3 "$VELOCITY_TOKEN" velocity 25570
flow_for_server paper-e2e-p3 "$PAPER_TOKEN" paper 25571
flow_for_server purpur-e2e-p3 "$PURPUR_TOKEN" purpur 25572

curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" "$API/api/v1/server-bridge/diagnostics" > "$RUNTIME_DIR/bridge-diagnostics.json"
cat > "$RUNTIME_DIR/result.json" <<JSON
{"version":"$VERSION","status":"passed","health":{"velocity":"healthy","paper":"healthy","purpur":"healthy"},"evidence":["health-velocity.json","health-paper.json","health-purpur.json","bridge-diagnostics.json"],"flow":["postgres-migrate","api-bootstrap","real-velocity","real-paper","real-purpur","container-healthchecks","bridge-heartbeat","publish","ed25519-verify","download-sha256","launch-fixture","minecraft-protocol-join","plugin-allow","revoke","minecraft-protocol-rejoin","plugin-deny"]}
JSON
printf '[e2e] PASS %s\n' "$(cat "$RUNTIME_DIR/result.json")"
