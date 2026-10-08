#!/usr/bin/env bash
set -euo pipefail

BACKEND="${1:-http://127.0.0.1:8080}"
EMAIL="${NEVERLAUNCHER_TEST_ADMIN_EMAIL:-admin@neverlauncher.local}"
PASSWORD="${NEVERLAUNCHER_TEST_ADMIN_PASSWORD:-admin}"
TS="$(date +%s)"
PROJECT="crud-${TS}"
PROFILE="vanilla"
CHANNEL="stable"
USER_EMAIL="operator-${TS}@neverlauncher.local"

login_json="$(curl -fsS -X POST "$BACKEND/api/v1/admin/login" -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
TOKEN="$(printf '%s' "$login_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
AUTH=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')

curl -fsS -X POST "$BACKEND/api/v1/admin/projects" "${AUTH[@]}" -d "{\"id\":\"$PROJECT\",\"name\":\"CRUD Project\",\"defaultChannel\":\"stable\"}" >/dev/null
curl -fsS -X PATCH "$BACKEND/api/v1/admin/projects/$PROJECT" "${AUTH[@]}" -d '{"description":"patched by 9.9 smoke"}' >/dev/null
curl -fsS -X POST "$BACKEND/api/v1/admin/projects/$PROJECT/profiles" "${AUTH[@]}" -d "{\"id\":\"$PROFILE\",\"name\":\"Vanilla\",\"loader\":\"vanilla\"}" >/dev/null
curl -fsS -X PATCH "$BACKEND/api/v1/admin/projects/$PROJECT/profiles/$PROFILE" "${AUTH[@]}" -d '{"description":"profile patched"}' >/dev/null
curl -fsS -X POST "$BACKEND/api/v1/admin/projects/$PROJECT/channels" "${AUTH[@]}" -d "{\"id\":\"$CHANNEL\",\"name\":\"stable\",\"protected\":true}" >/dev/null
curl -fsS -X PATCH "$BACKEND/api/v1/admin/projects/$PROJECT/channels/$CHANNEL" "${AUTH[@]}" -d '{"description":"channel patched","protected":true}' >/dev/null
user_json="$(curl -fsS -X POST "$BACKEND/api/v1/admin/users" "${AUTH[@]}" -d "{\"email\":\"$USER_EMAIL\",\"displayName\":\"Smoke Operator\",\"roleId\":\"viewer\",\"password\":\"ChangeMe-0.10.0\"}")"
USER_ID="$(printf '%s' "$user_json" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("id") or data.get("data",{}).get("user",{}).get("id") or data.get("user",{}).get("id"))')"
curl -fsS -X POST "$BACKEND/api/v1/admin/users/$USER_ID/disable" "${AUTH[@]}" >/dev/null
curl -fsS -X POST "$BACKEND/api/v1/admin/users/$USER_ID/enable" "${AUTH[@]}" >/dev/null
curl -fsS "$BACKEND/api/v1/admin/audit" "${AUTH[@]}" >/dev/null

echo "NeverLauncher ${VERSION:-0.10.0} admin CRUD smoke: OK"
