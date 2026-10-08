#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:18084}"
EMAIL="${NEVERLAUNCHER_TEST_ADMIN_EMAIL:-admin@neverlauncher.local}"
PASSWORD="${NEVERLAUNCHER_TEST_ADMIN_PASSWORD:-admin}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "neverlauncher-package-product-840" > "$TMP_DIR/example.jar"
TOKEN="$(curl -fsS -X POST "$BASE_URL/api/v1/admin/login" -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
if [[ -z "$TOKEN" ]]; then
  echo "Не удалось получить token" >&2
  exit 1
fi
PACKAGE_ID="$(curl -fsS -X POST "$BASE_URL/api/v1/packages" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"projectId\":\"demo-project\",\"profileId\":\"vanilla\",\"channel\":\"stable\",\"version\":\"${VERSION:-0.10.0}-smoke\"}" | sed -n 's/.*"packageId":"\([^"]*\)".*/\1/p')"
if [[ -z "$PACKAGE_ID" ]]; then
  echo "Не удалось создать package" >&2
  exit 1
fi
curl -fsS -X POST "$BASE_URL/api/v1/packages/$PACKAGE_ID/files" -H "Authorization: Bearer $TOKEN" -F "path=mods/example.jar" -F "file=@$TMP_DIR/example.jar" >/dev/null
curl -fsS -X POST "$BASE_URL/api/v1/packages/$PACKAGE_ID/validate" -H "Authorization: Bearer $TOKEN" | grep -q '"status":"valid"'
curl -fsS -X POST "$BASE_URL/api/v1/packages/$PACKAGE_ID/publish" -H "Authorization: Bearer $TOKEN" | grep -q '"status":"published"'
curl -fsS "$BASE_URL/api/v1/projects/demo-project/profiles/vanilla/manifest?channel=stable" | grep -q 'mods/example.jar'
echo "package product smoke OK: $PACKAGE_ID"
