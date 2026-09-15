#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
cd "${ROOT_DIR}"

grep -q "var version = \"${VERSION}\"" cli/cmd/neverlauncher/main.go
grep -q "var version = \"${VERSION}\"" services/api/cmd/neverlauncher-api/main.go
grep -q "\"version\": \"${VERSION}\"" apps/admin/package.json
grep -q "\"version\": \"${VERSION}\"" apps/desktop/package.json
grep -q "version = \"${VERSION}\"" apps/desktop/src-tauri/Cargo.toml
grep -q "\"version\": \"${VERSION}\"" apps/desktop/src-tauri/tauri.conf.json
grep -q "VERSION = \"${VERSION}\"" plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeDefaults.java
grep -q "version: ${VERSION}" plugins/paper-bridge/src/main/resources/plugin.yml
grep -q "version: ${VERSION}" plugins/purpur-bridge/src/main/resources/plugin.yml
grep -q "\"version\": \"${VERSION}\"" plugins/velocity-bridge/src/main/resources/velocity-plugin.json
grep -q "version = \"${VERSION}\"" runtime/neverruntime/Cargo.toml
grep -q "archiveVersion.set(\"${VERSION}\")" plugins/velocity-bridge/build.gradle.kts
grep -q "archiveVersion.set(\"${VERSION}\")" plugins/paper-bridge/build.gradle.kts
grep -q "archiveVersion.set(\"${VERSION}\")" plugins/purpur-bridge/build.gradle.kts
grep -q "NEVERLAUNCHER_IMAGE_TAG=${VERSION}" deploy/production/env.production.example
grep -q "VERSION=\"${VERSION}\"" e2e/scripts/run-minecraft-e2e.sh
grep -q "${VERSION}" README.md
grep -q "${VERSION}" deploy/production/production-checklist.md

echo "[NeverLauncher] version alignment OK: ${VERSION}"
