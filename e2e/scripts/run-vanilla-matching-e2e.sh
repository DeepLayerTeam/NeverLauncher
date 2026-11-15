#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
CLIENT_DIR="$RUNTIME_DIR/materialized-client"
SERVER_DIR="$RUNTIME_DIR/matching-server"
MINECRAFT_VERSION="${LAUNCHER_E2E_MINECRAFT_VERSION:-}"
JAVA_BIN="${LAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${LAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${LAUNCHER_COMPAT_TARGET_ID:-vanilla-matching-server}"
TARGET_OS="${LAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${LAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
CLIENT_RUNTIME_SECONDS="${LAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-55}"
PLAYER_USERNAME="NL_Cert_Client"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[matching-e2e] неверная версия Minecraft" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[matching-e2e] неверный основной номер версии Java" >&2; exit 2; }
[[ "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ]] || { echo "[matching-e2e] сквозные тесты соответствующего сервера сертифицированы на linux/x86_64" >&2; exit 2; }
[[ -n "$JAVA_BIN" && -x "$JAVA_BIN" ]] || { echo "[matching-e2e] исполняемый файл целевой Java недоступен: $JAVA_BIN" >&2; exit 2; }
for cmd in go cargo python3 xvfb-run; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[matching-e2e] отсутствует необходимая команда: $cmd" >&2; exit 1; }
done

# All matching targets use the same independent RCON witness and resource gate.
bash "$ROOT/e2e/scripts/run-vanilla-certification-case.sh"
python3 "$ROOT/e2e/scripts/matching_live_report.py" --runtime "$RUNTIME_DIR" \
  --minecraft "$MINECRAFT_VERSION" --java-major "$JAVA_MAJOR" --target "$TARGET_ID"
