#!/usr/bin/env bash
# Требуется настоящая доверенная идентичность Apple Developer ID Application.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${LAUNCHER_MACOS_SANDBOX_TEAM_ID:?укажите десятисимвольный идентификатор команды Apple}"
: "${LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY:?укажите идентификатор сертификата Developer ID Application}"
[[ "$LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY" == Developer\ ID\ Application:* ]] || { echo "Необходим сертификат Developer ID Application" >&2; exit 1; }
[[ "$LAUNCHER_MACOS_SANDBOX_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Некорректный Team ID" >&2; exit 1; }
DEST="${1:?укажите выходной путь для подписанного вспомогательного приложения}"
[[ "$DEST" = /* ]] || { echo "Выходной путь должен быть абсолютным" >&2; exit 1; }
mkdir -p "$(dirname "$DEST")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
xcrun swiftc -O -whole-module-optimization \
    "$ROOT/macos/sandbox-helper/ExtensionSandbox.swift" -o "$TMP/NeverExtensionSandbox" -lsandbox -lproc
codesign --force --sign "$LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY" \
    --options runtime --timestamp --identifier ru.skif4er.launcher.extension-sandbox \
    --entitlements "$ROOT/macos/sandbox-helper/ExtensionSandbox.entitlements" \
    "$TMP/NeverExtensionSandbox"
REQ="identifier \"ru.skif4er.launcher.extension-sandbox\" and anchor apple generic and certificate leaf[subject.OU] = \"$LAUNCHER_MACOS_SANDBOX_TEAM_ID\""
codesign --verify --strict --verbose=2 --test-requirement "$REQ" "$TMP/NeverExtensionSandbox"
plutil -lint "$ROOT/macos/sandbox-helper/ExtensionSandbox.entitlements"
install -m 0500 "$TMP/NeverExtensionSandbox" "$DEST"
codesign --verify --strict --test-requirement "$REQ" "$DEST"
echo "Подписанная вспомогательная программа установлена: $DEST"
