#!/usr/bin/env bash
# Собирайте нативный Desktop с открытым корневым ключом подписи пакета владельца.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Использование: $0 <32-byte-ed25519-public-root-hex-file>" >&2; exit 2; fi
ROOT_FILE="$1"
[[ -f "$ROOT_FILE" && ! -L "$ROOT_FILE" ]] || { echo "Файл корневого открытого ключа отсутствует или небезопасен" >&2; exit 2; }
ROOT=$(tr -d '\r\n ' < "$ROOT_FILE")
[[ "$ROOT" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Ожидается корневой ключ Ed25519 длиной ровно 32 байта (64 шестнадцатеричных символа)" >&2; exit 2; }
ROOT=$(printf '%s' "$ROOT" | tr 'A-F' 'a-f')
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../apps/desktop"
export LAUNCHER_BOOTSTRAP_ROOT_KEY="$ROOT"
# Корневой ключ встраивается в Rust через option_env! при компиляции, не передаётся JavaScript
# или через окружение запуска. Требуется существующий toolchain Tauri v2.
npm ci --ignore-scripts
npm run tauri:build
