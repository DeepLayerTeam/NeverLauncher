#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${ROOT_DIR}/dist/release-${VERSION}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  OUT_DIR="$1"
  shift
fi
EXPECTED_ARCH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-arch)
      EXPECTED_ARCH="${2:-}"
      shift 2
      ;;
    *)
      echo "Неизвестный аргумент: $1" >&2
      exit 2
      ;;
  esac
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="x64"; GOARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64"; GOARCH="arm64" ;;
  *) echo "Неподдерживаемая нативная архитектура Linux: $(uname -m)" >&2; exit 2 ;;
esac
if [[ -n "${EXPECTED_ARCH}" && "${EXPECTED_ARCH}" != "${ARCH}" ]]; then
  echo "Архитектура нативного исполняемого компонента не совпадает: ожидалась ${EXPECTED_ARCH}, получена ${ARCH}" >&2
  exit 2
fi

# Rust встраивает промышленный ключ проверки. Пустой ключ на этапе сборки
# никогда не должен позволять выпускать бинарники, которые позже объявят
# готовыми к промышленному использованию.
[[ "${LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY:-}" =~ ^[a-fA-F0-9]{64}$ ]] || {
  echo "Для рабочей сборки Linux Guard перед компиляцией Cargo требуется LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY" >&2; exit 2;
}
require() { command -v "$1" >/dev/null 2>&1 || { echo "Необходимо указать: $1" >&2; exit 1; }; }
for tool in go cargo npm python3; do require "${tool}"; done
mkdir -p "${OUT_DIR}"

echo "[Launcher ${VERSION}] Linux ${ARCH}: сборка интерфейса"
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)

echo "[Launcher ${VERSION}] Linux ${ARCH}: сборка CLI/API"
(
  cd "${ROOT_DIR}/cli"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.componentSetTrustedKey02310=${LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY:-} -X main.componentSetRootKey02312=${LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY:-}" -o "${OUT_DIR}/launcher-cli-linux-${ARCH}" ./cmd/launcher
)
(
  cd "${ROOT_DIR}/services/api"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED="${LAUNCHER_API_CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${LAUNCHER_SOURCE_COMMIT:-${GITHUB_SHA:-unknown}}" -o "${OUT_DIR}/launcher-api-linux-${ARCH}" ./cmd/launcher-api
)

echo "[Launcher ${VERSION}] Linux ${ARCH}: нативная сборка Desktop/Guard/Runtime"
cargo build --release --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
cargo build --release --manifest-path "${ROOT_DIR}/runtime/runtime/Cargo.toml" --bins

install -m 0755 "${ROOT_DIR}/apps/desktop/src-tauri/target/release/launcher-desktop" "${OUT_DIR}/launcher-desktop-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/runtime/target/release/guard" "${OUT_DIR}/guard-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/runtime/target/release/runtime" "${OUT_DIR}/runtime-linux-${ARCH}"
chmod 0755 \
  "${OUT_DIR}/launcher-cli-linux-${ARCH}" \
  "${OUT_DIR}/launcher-api-linux-${ARCH}"

# Сохраните настоящие неподписанные исполняемые файлы до применения манифестов
# Linux-пакетов и делегированных подписей. Воспроизводимый tar/gzip не зависит
# от временных меток ФС, UID, имени текущего пользователя или выходного
# каталога.
if [[ "${VERSION}" == "0.47.0" || "${LAUNCHER_UNSIGNED_ONLY:-}" == "1" ]]; then
  UNSIGNED_DIR="${LAUNCHER_UNSIGNED_OUTPUT_DIR:-${ROOT_DIR}/dist/unsigned-${VERSION}}"
  python3 "${ROOT_DIR}/scripts/release/unsigned_package_0470.py" \
    --platform linux --arch "${ARCH}" --out-dir "${UNSIGNED_DIR}" \
    --file "launcher/launcher-cli=${OUT_DIR}/launcher-cli-linux-${ARCH}" \
    --file "launcher/launcher-api=${OUT_DIR}/launcher-api-linux-${ARCH}" \
    --file "launcher/launcher-desktop=${OUT_DIR}/launcher-desktop-linux-${ARCH}" \
    --file "launcher/guard=${OUT_DIR}/guard-linux-${ARCH}" \
    --file "launcher/runtime=${OUT_DIR}/runtime-linux-${ARCH}"
fi

if [[ "${LAUNCHER_UNSIGNED_ONLY:-}" == "1" ]]; then
  echo "Launcher ${VERSION} Linux ${ARCH}: сохранены неподписанные исполняемые файлы"
  exit 0
fi

python3 "${ROOT_DIR}/scripts/release/linux-package.py" \
  --out "${OUT_DIR}" --version "${VERSION}" --architecture "${ARCH}"

echo "[Launcher ${VERSION}] Linux ${ARCH}: промышленный пакет готов: ${OUT_DIR}"
