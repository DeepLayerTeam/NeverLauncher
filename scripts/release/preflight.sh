#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
BASE_URL="${NEVERLAUNCHER_PREFLIGHT_BASE_URL:-${1:-http://localhost:8080}}"
RELEASE_DIR="${NEVERLAUNCHER_RELEASE_DIR:-${2:-${ROOT_DIR}/dist/release-${VERSION}}}"
MODE="${NEVERLAUNCHER_PREFLIGHT_MODE:-offline}"
STRICT="${NEVERLAUNCHER_PREFLIGHT_STRICT:-0}"
RUN_FRONTEND="${NEVERLAUNCHER_PREFLIGHT_FRONTEND:-auto}"
RUN_TAURI="${NEVERLAUNCHER_PREFLIGHT_TAURI:-0}"
RUN_FEDERATION_POSTGRES="${NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES:-0}"
RUN_DEVICE_TRUST_E2E="${NEVERLAUNCHER_PREFLIGHT_DEVICE_TRUST_E2E:-0}"

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if is_true "${STRICT}"; then
  export NEVERLAUNCHER_PREFLIGHT_PGX=1
  export NEVERLAUNCHER_PREFLIGHT_BRIDGE_STRICT=1
  RUN_FRONTEND=1
  RUN_TAURI=1
  RUN_FEDERATION_POSTGRES=1
  RUN_DEVICE_TRUST_E2E=1
fi

echo "[NeverLauncher] Preflight ${VERSION}: build, test & release gate (strict=${STRICT}, mode=${MODE})"

run_step() {
  local id="$1"; shift
  echo "[NeverLauncher][gate:${id}] $*"
  "$@"
}

run_step repository-policy python3 "${ROOT_DIR}/scripts/smoke/offline/repository-policy.py"
run_step device-key-storage python3 "${ROOT_DIR}/scripts/smoke/offline/device-key-storage.py"
run_step hardware-bound-identity python3 "${ROOT_DIR}/scripts/smoke/offline/hardware-bound-identity.py"
run_step challenge-response-attestation python3 "${ROOT_DIR}/scripts/smoke/offline/challenge-response-attestation.py"
run_step device-management-revocation python3 "${ROOT_DIR}/scripts/smoke/offline/device-management-revocation.py"
run_step session-device-risk-0126 python3 "${ROOT_DIR}/scripts/smoke/offline/session-device-risk-0126.py"
run_step minecraft-serverbridge-trust-0127 python3 "${ROOT_DIR}/scripts/smoke/offline/minecraft-serverbridge-trust-0127.py"
run_step cross-platform-key-recovery-0128 python3 "${ROOT_DIR}/scripts/smoke/offline/cross-platform-key-recovery-0128.py"
run_step device-trust-e2e-matrix-0129 python3 "${ROOT_DIR}/scripts/smoke/offline/device-trust-e2e-matrix-0129.py"
run_step device-trust-migration-stabilization-01210 python3 "${ROOT_DIR}/scripts/smoke/offline/device-trust-migration-stabilization-01210.py"
run_step device-trust-release-0130 python3 "${ROOT_DIR}/scripts/smoke/offline/device-trust-release-0130.py"
run_step neverguard-windows-0131 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-windows-0131.py"
run_step neverguard-integrity-evidence-0132 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-integrity-evidence-0132.py"
run_step cli-tests bash "${ROOT_DIR}/scripts/smoke/offline/cli-tests.sh"
run_step backend-tests bash "${ROOT_DIR}/scripts/smoke/offline/backend-tests.sh"
run_step federation-e2e python3 "${ROOT_DIR}/scripts/test/federation-e2e.py"
run_step cli-build bash "${ROOT_DIR}/scripts/smoke/offline/cli-build.sh"
run_step backend-build bash "${ROOT_DIR}/scripts/smoke/offline/backend-build.sh"
run_step version-alignment bash "${ROOT_DIR}/scripts/smoke/offline/version-alignment.sh"
run_step contract-validation python3 "${ROOT_DIR}/scripts/contracts/validate-openapi.py"
run_step compatibility-matrix bash "${ROOT_DIR}/scripts/smoke/offline/compatibility-matrix.sh"
run_step release-scripts bash "${ROOT_DIR}/scripts/smoke/offline/release-scripts.sh"
run_step bridge-build bash "${ROOT_DIR}/scripts/smoke/offline/bridge-build.sh"

if is_true "${RUN_FRONTEND}"; then
  run_step admin-build bash "${ROOT_DIR}/scripts/smoke/frontend/admin-build.sh"
  run_step desktop-web-build bash "${ROOT_DIR}/scripts/smoke/frontend/desktop-web-build.sh"
elif [[ "${RUN_FRONTEND}" == "auto" ]]; then
  if command -v npm >/dev/null 2>&1 && [[ -d "${ROOT_DIR}/apps/admin/node_modules" && -d "${ROOT_DIR}/apps/desktop/node_modules" ]]; then
    run_step admin-build bash "${ROOT_DIR}/scripts/smoke/frontend/admin-build.sh"
    run_step desktop-web-build bash "${ROOT_DIR}/scripts/smoke/frontend/desktop-web-build.sh"
  else
    echo "[NeverLauncher] frontend build пропущен в auto-режиме; такой прогон не является production-ready"
  fi
fi

if is_true "${RUN_TAURI}"; then
  if ! command -v cargo >/dev/null 2>&1; then
    if is_true "${STRICT}"; then
      echo "[NeverLauncher] strict preflight: cargo обязателен" >&2
      exit 1
    fi
    echo "[NeverLauncher] Tauri check пропущен: cargo отсутствует"
  else
    run_step tauri-check bash "${ROOT_DIR}/scripts/smoke/frontend/tauri-check.sh"
  fi
fi

if [[ "${MODE}" == "api" || "${MODE}" == "full" ]]; then
  run_step api-required bash "${ROOT_DIR}/scripts/smoke/api-required/api-smoke.sh" "${BASE_URL}"
fi

if is_true "${RUN_FEDERATION_POSTGRES}"; then
  run_step federation-postgres-e2e bash "${ROOT_DIR}/e2e/scripts/run-federation-postgres-e2e.sh"
fi

if is_true "${RUN_DEVICE_TRUST_E2E}"; then
  run_step device-trust-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-device-trust-migration-e2e.sh"
  run_step device-trust-postgres-e2e bash "${ROOT_DIR}/e2e/scripts/run-device-trust-e2e.sh"
fi

if [[ -d "${RELEASE_DIR}" ]]; then
  run_step release-bundle bash "${ROOT_DIR}/scripts/smoke/release-required/release-bundle.sh" "${RELEASE_DIR}"
elif is_true "${STRICT}"; then
  echo "[NeverLauncher] strict preflight: release bundle ${RELEASE_DIR} обязателен" >&2
  exit 1
else
  echo "[NeverLauncher] Release bundle ${RELEASE_DIR} не найден: проверка пропущена; такой прогон не является production-ready"
fi

if is_true "${STRICT}"; then
  echo "[NeverLauncher] Strict production preflight ${VERSION} завершён успешно"
else
  echo "[NeverLauncher] Preflight ${VERSION} завершён успешно для доступного локального контура; production-ready требует NEVERLAUNCHER_PREFLIGHT_STRICT=1"
fi
