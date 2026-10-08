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

echo "[NeverLauncher] Предварительная проверка ${VERSION}: сборка, тест и контроль выпуска (строгий=${STRICT}, режим=${MODE})"

run_step() {
  local id="$1"; shift
  echo "[NeverLauncher][контроль:${id}] $*"
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
run_step neverguard-process-policy-0133 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-process-policy-0133.py"
run_step neverguard-guard-attestation-0134 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-guard-attestation-0134.py"
run_step minecraft-serverbridge-integrity-0135 python3 "${ROOT_DIR}/scripts/smoke/offline/minecraft-serverbridge-integrity-0135.py"
run_step windows-production-hardening-0136 python3 "${ROOT_DIR}/scripts/smoke/offline/windows-production-hardening-0136.py"
run_step linux-production-implementation-0137 python3 "${ROOT_DIR}/scripts/smoke/offline/linux-production-implementation-0137.py"
run_step macos-production-implementation-0138 python3 "${ROOT_DIR}/scripts/smoke/offline/macos-production-implementation-0138.py"
run_step guard-ci-release-certification-0139 python3 "${ROOT_DIR}/scripts/smoke/offline/guard-ci-release-certification-0139.py"
run_step guard-migration-compatibility-stabilization-01310 python3 "${ROOT_DIR}/scripts/smoke/offline/guard-migration-compatibility-stabilization-01310.py"
run_step neverguard-release-0140 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-release-0140.py"
run_step serverbridge-protocol-v2-0141 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-protocol-v2-0141.py"
run_step serverbridge-crypto-node-identities-0142 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-crypto-node-identities-0142.py"
run_step serverbridge-one-time-join-tickets-0143 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-one-time-join-tickets-0143.py"
run_step serverbridge-bukkit-family-0144 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-bukkit-family-0144.py"
run_step serverbridge-proxy-family-0145 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-proxy-family-0145.py"
run_step serverbridge-fabric-0146 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-fabric-0146.py"
run_step serverbridge-forge-neoforge-0147 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-forge-neoforge-0147.py"
run_step serverbridge-zero-patch-topology-handoff-0148 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-zero-patch-topology-handoff-0148.py"
run_step serverbridge-public-matrix-ha-hardening-0149 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-public-matrix-ha-hardening-0149.py"
run_step serverbridge-migration-stabilization-01410 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-migration-stabilization-01410.py"
run_step serverbridge-release-0150 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-release-0150.py"
run_step serverbridge-runtime-identity-0192 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-runtime-identity-0192.py"
run_step serverbridge-telemetry-0193 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-telemetry-0193.py"
run_step serverbridge-event-stream-0194 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-event-stream-0194.py"
run_step serverbridge-control-api-0195 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-control-api-0195.py"
run_step serverbridge-topology-routing2-0196 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-topology-routing2-0196.py"
run_step serverbridge-player-session-integration3-0197 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-player-session-integration3-0197.py"
run_step serverbridge-universal-adapters-0198 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-universal-adapters-0198.py"
run_step serverbridge-zero-patch-provisioning-0199 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-zero-patch-provisioning-0199.py"
run_step serverbridge-host-01910 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-host-01910.py"
run_step serverbridge-ha-control-plane-01911 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-ha-control-plane-01911.py"
run_step serverbridge-security-certification-01912 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge-security-certification-01912.py"
run_step serverbridge-security-certification-01912-e2e bash "${ROOT_DIR}/e2e/scripts/run-serverbridge-security-certification-01912-e2e.sh"
run_step serverbridge3-ga-0200 python3 "${ROOT_DIR}/scripts/smoke/offline/serverbridge3-ga-0200.py"
run_step neverextensions-core-0201 python3 "${ROOT_DIR}/scripts/smoke/offline/neverextensions-core-0201.py"
run_step delivery-manifest-platform-architecture-0151 python3 "${ROOT_DIR}/scripts/smoke/offline/delivery-manifest-platform-architecture-0151.py"
run_step signed-windows-x64-arm64-0152 python3 "${ROOT_DIR}/scripts/smoke/offline/signed-windows-x64-arm64-0152.py"
run_step linux-x64-arm64-production-packages-0153 python3 "${ROOT_DIR}/scripts/smoke/offline/linux-x64-arm64-production-packages-0153.py"
run_step notarized-macos-x64-arm64-0154 python3 "${ROOT_DIR}/scripts/smoke/offline/notarized-macos-x64-arm64-0154.py"
run_step managed-jre-distribution-0155 python3 "${ROOT_DIR}/scripts/smoke/offline/managed-jre-distribution-0155.py"
run_step managed-java-II-0165 python3 "${ROOT_DIR}/scripts/smoke/offline/managed-java-II-0165.py"
run_step unified-transactional-updater-core-0156 python3 "${ROOT_DIR}/scripts/smoke/offline/unified-transactional-updater-core-0156.py"
run_step desktop-guard-runtime-transactional-update-0157 python3 "${ROOT_DIR}/scripts/smoke/offline/desktop-guard-runtime-transactional-update-0157.py"
run_step release-verification-v2-trust-lifecycle-0158 python3 "${ROOT_DIR}/scripts/smoke/offline/release-verification-v2-trust-lifecycle-0158.py"
run_step public-production-delivery-matrix-e2e-0159 python3 "${ROOT_DIR}/scripts/smoke/offline/public-production-delivery-matrix-e2e-0159.py"
run_step migration-stabilization-01510 python3 "${ROOT_DIR}/scripts/smoke/offline/migration-stabilization-01510.py"
run_step production-release-candidate-01511 python3 "${ROOT_DIR}/scripts/smoke/offline/production-release-candidate-01511.py"
run_step production-delivery-release-0160 python3 "${ROOT_DIR}/scripts/smoke/offline/production-delivery-release-0160.py"
run_step guard-ci-matrix-tests python3 "${ROOT_DIR}/scripts/guard_ci/test_matrix.py"
run_step cli-tests bash "${ROOT_DIR}/scripts/smoke/offline/cli-tests.sh"
run_step backend-tests bash "${ROOT_DIR}/scripts/smoke/offline/backend-tests.sh"
run_step federation-e2e python3 "${ROOT_DIR}/scripts/test/federation-e2e.py"
run_step cli-build bash "${ROOT_DIR}/scripts/smoke/offline/cli-build.sh"
run_step backend-build bash "${ROOT_DIR}/scripts/smoke/offline/backend-build.sh"
run_step version-alignment bash "${ROOT_DIR}/scripts/smoke/offline/version-alignment.sh"
run_step contract-validation python3 "${ROOT_DIR}/scripts/contracts/validate-openapi.py"
run_step compatibility-matrix bash "${ROOT_DIR}/scripts/smoke/offline/compatibility-matrix.sh"
run_step minecraft-compatibility-II-ga-0170 python3 "${ROOT_DIR}/scripts/smoke/offline/minecraft-compatibility-II-ga-0170.py"
run_step fabric-compatibility-II-0171 python3 "${ROOT_DIR}/scripts/smoke/offline/fabric-compatibility-II-0171.py"
run_step quilt-compatibility-II-0172 python3 "${ROOT_DIR}/scripts/smoke/offline/quilt-compatibility-II-0172.py"
run_step forge-modern-0173 python3 "${ROOT_DIR}/scripts/smoke/offline/forge-modern-0173.py"
run_step forge-legacy-1122-0174 python3 "${ROOT_DIR}/scripts/smoke/offline/forge-legacy-1122-0174.py"
run_step forge-legacy-1710-0175 python3 "${ROOT_DIR}/scripts/smoke/offline/forge-legacy-1710-0175.py"
run_step neoforge-compatibility-II-0176 python3 "${ROOT_DIR}/scripts/smoke/offline/neoforge-compatibility-II-0176.py"
run_step loader-resolution-pinning-0177 python3 "${ROOT_DIR}/scripts/smoke/offline/loader-resolution-pinning-0177.py"
run_step loader-native-e2e-0178 python3 "${ROOT_DIR}/scripts/smoke/offline/loader-native-e2e-0178.py"
run_step cross-platform-loaders-0179 python3 "${ROOT_DIR}/scripts/smoke/offline/cross-platform-loaders-0179.py"
run_step loader-hardening-01710 python3 "${ROOT_DIR}/scripts/smoke/offline/loader-hardening-01710.py"
run_step loader-compatibility-rc-01711 python3 "${ROOT_DIR}/scripts/smoke/offline/loader-compatibility-rc-01711.py"
run_step loader-compatibility-ga-0180 python3 "${ROOT_DIR}/scripts/smoke/offline/loader-compatibility-ga-0180.py"
run_step windows-protection-core-II-0181 python3 "${ROOT_DIR}/scripts/smoke/offline/windows-protection-core-II-0181.py"
run_step neverguard-sensor-0182 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-sensor-0182.py"
run_step neverguard-module-guard-0183 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-module-guard-0183.py"
run_step neverguard-aggressive-hook-engine-0184 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-aggressive-hook-engine-0184.py"
run_step neverguard-memory-integrity-0185 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-memory-integrity-0185.py"
run_step neverguard-thread-process-integrity-0186 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-thread-process-integrity-0186.py"
run_step neverguard-debug-instrumentation-0187 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-debug-instrumentation-0187.py"
run_step neverguard-jvm-aware-protection-0188 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-jvm-aware-protection-0188.py"
run_step neverguard-continuous-guard-0189 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-continuous-guard-0189.py"
run_step neverguard-attestation-v2-01810 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-attestation-v2-01810.py"
run_step neverguard-windows-adversarial-ci-01811 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-windows-adversarial-ci-01811.py"
run_step neverguard-windows-adversarial-ci-tests python3 "${ROOT_DIR}/scripts/guard_ci/test_windows_adversarial.py"
run_step neverguard-windows-protection-rc-01812 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-windows-protection-rc-01812.py"
run_step neverguard-windows-protection-ga-0190 python3 "${ROOT_DIR}/scripts/smoke/offline/neverguard-windows-protection-ga-0190.py"
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
    echo "[NeverLauncher] клиентская часть сборка пропущен в auto-режиме; такой прогон не является рабочий-готовый"
  fi
fi

if is_true "${RUN_TAURI}"; then
  if ! command -v cargo >/dev/null 2>&1; then
    if is_true "${STRICT}"; then
      echo "[NeverLauncher] строгий предварительная проверка: cargo обязателен" >&2
      exit 1
    fi
    echo "[NeverLauncher] Tauri проверка пропущен: cargo отсутствует"
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
  run_step guard-migration-postgres-e2e bash "${ROOT_DIR}/e2e/scripts/run-guard-migration-e2e.sh"
  run_step serverbridge-v2-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-serverbridge-v2-migration-e2e.sh"
  run_step serverbridge-crypto-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-serverbridge-crypto-identity-migration-e2e.sh"
  run_step one-time-join-ticket-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-one-time-join-ticket-migration-e2e.sh"
  run_step bukkit-family-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-bukkit-family-migration-e2e.sh"
  run_step proxy-family-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-proxy-family-migration-e2e.sh"
  run_step fabric-server-bridge-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-fabric-server-bridge-migration-e2e.sh"
  run_step forge-neoforge-server-bridge-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-forge-neoforge-server-bridge-migration-e2e.sh"
  run_step zero-patch-topology-handoff-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-zero-patch-topology-handoff-migration-e2e.sh"
  run_step serverbridge-ha-hardening-migration-e2e bash "${ROOT_DIR}/e2e/scripts/run-serverbridge-ha-hardening-migration-e2e.sh"
  run_step serverbridge-migration-stabilization-e2e bash "${ROOT_DIR}/e2e/scripts/run-serverbridge-migration-stabilization-e2e.sh"
fi

if [[ -d "${RELEASE_DIR}" ]]; then
  run_step release-bundle bash "${ROOT_DIR}/scripts/smoke/release-required/release-bundle.sh" "${RELEASE_DIR}"
elif is_true "${STRICT}"; then
  echo "[NeverLauncher] строгий предварительная проверка: комплект релиза ${RELEASE_DIR} обязателен" >&2
  exit 1
else
  echo "[NeverLauncher] Комплект релиза ${RELEASE_DIR} не найден: проверка пропущена; такой прогон не является рабочий-готовый"
fi

if is_true "${STRICT}"; then
  echo "[NeverLauncher] Строгий рабочий предварительная проверка ${VERSION} завершён успешно"
else
  echo "[NeverLauncher] Предварительная проверка ${VERSION} завершён успешно для доступного локального контура; рабочий-готовый требует NEVERLAUNCHER_PREFLIGHT_STRICT=1"
fi
