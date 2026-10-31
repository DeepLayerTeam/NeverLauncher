#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CANONICAL_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
if [[ -n "${1:-}" && "$1" != "${CANONICAL_VERSION}" ]]; then
  echo "Ошибка: версия release задаётся только через VERSION=${CANONICAL_VERSION}; передано: $1" >&2
  exit 2
fi
VERSION="${CANONICAL_VERSION}"
OUT_DIR="${2:-${ROOT_DIR}/dist/release-${VERSION}}"
WORK_DIR="${ROOT_DIR}/dist/.release-${VERSION}"
PRIVATE_KEY="${LAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE:-}"
PUBLIC_KEY="${LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE:-${LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE:-}}"
TRUST_POLICY="${LAUNCHER_RELEASE_TRUST_POLICY_FILE:-}"
TRUST_STATE="${LAUNCHER_RELEASE_TRUST_STATE_FILE:-${WORK_DIR}/release-trust-state.json}"
COMPATIBILITY_MATRIX="${LAUNCHER_COMPATIBILITY_MATRIX_FILE:-}"
COMPATIBILITY_TARGETS="${LAUNCHER_COMPATIBILITY_TARGETS_FILE:-${ROOT_DIR}/compatibility/targets.json}"
DEVICE_TRUST_MATRIX="${LAUNCHER_DEVICE_TRUST_MATRIX_FILE:-}"
DEVICE_TRUST_TARGETS="${LAUNCHER_DEVICE_TRUST_TARGETS_FILE:-${ROOT_DIR}/device-trust/targets.json}"
GUARD_CI_MATRIX="${LAUNCHER_GUARD_CI_MATRIX_FILE:-}"
GUARD_CI_TARGETS="${LAUNCHER_GUARD_CI_TARGETS_FILE:-${ROOT_DIR}/guard-ci/targets.json}"
GUARD_PLATFORM_ARTIFACTS_DIR="${LAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR:-}"
WINDOWS_SIGNED_ARTIFACTS_DIR="${LAUNCHER_WINDOWS_SIGNED_ARTIFACTS_DIR:-}"
LINUX_PRODUCTION_ARTIFACTS_DIR="${LAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR:-}"
MACOS_PRODUCTION_ARTIFACTS_DIR="${LAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR:-}"
MANAGED_JRE_ARTIFACTS_DIR="${LAUNCHER_MANAGED_JRE_ARTIFACTS_DIR:-}"
WINDOWS_ADVERSARIAL_CERTIFICATE="${LAUNCHER_WINDOWS_ADVERSARIAL_CERTIFICATE_FILE:-}"
SOURCE_COMMIT="${LAUNCHER_SOURCE_COMMIT:-}"
PUBLIC_RELEASE_BASE_URL="${LAUNCHER_PUBLIC_RELEASE_BASE_URL:-https://github.com/DeepLayerTeam/Launcher/releases/download/v${VERSION}}"
export LAUNCHER_PUBLIC_RELEASE_BASE_URL="${PUBLIC_RELEASE_BASE_URL}"

# 0.25.0 is GA only if a different, authorized CI attestation key has
# cryptographically certified all six real platform installers and the actual
# optional-components lifecycle. Perform this check before erasing any output.
COMPONENTS_GA_RECEIPT=""
if [[ "${VERSION}" == "0.25.0" ]]; then
  for tool in python3 git; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "GA requires ${tool}" >&2; exit 2; }
  done
  GA_DIR="${LAUNCHER_COMPONENT_GA_ATTESTATIONS_DIR:-}"
  GA_PUB="${LAUNCHER_COMPONENT_GA_PUBLIC_KEY:-}"
  if [[ -z "${GA_DIR}" || -z "${GA_PUB}" || ! -d "${GA_DIR}" ]]; then
    echo "0.25.0 GA requires signed evidence in LAUNCHER_COMPONENT_GA_ATTESTATIONS_DIR and a pinned LAUNCHER_COMPONENT_GA_PUBLIC_KEY" >&2
    exit 2
  fi
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  if [[ -n "${SOURCE_COMMIT}" && "${SOURCE_COMMIT}" != "${HEAD_COMMIT}" ]]; then
    echo "GA source commit does not equal git HEAD" >&2
    exit 2
  fi
  SOURCE_COMMIT="${HEAD_COMMIT}"
  if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]]; then
    echo "0.25.0 GA signing requires a clean, committed source tree" >&2
    exit 2
  fi
  COMPONENTS_GA_RECEIPT="$(mktemp)"
  trap 'rm -f "${COMPONENTS_GA_RECEIPT}"' EXIT
  python3 "${ROOT_DIR}/scripts/ga/release_gate.py" \
    --version 0.25.0 --attestations "${GA_DIR}" \
    --trusted-attestation-public-key "${GA_PUB}" \
    --commit "${SOURCE_COMMIT}" --output "${COMPONENTS_GA_RECEIPT}"
fi

# 0.27.0 GA requires an independent, signed LIVE Microsoft/Xbox/Minecraft
# attestation for each shipping OS/architecture. Unit tests and CI builds
# cannot satisfy this gate. Keep operator keys outside the source tree.
OFFICIAL_GA_RECEIPT=""
if [[ "${VERSION}" == "0.27.0" ]]; then
  OFFICIAL_GA_DIR="${LAUNCHER_OFFICIAL_GA_ATTESTATIONS_DIR:-}"
  OFFICIAL_GA_PUB="${LAUNCHER_OFFICIAL_GA_PUBLIC_KEY:-}"
  [[ -d "${OFFICIAL_GA_DIR}" && -n "${OFFICIAL_GA_PUB}" ]] || {
    echo "0.27.0 GA BLOCKED: six signed live official Minecraft attestations and a pinned operator public key are required" >&2
    exit 2
  }
  command -v git >/dev/null 2>&1 || { echo "GA requires git" >&2; exit 2; }
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  [[ -z "${SOURCE_COMMIT}" || "${SOURCE_COMMIT}" == "${HEAD_COMMIT}" ]] || {
    echo "official GA source commit mismatch" >&2; exit 2;
  }
  SOURCE_COMMIT="${HEAD_COMMIT}"
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]] || {
    echo "official GA signing requires a clean, committed source tree" >&2; exit 2;
  }
  OFFICIAL_GA_RECEIPT="$(mktemp)"
  trap '[[ -z "${COMPONENTS_GA_RECEIPT}" ]] || rm -f "${COMPONENTS_GA_RECEIPT}"; [[ -z "${OFFICIAL_GA_RECEIPT}" ]] || rm -f "${OFFICIAL_GA_RECEIPT}"' EXIT
  python3 "${ROOT_DIR}/scripts/ga/official_minecraft_0270.py" \
    --attestations "${OFFICIAL_GA_DIR}" --public-key "${OFFICIAL_GA_PUB}" \
    --commit "${SOURCE_COMMIT}" --output "${OFFICIAL_GA_RECEIPT}"
fi

# 0.31.0 Java SDK & Module Parity GA: no unsigned/incomplete evidence may
# authorize production signing. Validate before deleting any release outputs.
if [[ "${VERSION}" == "0.31.0" ]]; then
  for name in LAUNCHER_JAVA_GA_EVIDENCE_DIR LAUNCHER_JAVA_GA_APPROVAL_PUBLIC_KEY_FILE LAUNCHER_JAVA_GA_APPROVAL_SIGNATURE_FILE; do
    [[ -n "${!name:-}" ]] || { echo "0.31.0 GA BLOCKED: missing ${name}" >&2; exit 2; }
  done
  command -v git >/dev/null 2>&1 || { echo "0.31.0 GA requires git" >&2; exit 2; }
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  [[ -z "${SOURCE_COMMIT}" || "${SOURCE_COMMIT}" == "${HEAD_COMMIT}" ]] || {
    echo "0.31.0 GA source commit mismatch" >&2; exit 2;
  }
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]] || {
    echo "0.31.0 GA signing requires a clean source checkout" >&2; exit 2;
  }
  SOURCE_COMMIT="${HEAD_COMMIT}"
  python3 "${ROOT_DIR}/scripts/ga/verify_java_ga_0310.py" \
    --evidence "${LAUNCHER_JAVA_GA_EVIDENCE_DIR}" \
    --revision "${HEAD_COMMIT}" \
    --public-key "${LAUNCHER_JAVA_GA_APPROVAL_PUBLIC_KEY_FILE}" \
    --signature "${LAUNCHER_JAVA_GA_APPROVAL_SIGNATURE_FILE}" >/dev/null || exit 2
fi

# Trusted release policy is compiled into scripts/release/release_policy.py, not
# read from unsigned build outputs. Check independent operator signature and
# exact source identity BEFORE expensive staging or modification of output.
GA_TARGET_MODE="$(python3 "${ROOT_DIR}/scripts/release/release_policy.py" ga-mode --version "${VERSION}")"
GA_TARGET_EVIDENCE_DIR=""
GA_TARGET_TRUSTED_KEY=""
if [[ "${GA_TARGET_MODE}" == "legacy-ga036" ]]; then
  GA_TARGET_EVIDENCE_DIR="${LAUNCHER_GA036_EVIDENCE_DIR:-}"
  GA_TARGET_TRUSTED_KEY="${LAUNCHER_GA036_TRUSTED_PUBLIC_KEY_FILE:-}"
elif [[ "${GA_TARGET_MODE}" == "signed-ga-v2" ]]; then
  GA_TARGET_EVIDENCE_DIR="${LAUNCHER_GA_EVIDENCE_DIR:-}"
  GA_TARGET_TRUSTED_KEY="${LAUNCHER_GA_TRUSTED_PUBLIC_KEY_FILE:-}"
fi
if [[ "${GA_TARGET_MODE}" != "historical" ]]; then
  [[ -n "${GA_TARGET_EVIDENCE_DIR}" && -n "${GA_TARGET_TRUSTED_KEY}" ]] || {
    echo "${VERSION} GA BLOCKED: independent signed target evidence and pinned operator public key required" >&2
    exit 2
  }
  command -v git >/dev/null 2>&1 || { echo "GA requires git" >&2; exit 2; }
  GA_TARGET_HEAD="$(git -C "${ROOT_DIR}" rev-parse --verify HEAD)" || exit 2
  [[ -z "${SOURCE_COMMIT}" || "${SOURCE_COMMIT}" == "${GA_TARGET_HEAD}" ]] || {
    echo "${VERSION} GA BLOCKED: source SHA differs from git HEAD" >&2; exit 2;
  }
  SOURCE_COMMIT="${GA_TARGET_HEAD}"
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal -- ':!dist')" ]] || {
    echo "${VERSION} GA BLOCKED: source checkout is not clean" >&2; exit 2;
  }
  python3 "${ROOT_DIR}/scripts/ga/verified_targets.py" \
    --preflight --evidence "${GA_TARGET_EVIDENCE_DIR}" \
    --trusted-key "${GA_TARGET_TRUSTED_KEY}" --commit "${SOURCE_COMMIT}" \
    --version "${VERSION}"
fi

# Launcher 0.33.0 must not be shipped as GA based on an RC test receipt,
# a PostgreSQL+SQLite coordinator, or a self-attestation. Verify an independent
# operator-signed, actual SQLite-only HTTP deployment report BEFORE touching
# an existing output bundle.
SINGLE_NODE_GA_DIR=""
SINGLE_NODE_GA_VERIFIED_DIR=""
if [[ "${VERSION}" == "0.33.0" ]]; then
  SINGLE_NODE_GA_DIR="${LAUNCHER_SINGLE_NODE_GA_EVIDENCE_DIR:-}"
  SINGLE_NODE_GA_PUBLIC_KEY="${LAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE:-}"
  [[ -d "${SINGLE_NODE_GA_DIR}" && -f "${SINGLE_NODE_GA_PUBLIC_KEY}" ]] || {
    echo "0.33.0 GA BLOCKED: signed live SQLite-only evidence and an independently pinned public key are mandatory" >&2; exit 2;
  }
  command -v git >/dev/null 2>&1 || { echo "0.33.0 GA requires git" >&2; exit 2; }
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)" || exit 2
  [[ -z "${SOURCE_COMMIT}" || "${SOURCE_COMMIT}" == "${HEAD_COMMIT}" ]] || {
    echo "0.33.0 GA BLOCKED: source commit mismatch" >&2; exit 2;
  }
  SOURCE_COMMIT="${HEAD_COMMIT}"
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]] || {
    echo "0.33.0 GA signing requires clean tracked and untracked sources" >&2; exit 2;
  }
  SINGLE_NODE_GA_VERIFIED_DIR="$(mktemp -d)"
  trap 'rm -rf -- "${SINGLE_NODE_GA_VERIFIED_DIR}"' EXIT
  python3 "${ROOT_DIR}/scripts/ga/single_node_ga_0330.py" \
    --evidence-dir "${SINGLE_NODE_GA_DIR}" \
    --public-key "${SINGLE_NODE_GA_PUBLIC_KEY}" \
    --commit "${SOURCE_COMMIT}" \
    --output "${SINGLE_NODE_GA_VERIFIED_DIR}/SINGLE_NODE_GA_CERTIFICATION.json" || exit 2
fi

# Every release from 0.35.0 onward must recheck the real protected Backend.
# Do NOT narrow this to one historical version: otherwise all future versions
# silently bypass the trusted-runtime publication requirement.
GA_RUNTIME_PREFLIGHT_FILE=""
GA_RUNTIME_GATE_REQUIRED=0
if [[ "${VERSION}" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  if (( 10#${BASH_REMATCH[1]} > 0 || 10#${BASH_REMATCH[2]} >= 35 )); then
    GA_RUNTIME_GATE_REQUIRED=1
  fi
fi
if [[ "${GA_RUNTIME_GATE_REQUIRED}" == "1" ]]; then
  [[ -n "${NL_GA_BACKEND_URL:-}" && -n "${NL_GA_PACKAGE_ID:-}" && -n "${NL_GA_OPERATOR_TOKEN:-}" ]] || {
    echo "protected runtime release BLOCKED: protected Backend URL, staged package and read token required" >&2; exit 2;
  }
  command -v git >/dev/null 2>&1 || { echo "protected runtime release requires git" >&2; exit 2; }
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  [[ -z "${SOURCE_COMMIT}" || "${SOURCE_COMMIT}" == "${HEAD_COMMIT}" ]] || {
    echo "protected runtime release source SHA does not match checkout" >&2; exit 2;
  }
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]] || {
    echo "protected runtime release signing requires clean committed source" >&2; exit 2;
  }
  SOURCE_COMMIT="${HEAD_COMMIT}"
  GA_RUNTIME_PREFLIGHT_FILE="$(mktemp)"
  trap 'rm -f -- "${GA_RUNTIME_PREFLIGHT_FILE}"' EXIT
  python3 "${ROOT_DIR}/scripts/ga/runtime_acceptance_0350.py" \
    --backend "${NL_GA_BACKEND_URL}" --package-id "${NL_GA_PACKAGE_ID}" \
    --source-sha "${SOURCE_COMMIT}" --version "${VERSION}" \
    --output "${GA_RUNTIME_PREFLIGHT_FILE}" || {
      echo "protected runtime release BLOCKED: trusted Backend runtime evidence incomplete" >&2; exit 2;
    }
fi

rm -rf "${OUT_DIR}" "${WORK_DIR}"
mkdir -p "${OUT_DIR}" "${WORK_DIR}"
if [[ -n "${GA_RUNTIME_PREFLIGHT_FILE}" ]]; then
  cp -- "${GA_RUNTIME_PREFLIGHT_FILE}" "${OUT_DIR}/GA_RUNTIME_PREFLIGHT_0350.json"
fi
if [[ "${VERSION}" == "0.33.0" ]]; then
  for name in SINGLE_NODE_GA_ATTESTATION.json SINGLE_NODE_GA_ATTESTATION.sig SINGLE_NODE_GA_RC.json SINGLE_NODE_GA_CERTIFICATION.json; do
    if [[ "${name}" == "SINGLE_NODE_GA_CERTIFICATION.json" ]]; then
      cp -- "${SINGLE_NODE_GA_VERIFIED_DIR}/${name}" "${OUT_DIR}/${name}"
    else
      cp -- "${SINGLE_NODE_GA_DIR}/${name}" "${OUT_DIR}/${name}"
    fi
  done
fi

log() { printf '[Launcher %s] %s\n' "${VERSION}" "$*"; }
require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Ошибка: production release требует команду '$1'" >&2
    exit 1
  fi
}
require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Ошибка: обязательный release artifact отсутствует: $1" >&2
    exit 1
  fi
}

for tool in go python3 npm cargo gradle; do require "${tool}"; done
if [[ -z "${PRIVATE_KEY}" || -z "${PUBLIC_KEY}" || -z "${TRUST_POLICY}" ]]; then
  echo "Ошибка: задайте LAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE, LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE и LAUNCHER_RELEASE_TRUST_POLICY_FILE" >&2
  exit 1
fi
require_file "${PRIVATE_KEY}"
require_file "${PUBLIC_KEY}"
require_file "${TRUST_POLICY}"
python3 "${ROOT_DIR}/scripts/version/manage.py" check
GUARD_CERT_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,13,9) else '0')
PYVER
)"
WINDOWS_DUAL_ARCH_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,2) else '0')
PYVER
)"
LINUX_DUAL_ARCH_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,3) else '0')
PYVER
)"
MACOS_DUAL_ARCH_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,4) else '0')
PYVER
)"
MANAGED_JRE_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,5) else '0')
PYVER
)"
MANAGED_JAVA_II_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,16,5) else '0')
PYVER
)"
PUBLIC_DELIVERY_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,9) else '0')
PYVER
)"
PRODUCTION_RC_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,15,11) else '0')
PYVER
)"
PRODUCTION_DELIVERY_RELEASE_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,16,0) else '0')
PYVER
)"
WINDOWS_PROTECTION_RC_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,18,12) else '0')
PYVER
)"
WINDOWS_PROTECTION_GA_REQUIRED="$(python3 - "${VERSION}" <<'PYVER'
import sys
parts=sys.argv[1].split('.',2)
try:
    major,minor,patch=int(parts[0]),int(parts[1]),int(parts[2].split('-',1)[0].split('+',1)[0])
except Exception:
    print('0'); raise SystemExit
print('1' if (major,minor,patch) >= (0,19,0) else '0')
PYVER
)"
if [[ "${PRODUCTION_RC_REQUIRED}" == "1" ]]; then
  require git
  [[ -n "${COMPATIBILITY_MATRIX}" && -n "${DEVICE_TRUST_MATRIX}" && -n "${GUARD_CI_MATRIX}" ]] || {
    echo "Ошибка: ${VERSION} Production Release Candidate требует полный Compatibility + Device Trust + Guard CI certification cohort" >&2
    exit 1
  }
  require_file "${COMPATIBILITY_MATRIX}"
  require_file "${COMPATIBILITY_TARGETS}"
  require_file "${DEVICE_TRUST_MATRIX}"
  require_file "${DEVICE_TRUST_TARGETS}"
  require_file "${GUARD_CI_MATRIX}"
  require_file "${GUARD_CI_TARGETS}"
  git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "Ошибка: ${VERSION} Production Release Candidate должен собираться из git checkout" >&2
    exit 1
  }
  HEAD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  if [[ -z "${SOURCE_COMMIT}" ]]; then SOURCE_COMMIT="${HEAD_COMMIT}"; fi
  [[ "${SOURCE_COMMIT,,}" == "${HEAD_COMMIT,,}" ]] || {
    echo "Ошибка: LAUNCHER_SOURCE_COMMIT=${SOURCE_COMMIT} не совпадает с git HEAD=${HEAD_COMMIT}" >&2
    exit 1
  }
  [[ "${SOURCE_COMMIT}" =~ ^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$ ]] || {
    echo "Ошибка: некорректный exact source commit: ${SOURCE_COMMIT}" >&2
    exit 1
  }
  git -C "${ROOT_DIR}" diff --quiet HEAD -- || {
    echo "Ошибка: Production Release Candidate запрещает изменения tracked-файлов относительно HEAD" >&2
    exit 1
  }
  git -C "${ROOT_DIR}" diff --cached --quiet || {
    echo "Ошибка: Production Release Candidate запрещает staged изменения относительно HEAD" >&2
    exit 1
  }
fi
if [[ "${WINDOWS_PROTECTION_RC_REQUIRED}" == "1" ]]; then
  [[ -n "${WINDOWS_ADVERSARIAL_CERTIFICATE}" ]] || {
    echo "Ошибка: ${VERSION} Windows Protection RC требует LAUNCHER_WINDOWS_ADVERSARIAL_CERTIFICATE_FILE" >&2
    exit 1
  }
  require_file "${WINDOWS_ADVERSARIAL_CERTIFICATE}"
fi
if [[ "${PRODUCTION_DELIVERY_RELEASE_REQUIRED}" == "1" ]]; then
  [[ "${VERSION}" != *-* && "${VERSION}" != *+* ]] || {
    echo "Ошибка: Production Delivery Release требует GA SemVer без prerelease/build suffix: ${VERSION}" >&2
    exit 1
  }
  python3 - "${PUBLIC_RELEASE_BASE_URL}" "${VERSION}" <<'PYURL'
import sys, urllib.parse
raw, version = sys.argv[1], sys.argv[2]
u = urllib.parse.urlparse(raw)
segments = [urllib.parse.unquote(x) for x in u.path.split('/') if x]
if u.scheme != 'https' or not u.netloc or (version not in segments and ('v'+version) not in segments):
    raise SystemExit(f"Ошибка: Production Delivery Release требует HTTPS public origin с immutable version segment {version!r} или {'v'+version!r}: {raw}")
PYURL
fi

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  [[ -n "${LINUX_PRODUCTION_ARTIFACTS_DIR}" && -d "${LINUX_PRODUCTION_ARTIFACTS_DIR}" ]] || {
    echo "Ошибка: ${VERSION} production release требует LAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR с native x64+ARM64 outputs" >&2
    exit 1
  }
fi
if [[ "${MACOS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  [[ -n "${MACOS_PRODUCTION_ARTIFACTS_DIR}" && -d "${MACOS_PRODUCTION_ARTIFACTS_DIR}" ]] || {
    echo "Ошибка: ${VERSION} release bundle требует LAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR с macOS x64+ARM64 delivery outputs" >&2
    exit 1
  }
fi
if [[ "${MANAGED_JRE_REQUIRED}" == "1" ]]; then
  [[ -n "${MANAGED_JRE_ARTIFACTS_DIR}" && -d "${MANAGED_JRE_ARTIFACTS_DIR}" ]] || {
    echo "Ошибка: ${VERSION} release bundle требует LAUNCHER_MANAGED_JRE_ARTIFACTS_DIR с Managed JRE Distribution" >&2
    exit 1
  }
fi
if [[ "${GUARD_CERT_REQUIRED}" == "1" ]]; then
  [[ -n "${GUARD_CI_MATRIX}" && -n "${GUARD_CI_TARGETS}" && -n "${GUARD_PLATFORM_ARTIFACTS_DIR}" ]] || {
    echo "Ошибка: ${VERSION} production release требует LAUNCHER_GUARD_CI_MATRIX_FILE, LAUNCHER_GUARD_CI_TARGETS_FILE и LAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR" >&2
    exit 1
  }
  require_file "${GUARD_CI_MATRIX}"
  require_file "${GUARD_CI_TARGETS}"
  [[ -d "${GUARD_PLATFORM_ARTIFACTS_DIR}" ]] || { echo "Ошибка: Guard platform artifact directory отсутствует: ${GUARD_PLATFORM_ARTIFACTS_DIR}" >&2; exit 1; }
  python3 "${ROOT_DIR}/scripts/guard_ci/matrix.py" validate --targets "${GUARD_CI_TARGETS}"
fi
if [[ -n "${COMPATIBILITY_MATRIX}" ]]; then
  require_file "${COMPATIBILITY_MATRIX}"
  require_file "${COMPATIBILITY_TARGETS}"
fi
if [[ -n "${DEVICE_TRUST_MATRIX}" ]]; then
  require_file "${DEVICE_TRUST_MATRIX}"
  require_file "${DEVICE_TRUST_TARGETS}"
fi
if [[ -n "${COMPATIBILITY_MATRIX}" || -n "${DEVICE_TRUST_MATRIX}" || -n "${GUARD_CI_MATRIX}" ]]; then
  if [[ -z "${SOURCE_COMMIT}" ]] && command -v git >/dev/null 2>&1; then
    SOURCE_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || true)"
  fi
  if [[ -z "${SOURCE_COMMIT}" ]]; then
    echo "Ошибка: certified release требует LAUNCHER_SOURCE_COMMIT или git HEAD" >&2
    exit 1
  fi
fi

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" != "1" ]]; then
  log "Сборка legacy CLI linux/amd64"
  (
    cd "${ROOT_DIR}/cli"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/launcher-cli-linux-amd64" ./cmd/launcher
  )
  chmod +x "${OUT_DIR}/launcher-cli-linux-amd64"
fi

if [[ "${WINDOWS_DUAL_ARCH_REQUIRED}" != "1" ]]; then
  log "Сборка legacy CLI windows/amd64"
  (
    cd "${ROOT_DIR}/cli"
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/launcher-cli-windows-amd64.exe" ./cmd/launcher
  )
fi

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" != "1" ]]; then
  log "Сборка legacy Backend API linux/amd64 (production pgx, fail-closed)"
  (
    cd "${ROOT_DIR}/services/api"
    GOOS=linux GOARCH=amd64 CGO_ENABLED="${LAUNCHER_API_CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${SOURCE_COMMIT:-unknown}" -o "${OUT_DIR}/launcher-api-linux-amd64" ./cmd/launcher-api
  )
  chmod +x "${OUT_DIR}/launcher-api-linux-amd64"
fi
printf 'apiBuildMode=pgx-production\n' > "${OUT_DIR}/BUILD_NOTES.txt"

log "Сборка Admin Web"
(
  cd "${ROOT_DIR}/apps/admin"
  npm ci
  npm run build
)
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${ROOT_DIR}/apps/admin/dist" "${OUT_DIR}/launcher-admin-web-${VERSION}.zip" --prefix admin

log "Сборка Desktop Web и native binary"
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${ROOT_DIR}/apps/desktop/dist" "${OUT_DIR}/launcher-desktop-web-${VERSION}.zip" --prefix desktop
if [[ -n "${GUARD_CI_MATRIX}" ]]; then
  log "Импорт exact cross-platform Guard artifacts из certification run"
  python3 "${ROOT_DIR}/scripts/guard_ci/stage_release.py" \
    --matrix "${GUARD_CI_MATRIX}" \
    --artifacts-root "${GUARD_PLATFORM_ARTIFACTS_DIR}" \
    --out "${OUT_DIR}" \
    --expected-commit "${SOURCE_COMMIT}"
  if [[ "${WINDOWS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
    windows_delivery_source="${WINDOWS_SIGNED_ARTIFACTS_DIR:-${GUARD_PLATFORM_ARTIFACTS_DIR}/windows}"
    windows_delivery_source="$(bash "${ROOT_DIR}/scripts/release/resolve-artifact-payload.sh" \
      "${windows_delivery_source}" "${VERSION}" "launcher-cli-windows-x64.exe" "Windows x64/ARM64 delivery")"
    log "Импорт Windows x64/ARM64 delivery artifacts из ${windows_delivery_source}"
    for artifact in \
      "launcher-cli-windows-x64.exe" \
      "launcher-cli-windows-arm64.exe" \
      "launcher-desktop-windows-x64.exe" \
      "launcher-desktop-windows-arm64.exe" \
      "guard-windows-x64.exe" \
      "guard-windows-arm64.exe" \
      "guard-sensor-windows-x64.dll" \
      "guard-sensor-windows-arm64.dll" \
      "runtime-windows-x64.exe" \
      "runtime-windows-arm64.exe" \
      "launcher-desktop-${VERSION}-windows-x64.zip" \
      "launcher-desktop-${VERSION}-windows-arm64.zip" \
      "WINDOWS_PACKAGE_MANIFEST_X64.json" \
      "WINDOWS_PACKAGE_MANIFEST_ARM64.json" \
      "GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json" \
      "WINDOWS_SIGNING_EVIDENCE.json"; do
      require_file "${windows_delivery_source}/${artifact}"
      cp "${windows_delivery_source}/${artifact}" "${OUT_DIR}/${artifact}"
    done
  fi
  if [[ "${WINDOWS_PROTECTION_RC_REQUIRED}" == "1" ]]; then
    log "Импорт Windows adversarial certificate exact commit"
    cp "${WINDOWS_ADVERSARIAL_CERTIFICATE}" "${OUT_DIR}/WINDOWS_ADVERSARIAL_CERTIFICATE.json"
  fi
  if [[ "${LINUX_DUAL_ARCH_REQUIRED}" == "1" ]]; then
    linux_delivery_source="$(bash "${ROOT_DIR}/scripts/release/resolve-artifact-payload.sh" \
      "${LINUX_PRODUCTION_ARTIFACTS_DIR}" "${VERSION}" "launcher-cli-linux-x64" "Linux x64/ARM64 delivery")"
    log "Импорт native Linux x64/ARM64 production artifacts из ${linux_delivery_source}"
    for arch in x64 arm64; do
      for artifact in \
        "launcher-cli-linux-${arch}" \
        "launcher-api-linux-${arch}" \
        "launcher-desktop-linux-${arch}" \
        "guard-linux-${arch}" \
        "runtime-linux-${arch}" \
        "launcher-linux-${arch}-${VERSION}.tar.gz" \
        "LINUX_PACKAGE_MANIFEST_$(tr '[:lower:]' '[:upper:]' <<<"${arch}").json"; do
        require_file "${linux_delivery_source}/${artifact}"
        cp "${linux_delivery_source}/${artifact}" "${OUT_DIR}/${artifact}"
      done
      chmod 0755 \
        "${OUT_DIR}/launcher-cli-linux-${arch}" \
        "${OUT_DIR}/launcher-api-linux-${arch}" \
        "${OUT_DIR}/launcher-desktop-linux-${arch}" \
        "${OUT_DIR}/guard-linux-${arch}" \
        "${OUT_DIR}/runtime-linux-${arch}"
    done
  fi
  if [[ "${MACOS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
    macos_delivery_source="$(bash "${ROOT_DIR}/scripts/release/resolve-artifact-payload.sh" \
      "${MACOS_PRODUCTION_ARTIFACTS_DIR}" "${VERSION}" "launcher-cli-macos-x64" "macOS x64/ARM64 delivery")"
    log "Импорт macOS x64/ARM64 delivery artifacts из ${macos_delivery_source}"
    for arch in x64 arm64; do
      for artifact in \
        "launcher-cli-macos-${arch}" \
        "launcher-desktop-macos-${arch}" \
        "guard-macos-${arch}" \
        "runtime-macos-${arch}" \
        "launcher-desktop-${VERSION}-macos-${arch}.zip" \
        "MACOS_PACKAGE_MANIFEST_$(tr '[:lower:]' '[:upper:]' <<<"${arch}").json"; do
        require_file "${macos_delivery_source}/${artifact}"
        cp "${macos_delivery_source}/${artifact}" "${OUT_DIR}/${artifact}"
      done
      chmod 0755 \
        "${OUT_DIR}/launcher-cli-macos-${arch}" \
        "${OUT_DIR}/launcher-desktop-macos-${arch}" \
        "${OUT_DIR}/guard-macos-${arch}" \
        "${OUT_DIR}/runtime-macos-${arch}"
    done
    for artifact in MACOS_NOTARIZATION_EVIDENCE.json GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json; do
      require_file "${macos_delivery_source}/${artifact}"
      cp "${macos_delivery_source}/${artifact}" "${OUT_DIR}/${artifact}"
    done
  fi
else
  log "Сборка Linux Desktop + Guard production package"
  bash "${ROOT_DIR}/scripts/release/build-linux-desktop.sh" "${OUT_DIR}"
fi
for required_guard_artifact in \
  "launcher-desktop-linux-amd64" \
  "guard-linux-amd64" \
  "GUARD_RELEASE_ALLOWLIST_LINUX.json" \
  "LINUX_PACKAGE_MANIFEST.json" \
  "launcher-desktop-${VERSION}-linux-amd64.zip"; do
  require_file "${OUT_DIR}/${required_guard_artifact}"
done
if [[ -n "${GUARD_CI_MATRIX}" ]]; then
  for required_guard_artifact in \
    "launcher-desktop-windows-amd64.exe" \
    "guard-windows-amd64.exe" \
    "WINDOWS_PACKAGE_MANIFEST.json" \
    "GUARD_RELEASE_ALLOWLIST_WINDOWS.json" \
    "launcher-desktop-${VERSION}-windows-amd64.zip" \
    "launcher-desktop-macos-universal" \
    "guard-macos-universal" \
    "MACOS_PACKAGE_MANIFEST.json" \
    "GUARD_RELEASE_ALLOWLIST_MACOS.json" \
    "launcher-desktop-${VERSION}-macos-universal.zip"; do
    require_file "${OUT_DIR}/${required_guard_artifact}"
  done
fi

if [[ "${WINDOWS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  for required_windows_delivery in \
    "launcher-cli-windows-x64.exe" \
    "launcher-cli-windows-arm64.exe" \
    "launcher-desktop-windows-x64.exe" \
    "launcher-desktop-windows-arm64.exe" \
    "guard-windows-x64.exe" \
    "guard-windows-arm64.exe" \
    "guard-sensor-windows-x64.dll" \
    "guard-sensor-windows-arm64.dll" \
    "runtime-windows-x64.exe" \
    "runtime-windows-arm64.exe" \
    "launcher-desktop-${VERSION}-windows-x64.zip" \
    "launcher-desktop-${VERSION}-windows-arm64.zip" \
    "WINDOWS_PACKAGE_MANIFEST_X64.json" \
    "WINDOWS_PACKAGE_MANIFEST_ARM64.json" \
    "GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json" \
    "WINDOWS_SIGNING_EVIDENCE.json"; do
    require_file "${OUT_DIR}/${required_windows_delivery}"
  done
fi

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  for arch in x64 arm64; do
    for required_linux_delivery in \
      "launcher-cli-linux-${arch}" \
      "launcher-api-linux-${arch}" \
      "launcher-desktop-linux-${arch}" \
      "guard-linux-${arch}" \
      "runtime-linux-${arch}" \
      "launcher-linux-${arch}-${VERSION}.tar.gz" \
      "LINUX_PACKAGE_MANIFEST_$(tr '[:lower:]' '[:upper:]' <<<"${arch}").json"; do
      require_file "${OUT_DIR}/${required_linux_delivery}"
    done
  done
fi
if [[ "${MACOS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  for arch in x64 arm64; do
    for required_macos_delivery in \
      "launcher-cli-macos-${arch}" \
      "launcher-desktop-macos-${arch}" \
      "guard-macos-${arch}" \
      "runtime-macos-${arch}" \
      "launcher-desktop-${VERSION}-macos-${arch}.zip" \
      "MACOS_PACKAGE_MANIFEST_$(tr '[:lower:]' '[:upper:]' <<<"${arch}").json"; do
      require_file "${OUT_DIR}/${required_macos_delivery}"
    done
  done
  require_file "${OUT_DIR}/MACOS_NOTARIZATION_EVIDENCE.json"
  require_file "${OUT_DIR}/GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json"
fi

if [[ "${MANAGED_JRE_REQUIRED}" == "1" ]]; then
  log "Импорт Managed JRE Distribution из ${MANAGED_JRE_ARTIFACTS_DIR}"
  for artifact in MANAGED_JRE_MANIFEST.json MANAGED_JRE_EVIDENCE.json; do
    require_file "${MANAGED_JRE_ARTIFACTS_DIR}/${artifact}"
    cp "${MANAGED_JRE_ARTIFACTS_DIR}/${artifact}" "${OUT_DIR}/${artifact}"
  done
  if [[ "${MANAGED_JAVA_II_REQUIRED}" == "1" ]]; then
    require_file "${MANAGED_JRE_ARTIFACTS_DIR}/MANAGED_JAVA_II_EVIDENCE.json"
    cp "${MANAGED_JRE_ARTIFACTS_DIR}/MANAGED_JAVA_II_EVIDENCE.json" "${OUT_DIR}/MANAGED_JAVA_II_EVIDENCE.json"
  fi
  for platform in windows linux macos; do
    for arch in x64 arm64; do
      ext="tar.gz"
      [[ "${platform}" == "windows" ]] && ext="zip"
      artifact="launcher-jre-temurin21-${platform}-${arch}-${VERSION}.${ext}"
      require_file "${MANAGED_JRE_ARTIFACTS_DIR}/${artifact}"
      cp "${MANAGED_JRE_ARTIFACTS_DIR}/${artifact}" "${OUT_DIR}/${artifact}"
    done
  done
fi

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  RELEASE_CLI="${OUT_DIR}/launcher-cli-linux-x64"
else
  RELEASE_CLI="${OUT_DIR}/launcher-cli-linux-amd64"
fi
require_file "${RELEASE_CLI}"

if [[ "${MANAGED_JRE_REQUIRED}" == "1" ]]; then
  log "Проверка Managed JRE manifest/evidence и шести native Java targets"
  # DELIVERY_MANIFEST.json будет сформирован release build ниже; до этого проверяем source artifacts через production Go tests/static gate.
  python3 "${ROOT_DIR}/scripts/smoke/offline/managed-jre-distribution-0155.py"
fi

log "Формирование и проверка реального Desktop package"
"${RELEASE_CLI}" desktop package --version "${VERSION}" --artifact-dir "${OUT_DIR}" --out "${WORK_DIR}/desktop-package" --platform linux
"${RELEASE_CLI}" desktop verify "${WORK_DIR}/desktop-package"
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${WORK_DIR}/desktop-package" "${OUT_DIR}/launcher-desktop-package-${VERSION}.zip" --prefix desktop-package

if [[ "${LINUX_DUAL_ARCH_REQUIRED}" != "1" ]]; then
  log "Сборка legacy Runtime linux/amd64"
  cargo build --release --manifest-path "${ROOT_DIR}/runtime/runtime/Cargo.toml"
  require_file "${ROOT_DIR}/runtime/runtime/target/release/runtime"
  cp "${ROOT_DIR}/runtime/runtime/target/release/runtime" "${OUT_DIR}/runtime-linux-amd64"
  chmod +x "${OUT_DIR}/runtime-linux-amd64"
fi

log "Сборка ServerBridge JAR"
bash "${ROOT_DIR}/scripts/build/bridge-plugins.sh"
for bridge in velocity bungeecord waterfall bukkit spigot paper purpur folia fabric quilt forge neoforge sponge vanilla; do
  src="${ROOT_DIR}/artifacts/plugins/launcher-${bridge}-bridge-${VERSION}.jar"
  require_file "${src}"
  cp "${src}" "${OUT_DIR}/launcher-${bridge}-bridge-${VERSION}.jar"
done
require_file "${ROOT_DIR}/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json"
require_file "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json"
require_file "${ROOT_DIR}/artifacts/plugins/SERVERBRIDGE3_CERTIFICATION.json"
cp "${ROOT_DIR}/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json" "${OUT_DIR}/BRIDGE_RELEASE_ALLOWLIST.json"
cp "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json" "${OUT_DIR}/BRIDGE_PLUGIN_MANIFEST.json"
cp "${ROOT_DIR}/artifacts/plugins/SERVERBRIDGE3_CERTIFICATION.json" "${OUT_DIR}/SERVERBRIDGE3_CERTIFICATION.json"

# GA network acceptance consumes the exact JARs copied into OUT_DIR, not build
# intermediates. This gate stays required for every release from 0.42.0
# onward; changing VERSION must never silently skip the 14-target live proof.
if [[ "$(printf '%s\n' '0.42.0' "${VERSION}" | sort -V | head -n1)" == "0.42.0" ]]; then
  log "${VERSION}: verify exact final ServerBridge payload and full live network cycle"
  python3 "${ROOT_DIR}/scripts/ga/accept_network_release_0420.py" \
    --root "${ROOT_DIR}" --release "${OUT_DIR}" \
    --runtime "${LAUNCHER_NETWORK_LIVE_EVIDENCE_DIR:-${ROOT_DIR}/e2e/runtime}" \
    --source-commit "${SOURCE_COMMIT}" \
    --out "${OUT_DIR}/SERVER_NETWORK_ACCEPTANCE_0420.json"
fi

# 0.43.0+: build *executable* Java extension packages from SDK sources and
# certify their exact signed bytes against all six same-run JVM acceptance
# reports. Never issue a signed release solely on declared module parity.
if [[ "$(printf '%s\n' '0.43.0' "${VERSION}" | sort -V | head -n1)" == '0.43.0' ]]; then
  log "${VERSION}: build, sign and verify runnable Java Host and Gravit source-port .nlext"
  EXT_EVIDENCE="${LAUNCHER_EXTENSION_ACCEPTANCE_EVIDENCE_DIR:-}"
  EXT_KEY="${LAUNCHER_EXTENSION_PUBLISHER_PRIVATE_KEY_FILE:-}"
  EXT_PUBLIC="${LAUNCHER_EXTENSION_PUBLISHER_PUBLIC_KEY_FILE:-}"
  EXT_RUN="${LAUNCHER_EXTENSION_ACCEPTANCE_RUN_ID:-}"
  EXT_ATTEMPT="${LAUNCHER_EXTENSION_ACCEPTANCE_RUN_ATTEMPT:-}"
  [[ -d "${EXT_EVIDENCE}" && -f "${EXT_KEY}" && -f "${EXT_PUBLIC}" && -n "${EXT_RUN}" && -n "${EXT_ATTEMPT}" ]] || {
    echo "${VERSION} EXTENSION GA BLOCKED: requires six real platform reports, CI run/attempt and dedicated publisher signing identity" >&2
    exit 2
  }
  sh "${ROOT_DIR}/examples/extensions/java-host/build.sh"
  sh "${ROOT_DIR}/examples/extensions/gravit-compat/build.sh"
  for extension in java-host gravit-port; do
    if [[ "${extension}" == java-host ]]; then
      STAGE="${ROOT_DIR}/examples/extensions/java-host/build/package"
      FILE="launcher-example-java-host.nlext"
    else
      STAGE="${ROOT_DIR}/examples/extensions/gravit-compat/build/package"
      FILE="launcher-example-gravit-port.nlext"
    fi
    "${RELEASE_CLI}" extension pack "${STAGE}" --output "${OUT_DIR}/${FILE}" --private-key "${EXT_KEY}"
    "${RELEASE_CLI}" extension verify "${OUT_DIR}/${FILE}" --public-key "${EXT_PUBLIC}"
  done
  cp -- "${EXT_PUBLIC}" "${OUT_DIR}/EXTENSION_PUBLISHER_PUBLIC_KEY_0430.pem"
  python3 "${ROOT_DIR}/scripts/ga/extension_release_0430.py" \
    --evidence "${EXT_EVIDENCE}" --bundle "${OUT_DIR}" --cli "${RELEASE_CLI}" \
    --publisher-key "${EXT_PUBLIC}" --version "${VERSION}" \
    --commit "${SOURCE_COMMIT}" --run-id "${EXT_RUN}" --run-attempt "${EXT_ATTEMPT}" \
    --matrix "${ROOT_DIR}/compatibility/gravit/module-parity-04211.json" \
    --output "${OUT_DIR}/EXTENSION_RELEASE_CERTIFICATION_0430.json"
  # BOM/SHA256SUMS enumerate the flat release root. Bundle all seven raw
  # reports in one top-level ZIP so their exact bytes enter the signed BOM.
  python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${EXT_EVIDENCE}" \
    "${OUT_DIR}/EXTENSION_ACCEPTANCE_EVIDENCE_0430.zip"
fi

log "Source archive только из git-tracked/allowlisted файлов"
python3 "${ROOT_DIR}/scripts/release/source-package.py" "${ROOT_DIR}" "${OUT_DIR}/launcher-source-${VERSION}.zip" --list-file "${WORK_DIR}/source-files.txt"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-source-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-admin-web-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-web-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-package-${VERSION}.zip"
if [[ "${WINDOWS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-${VERSION}-windows-x64.zip"
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-${VERSION}-windows-arm64.zip"
fi
if [[ "${LINUX_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-linux-x64-${VERSION}.tar.gz"
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-linux-arm64-${VERSION}.tar.gz"
fi
if [[ "${MACOS_DUAL_ARCH_REQUIRED}" == "1" ]]; then
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-${VERSION}-macos-x64.zip"
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/launcher-desktop-${VERSION}-macos-arm64.zip"
fi

if [[ "${WINDOWS_PROTECTION_RC_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/WINDOWS_ADVERSARIAL_CERTIFICATE.json"
fi
if [[ "${WINDOWS_PROTECTION_GA_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/WINDOWS_ADVERSARIAL_CERTIFICATE.json"
fi

if [[ "${VERSION}" == "0.27.0" ]]; then
  [[ -s "${OFFICIAL_GA_RECEIPT}" ]] || { echo "missing signed official Minecraft GA receipt" >&2; exit 2; }
  cp "${OFFICIAL_GA_RECEIPT}" "${OUT_DIR}/OFFICIAL_MINECRAFT_GA_CERTIFICATION.json"
  log "Binding independent six-platform LIVE official Minecraft certification into signed manifest"
  python3 "${ROOT_DIR}/scripts/ga/verify_official_artifacts_0270.py" \
    --bundle "${OUT_DIR}" --receipt "${OUT_DIR}/OFFICIAL_MINECRAFT_GA_CERTIFICATION.json"
fi

# Final authorization is over the ACTUAL staged installer and executable bytes.
# A preflight receipt is never enough; verification here runs after packaging.
if [[ "${GA_TARGET_MODE}" != "historical" ]]; then
  if [[ "${GA_TARGET_MODE}" == "legacy-ga036" ]]; then
    GA_RECEIPT="GA_VERIFIED_TARGETS_0360.json"
    GA_APPROVAL="GA_TARGET_APPROVAL_0360.json"
    GA_SIGNATURE="GA_TARGET_APPROVAL_0360.sig"
  else
    GA_RECEIPT="GA_VERIFIED_TARGETS.json"
    GA_APPROVAL="GA_TARGET_APPROVAL.json"
    GA_SIGNATURE="GA_TARGET_APPROVAL.sig"
  fi
  python3 "${ROOT_DIR}/scripts/ga/verified_targets.py" \
    --bundle "${OUT_DIR}" --evidence "${GA_TARGET_EVIDENCE_DIR}" \
    --trusted-key "${GA_TARGET_TRUSTED_KEY}" \
    --version "${VERSION}" --commit "${SOURCE_COMMIT}" \
    --output "${OUT_DIR}/${GA_RECEIPT}"
  cp -- "${GA_TARGET_EVIDENCE_DIR}/approval.json" "${OUT_DIR}/${GA_APPROVAL}"
  cp -- "${GA_TARGET_EVIDENCE_DIR}/approval.sig" "${OUT_DIR}/${GA_SIGNATURE}"
  # 0.43.1+: ship the independently signed per-capability raw observations,
  # not only an aggregate 'security: PASS'. Publication rechecks this archive.
  if [[ "$(printf '%s\n' '0.43.1' "${VERSION}" | sort -V | head -n1)" == '0.43.1' ]]; then
    python3 "${ROOT_DIR}/scripts/ga/package_security_0431.py" \
      --evidence "${GA_TARGET_EVIDENCE_DIR}" --trusted-key "${GA_TARGET_TRUSTED_KEY}" \
      --version "${VERSION}" --commit "${SOURCE_COMMIT}" \
      --output "${OUT_DIR}/SECURITY_CAPABILITY_EVIDENCE_0431.zip"
  fi
fi

# 0.36.5+: inspect six actual signed/native packages and their inner payload
# against independently approved exact bytes BEFORE calculating SHA256SUMS.
# This receipt is included in the signed release boundary, never added later.
if python3 "${ROOT_DIR}/scripts/release/release_policy.py" requires-rehearsal --version "${VERSION}" | grep -qx '1'; then
  log "Репетиция конечной упаковки и проверка подписанных точных байтов"
  python3 "${ROOT_DIR}/scripts/release/rehearsal_0365.py" certify \
    --bundle "${OUT_DIR}" --evidence "${GA_TARGET_EVIDENCE_DIR}" \
    --trusted-key "${GA_TARGET_TRUSTED_KEY}" --commit "${SOURCE_COMMIT}" \
    --version "${VERSION}" --output "${OUT_DIR}/RELEASE_REHEARSAL_0365.json"
fi

log "Генерация RELEASE_MANIFEST/SHA256SUMS/SBOM/PROVENANCE"
release_build_args=(release build --version "${VERSION}" --out "${OUT_DIR}" --source-root "${ROOT_DIR}" --trust-policy "${TRUST_POLICY}" --public-base-url "${PUBLIC_RELEASE_BASE_URL}")
if [[ -n "${COMPATIBILITY_MATRIX}" ]]; then
  log "Встраивание machine-verifiable Minecraft Compatibility certification для commit ${SOURCE_COMMIT}"
  release_build_args+=(--compatibility-matrix "${COMPATIBILITY_MATRIX}" --compatibility-targets "${COMPATIBILITY_TARGETS}")
fi
if [[ -n "${DEVICE_TRUST_MATRIX}" ]]; then
  log "Встраивание machine-verifiable Device Trust certification для commit ${SOURCE_COMMIT}"
  release_build_args+=(--device-trust-matrix "${DEVICE_TRUST_MATRIX}" --device-trust-targets "${DEVICE_TRUST_TARGETS}")
fi
if [[ -n "${GUARD_CI_MATRIX}" ]]; then
  log "Встраивание cross-platform Guard CI certification для commit ${SOURCE_COMMIT}"
  release_build_args+=(--guard-ci-matrix "${GUARD_CI_MATRIX}" --guard-ci-targets "${GUARD_CI_TARGETS}")
fi
if [[ -n "${SOURCE_COMMIT}" ]]; then
  release_build_args+=(--source-commit "${SOURCE_COMMIT}")
fi
"${RELEASE_CLI}" "${release_build_args[@]}"
if [[ "${PUBLIC_DELIVERY_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/PUBLIC_PRODUCTION_DELIVERY_MATRIX.json"
  "${RELEASE_CLI}" delivery verify-public-matrix --bundle "${OUT_DIR}" --version "${VERSION}"
fi
if [[ "${WINDOWS_PROTECTION_RC_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json"
  log "Проверка Windows Protection RC certificate до release signing"
  "${RELEASE_CLI}" release windows-protection-verify "${OUT_DIR}"
fi
if [[ "${WINDOWS_PROTECTION_GA_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/WINDOWS_PROTECTION_GA_CERTIFICATE.json"
  log "Проверка Windows Protection GA certificate до release signing"
  "${RELEASE_CLI}" release windows-protection-ga-verify "${OUT_DIR}"
fi
if [[ "${PRODUCTION_RC_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/PRODUCTION_RELEASE_CANDIDATE.json"
  log "Проверка production release candidate cohort до подписи"
  "${RELEASE_CLI}" release candidate-verify "${OUT_DIR}"
fi
if [[ "${PRODUCTION_DELIVERY_RELEASE_REQUIRED}" == "1" ]]; then
  require_file "${OUT_DIR}/PRODUCTION_DELIVERY_RELEASE.json"
  log "Проверка stable Production Delivery Release boundary до подписи"
  "${RELEASE_CLI}" release production-verify "${OUT_DIR}"
fi

if [[ "${VERSION}" == "0.25.0" ]]; then
  [[ -s "${COMPONENTS_GA_RECEIPT}" ]] || { echo "missing authenticated component GA receipt" >&2; exit 2; }
  cp "${COMPONENTS_GA_RECEIPT}" "${OUT_DIR}/OPTIONAL_COMPONENTS_GA_CERTIFICATION.json"
  log "Authenticated all six real-platform signed Optional Components GA attestations"
fi

log "Ed25519 release signing"
"${RELEASE_CLI}" release sign "${OUT_DIR}" --private-key "${PRIVATE_KEY}"

log "Строгая проверка required artifacts/checksums/Ed25519 trust anchor"
"${RELEASE_CLI}" release verify "${OUT_DIR}" --public-key "${PUBLIC_KEY}" --trust-state "${TRUST_STATE}" --trust-policy "${TRUST_POLICY}"
if [[ "${GA_TARGET_MODE}" != "historical" ]]; then
  [[ -s "${OUT_DIR}/${GA_RECEIPT}" && -s "${OUT_DIR}/${GA_APPROVAL}" && -s "${OUT_DIR}/${GA_SIGNATURE}" ]] || {
    echo "${VERSION} GA BLOCKED: missing independently verified exact-byte approval" >&2; exit 2;
  }
  [[ -n "${COMPATIBILITY_MATRIX}" && -n "${DEVICE_TRUST_MATRIX}" && -n "${GUARD_CI_MATRIX}" ]] || {
    echo "${VERSION} GA BLOCKED: all three protected publish certifications required" >&2; exit 2;
  }
fi
if [[ -n "${COMPATIBILITY_MATRIX}" && -n "${DEVICE_TRUST_MATRIX}" && -n "${GUARD_CI_MATRIX}" ]]; then
  log "Publish-check Minecraft Compatibility + Device Trust Release + cross-platform Guard CI certification"
  "${RELEASE_CLI}" release publish-check "${OUT_DIR}" --public-key "${PUBLIC_KEY}" --trust-state "${TRUST_STATE}" --trust-policy "${TRUST_POLICY}"
  if python3 "${ROOT_DIR}/scripts/release/release_policy.py" requires-rehearsal --version "${VERSION}" | grep -qx '1'; then
    log "Публикационный dry-run: физическое копирование релиза, повторная проверка подписи и publish-check"
    python3 "${ROOT_DIR}/scripts/release/rehearsal_0365.py" dry-run \
      --bundle "${OUT_DIR}" --evidence "${GA_TARGET_EVIDENCE_DIR}" \
      --trusted-key "${GA_TARGET_TRUSTED_KEY}" --commit "${SOURCE_COMMIT}" \
      --version "${VERSION}" --cli "${RELEASE_CLI}" --public-key "${PUBLIC_KEY}" \
      --trust-policy "${TRUST_POLICY}" --trust-state "${TRUST_STATE}" \
      --stage "${WORK_DIR}/publication-dry-run" \
      --output "${WORK_DIR}/PUBLICATION_DRY_RUN_0365.json"
  fi
elif [[ -n "${COMPATIBILITY_MATRIX}" || -n "${DEVICE_TRUST_MATRIX}" || -n "${GUARD_CI_MATRIX}" ]]; then
  log "Передан неполный certification set: официальный publish-check ${VERSION} требует Compatibility, Device Trust и Guard CI evidence"
else
  log "Certification evidence не передан: bundle не является publishable release"
fi

log "Каталог production-релиза готов: ${OUT_DIR}"
