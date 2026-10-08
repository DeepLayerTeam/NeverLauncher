#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}"

# Source ZIPs do not reliably preserve Unix executable bits. Release gates invoke
# shell scripts explicitly via bash, so validate presence + syntax rather than a
# filesystem mode bit that is unrelated to script correctness.
for script in scripts/release/preflight.sh scripts/test/run-release-smoke.sh scripts/build/bridge-plugins.sh scripts/release/build-release.sh scripts/release/build-linux-production.sh scripts/smoke/release-required/release-bundle.sh; do
  test -f "$script"
  bash -n "$script"
done
bash -n scripts/smoke/offline/cli-tests.sh
bash -n scripts/smoke/offline/backend-tests.sh
bash -n scripts/smoke/offline/cli-build.sh
bash -n scripts/smoke/offline/backend-build.sh
bash -n scripts/smoke/offline/version-alignment.sh

python3 -m py_compile \
  scripts/smoke/offline/repository-policy.py \
  scripts/release/source-package.py \
  scripts/release/secret-scan.py \
  scripts/release/zip-dir.py \
  scripts/release/linux-package.py \
  scripts/guard_ci/matrix.py \
  scripts/guard_ci/stage_release.py \
  scripts/guard_ci/test_matrix.py \
  scripts/smoke/offline/guard-ci-release-certification-0139.py \
  scripts/smoke/offline/linux-x64-arm64-production-packages-0153.py

# The source package is a production artifact, not just a syntax-checked helper.
# Verify that current policy/certification inputs and the canonical bridge build
# entrypoint survive the allowlist used by build-release.sh.
source_package_tmp="$(mktemp -d)"
trap 'rm -rf "${source_package_tmp}"' EXIT
python3 scripts/release/source-package.py \
  "${ROOT_DIR}" \
  "${source_package_tmp}/neverlauncher-source.zip" \
  --list-file "${source_package_tmp}/source-files.txt"
for required in \
  compatibility/targets.json \
  device-trust/targets.json \
  guard-ci/targets.json \
  serverbridge/targets.json \
  serverbridge/certify_release.py \
  scripts/build/bridge-plugins.sh; do
  grep -Fxq "${required}" "${source_package_tmp}/source-files.txt"
done
python3 scripts/release/secret-scan.py "${source_package_tmp}/neverlauncher-source.zip"
python3 - <<'PY'
import importlib.util
from pathlib import Path

root = Path.cwd()
spec = importlib.util.spec_from_file_location("source_package", root / "scripts/release/source-package.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for rel in [
    "compatibility/targets.json",
    "device-trust/targets.json",
    "guard-ci/targets.json",
    "serverbridge/targets.json",
    "scripts/build/bridge-plugins.sh",
]:
    assert module.safe_rel(rel), rel
for rel in [
    "scripts/release/__pycache__/source-package.cpython-313.pyc",
    "apps/admin/node_modules/pkg/index.js",
    "apps/desktop/dist/index.html",
    "runtime/neverruntime/target/release/neverruntime",
    "e2e/reports/result.json",
    "deploy/production/certs/server.pem",
    "cli/nl",
    "services/api/neverlauncher-api",
    "apps/admin/.env.local",
    "scripts/release/debug.log",
]:
    assert not module.safe_rel(rel), rel
PY
