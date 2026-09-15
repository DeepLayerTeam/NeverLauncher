#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}"

# Source ZIPs do not reliably preserve Unix executable bits. Release gates invoke
# shell scripts explicitly via bash, so validate presence + syntax rather than a
# filesystem mode bit that is unrelated to script correctness.
for script in scripts/release/preflight.sh scripts/test/run-release-smoke.sh scripts/build/bridge-plugins.sh scripts/release/build-release.sh scripts/smoke/release-required/release-bundle.sh; do
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
  scripts/release/zip-dir.py
