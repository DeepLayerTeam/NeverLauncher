#!/usr/bin/env bash
# Выполняйте настоящие тесты хоста/JVM/отказов и полный Minecraft E2E для 14
# целей. Принцип безопасного отказа: отсутствие Docker/JAR/Go/Java нельзя компенсировать
# заглушками.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_COMMIT="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)}"
[[ "$SOURCE_COMMIT" =~ ^[a-f0-9]{40}$ || "$SOURCE_COMMIT" =~ ^[a-f0-9]{64}$ ]] || {
  echo '0.42.0: требуется точный коммит исходного кода' >&2; exit 2;
}
[[ "$(cat "$ROOT/VERSION")" == 0.42.0 ]] || { echo 'Неверная версия исходного кода' >&2; exit 2; }
# Раннер E2E очищает Runtime; запускайте тесты отказов ПОСЛЕ него, а не до.
GITHUB_SHA="$SOURCE_COMMIT" LAUNCHER_E2E_MODE=full bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
mkdir -p "$ROOT/e2e/runtime"
(
  cd "$ROOT/cli"
  GOTOOLCHAIN=local go test -json -race -count=1 -timeout 240s ./cmd/launcher \
    -run '^(TestRemoteFault.*04112|TestHostLifecycle0414(RealJVMStartStopRestartAndSIGTERM|RealJVMAutoRecoveryAfterCrash|RealJVMCrashLoopIsBounded|ActualCLIAndRemoteEffects|StopWhileJavaCrashIsInBackoff)|TestWorldBackup(CreateVerifyRestore02810|GateBlocksStartAndSecondBackup04110|GateFailsClosedAndRecoversOffline04110))$'
) > "$ROOT/e2e/runtime/network-faults-0420.go-test.jsonl"
python3 "$ROOT/scripts/ga/record_network_faults.py" \
  --log "$ROOT/e2e/runtime/network-faults-0420.go-test.jsonl" \
  --source-commit "$SOURCE_COMMIT" --version 0.42.0 \
  --out "$ROOT/e2e/runtime/network-faults-0420.json"
python3 "$ROOT/serverbridge/live_matrix.py" --scope all --root "$ROOT" \
  --runtime "$ROOT/e2e/runtime" \
  --out "$ROOT/e2e/runtime/live-matrix-all-0420.json"
printf '0.42.0: выполнены реальные испытания сбоев JVM/хоста и полная матрица Minecraft\n'
