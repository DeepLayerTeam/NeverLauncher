#!/usr/bin/env bash
# Live CLI/RemoteControl fault regression. Requires Go >=1.22 and OpenJDK 21.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/cli"
: "${GOTOOLCHAIN:=local}"
export GOTOOLCHAIN

go test -race ./cmd/neverlauncher -count=1 -timeout 90s -run '^(TestRemoteFault.*04112|TestRemoteControlIdempotencyAndUnknown0284|TestRemoteControlConcurrentDelivery0284|TestRemoteKeyRotationLiveAndLease0284)$'
go test ./cmd/neverlauncher -count=1 -timeout 90s -run '^TestHostLifecycle0414(RealJVMStartStopRestartAndSIGTERM|RealJVMAutoRecoveryAfterCrash|RealJVMCrashLoopIsBounded|StopWhileJavaCrashIsInBackoff)$'
cd "$ROOT"
GO111MODULE=off go test -race services/api/internal/hostcontrol/remote_0413.go services/api/internal/hostcontrol/remote_0413_test.go
