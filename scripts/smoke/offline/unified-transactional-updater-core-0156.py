#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 6):
    raise SystemExit(f"Unified Transactional Updater Core gate requires VERSION>=0.15.6, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


core_go = read("cli/cmd/neverlauncher/transactional_updater.go")
require(
    core_go,
    [
        'const updaterCoreDir0156 = ".neverlauncher/updater"',
        'prepareLocked',
        'commitLocked',
        'rollbackLocked',
        'recoverIncompleteLocked',
        'journal.Phase = "committing"',
        'journal.Phase = "verifying"',
        'journal.Phase = "committed"',
        'journal.Phase = "rolling-back"',
        'journal.Phase = "rolled-back"',
        'source должен быть regular file и не symlink',
        'updater refuses symlink parent',
        'replaceFileAtomicPortable',
        'Sync()',
        'updaterProcessAlive0156',
    ],
    "transactional updater core",
)

command_go = read("cli/cmd/neverlauncher/transactional_updater_command.go")
require(
    command_go,
    [
        'applyManifestUpdate0156',
        'runUpdaterSelfTest0156',
        'verified-staging',
        'same-filesystem-switch',
        'automatic-rollback',
        'durable-journal',
    ],
    "transactional updater commands",
)

main_go = read("cli/cmd/neverlauncher/main.go")
require(
    main_go,
    ['case "apply":', 'case "status":', 'case "recover":', 'case "self-test":'],
    "update CLI integration",
)

client = read("cli/cmd/neverlauncher/client_lifecycle.go") + read("cli/cmd/neverlauncher/package_commands.go")
require(
    client,
    [
        'clientPackageConsumeTransactional0156',
        'client-repair',
        'client-rollback',
        'updaterCore":      "unified-transactional-updater/0.15.6"',
        'rollbackSnapshot',
        'removedFiles',
        '.neverlauncher/client-state.json',
    ],
    "client updater integration",
)

windows_lock = read("cli/cmd/neverlauncher/transactional_updater_process_windows.go")
unix_lock = read("cli/cmd/neverlauncher/transactional_updater_process_unix.go")
require(windows_lock, ['OpenProcess', 'PROCESS_QUERY_LIMITED_INFORMATION'.lower().replace('_', '') if False else 'processQueryLimitedInformation'], "Windows updater lock")
require(unix_lock, ['syscall.Signal(0)', 'syscall.EPERM'], "Unix updater lock")

tests = read("cli/cmd/neverlauncher/transactional_updater_test.go")
require(
    tests,
    [
        'TestTransactionalUpdaterCommitAndDelete0156',
        'TestTransactionalUpdaterPostVerifyFailureRollsBack0156',
        'TestTransactionalUpdaterCrashRecovery0156',
        'TestTransactionalUpdaterRejectsTraversal0156',
    ],
    "transactional updater regression tests",
)

ci = read(".github/workflows/ci.yml")
for required in [
    'unified-transactional-updater-core-0156.py',
    'update self-test',
    'neverlauncher-cli-linux-${{ matrix.arch }}" update self-test',
]:
    if required not in ci:
        raise SystemExit(f"CI updater gate missing: {required}")

preflight = read("scripts/release/preflight.sh")
if "unified-transactional-updater-core-0156.py" not in preflight:
    raise SystemExit("preflight updater gate missing")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestTransactionalUpdater|TestClientLifecycleInstallRepairCleanupRollback", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Unified Transactional Updater Core gate: OK")
