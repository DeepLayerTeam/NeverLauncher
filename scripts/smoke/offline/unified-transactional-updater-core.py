#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 6):
    raise SystemExit(
        f"Единое ядро транзакционного обновления: требуется версия не ниже 0.15.6, получено {VERSION}"
    )


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


core_go = read("cli/cmd/launcher/transactional_updater.go")
require(
    core_go,
    [
        'const updaterCoreDir0156 = ".launcher/updater"',
        "prepareLocked",
        "commitLocked",
        "rollbackLocked",
        "recoverIncompleteLocked",
        'journal.Phase = "committing"',
        'journal.Phase = "verifying"',
        'journal.Phase = "committed"',
        'journal.Phase = "rolling-back"',
        'journal.Phase = "rolled-back"',
        "Источник должен быть обычным файлом, а не символической ссылкой",
        "updater refuses symlink parent",
        "replaceFileAtomicPortable",
        "Sync()",
        "updaterProcessAlive0156",
    ],
    "Ядро транзакционного обновления",
)

command_go = read("cli/cmd/launcher/transactional_updater_command.go")
require(
    command_go,
    [
        "applyManifestUpdate0156",
        "runUpdaterSelfTest0156",
        "verified-staging",
        "same-filesystem-switch",
        "automatic-rollback",
        "durable-journal",
    ],
    "Команды транзакционного обновления",
)

main_go = read("cli/cmd/launcher/main.go")
require(
    main_go,
    ['case "apply":', 'case "status":', 'case "recover":', 'case "self-test":'],
    "Интеграция CLI обновления",
)

client = read("cli/cmd/launcher/client_lifecycle.go") + read(
    "cli/cmd/launcher/package_commands.go"
)
require(
    client,
    [
        "clientPackageConsumeTransactional0156",
        "client-repair",
        "client-rollback",
        'updaterCore":      "unified-transactional-updater/0.15.6"',
        "rollbackSnapshot",
        "removedFiles",
        ".launcher/client-state.json",
    ],
    "Интеграция обновления клиента",
)

windows_lock = read("cli/cmd/launcher/transactional_updater_process_windows.go")
unix_lock = read("cli/cmd/launcher/transactional_updater_process_unix.go")
require(
    windows_lock,
    [
        "OpenProcess",
        "PROCESS_QUERY_LIMITED_INFORMATION".lower().replace("_", "")
        if False
        else "processQueryLimitedInformation",
    ],
    "Блокировка обновления Windows",
)
require(unix_lock, ["syscall.Signal(0)", "syscall.EPERM"], "Блокировка обновления Unix")

tests = read("cli/cmd/launcher/transactional_updater_test.go")
require(
    tests,
    [
        "TestTransactionalUpdaterCommitAndDelete0156",
        "TestTransactionalUpdaterPostVerifyFailureRollsBack0156",
        "TestTransactionalUpdaterCrashRecovery0156",
        "TestTransactionalUpdaterRejectsTraversal0156",
    ],
    "Регрессионные тесты транзакционного обновления",
)

ci = read(".github/workflows/ci.yml")
for required in [
    "unified-transactional-updater-core.py",
    "update self-test",
    'launcher-cli-linux-${{ matrix.arch }}" update self-test',
]:
    if required not in ci:
        raise SystemExit(f"Отсутствует: «проверка обновления в CI»: {required}")

preflight = read("scripts/release/preflight.sh")
if "unified-transactional-updater-core.py" not in preflight:
    raise SystemExit("Отсутствует: «предварительная проверка обновления»")

subprocess.run(
    [
        "go",
        "test",
        "./cmd/launcher",
        "-run",
        "TestTransactionalUpdater|TestClientLifecycleInstallRepairCleanupRollback",
        "-count=1",
    ],
    cwd=ROOT / "cli",
    check=True,
)

print(f"Launcher {VERSION}: проверка ядра единого транзакционного обновления: OK")
print('Unified Transactional Updater Core gate: OK')
