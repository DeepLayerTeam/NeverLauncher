#!/usr/bin/env python3
"""Запуск настоящих сценариев приёмки Launcher 0.30.12 через подпроцессы.

Раннер выполняет фиксированный проверенный список разрешённых команд. Наличие исходника или
пропущенный тест не превращаются в успех; отчёт не является сертификатом паритета Gravit. Учётные
данные, исходный вывод подпроцессов и секреты не сохраняются.
"""

from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]

# Каждый сценарий выполняет настоящий код, включая отрицательные и атакующие тесты своего набора.
# Команды неизменяемы и не берутся из расширения или манифеста пользователя.
CASES = {
    "java-sdk": (("sh", "sdk/java/core/build.sh", "test"),),
    "jvm-host-e2e": (
        ("sh", "examples/extensions/java-host/build.sh"),
        (sys.executable, "examples/extensions/java-host/test-runner.py"),
    ),
    "gravit-e2e": (
        ("sh", "examples/extensions/gravit-compat/build.sh"),
        (sys.executable, "examples/extensions/gravit-compat/test-runner.py"),
    ),
    "java-lifecycle-e2e": (
        ("sh", "examples/extensions/java-lifecycle/build.sh"),
        (sys.executable, "examples/extensions/java-lifecycle/test-runner.py"),
    ),
    "java-runtime-e2e": (
        ("sh", "examples/extensions/java-runtime/build.sh"),
        (sys.executable, "examples/extensions/java-runtime/test-runner.py"),
    ),
    "java-supervisor-go": (
        ("sh", "examples/extensions/java-host/build.sh"),
        (
            "go",
            "test",
            "-v",
            "-race",
            "-count=1",
            "-timeout",
            "3m",
            "-run",
            "TestJava.*0304|TestSupervisor.*03012",
            "./internal/extensionhost",
        ),
    ),
    "trusted-agent-e2e": (
        ("sh", "examples/extensions/trusted-jvm/build.sh"),
        (
            "go",
            "test",
            "-v",
            "-count=1",
            "-timeout",
            "4m",
            "-run",
            "^TestTrustedJVM0306",
            "./cmd/launcher",
        ),
    ),
    "devtools-e2e": (
        ("go", "build", "-o", "{cli}", "./cmd/launcher"),
        (sys.executable, "scripts/devtools/smoke_03010.py", "--cli", "{cli}"),
    ),
    "lan-security": (("go", "test", "-v", "-race", "-count=1", "./internal/lanmdns"),),
    "discord-ipc": (
        ("go", "test", "-v", "-race", "-count=1", "./internal/discordrpc"),
    ),
    "devtools-security": (
        ("go", "test", "-v", "-race", "-count=1", "./internal/devtools"),
    ),
    "sentry-backend": (
        ("go", "test", "-v", "-race", "-count=1", "./internal/sentrydiag"),
    ),
    "asset-integrity": (
        ("node", "--test", "scripts/desktop/prebuild_assets_03011.test.mjs"),
        (
            "node",
            "--experimental-strip-types",
            "--test",
            "scripts/desktop/startup_prewarmer_03011.test.mjs",
        ),
    ),
    "sentry-release": (
        (sys.executable, "scripts/diagnostics/test_upload_release_0309.py"),
    ),
    "module-parity": (
        ("go", "build", "-o", "{cli}", "./cmd/launcher"),
        (
            "{cli}",
            "module-parity",
            "audit",
            "--root",
            "{root}",
            "--baseline",
            "0.30.12",
            "--module",
            "M02,M04,M13,M14,M15,M17,M18,M19",
            "--run-tests",
            "--require-tests",
            "--timeout",
            "120s",
            "--report",
            "{parity}",
        ),
    ),
}
CLI_CASES = {
    "trusted-agent-e2e",
    "devtools-e2e",
    "lan-security",
    "discord-ipc",
    "devtools-security",
    "module-parity",
}
API_CASES = {"java-supervisor-go", "sentry-backend"}


def case_directory(name: str) -> Path:
    if name in API_CASES:
        return ROOT / "services/api"
    if name in CLI_CASES:
        return ROOT / "cli"
    return ROOT


def run_cases(
    names: list[str], report_path: Path, *, timeout: float, cli: str, commit: str
) -> dict:
    if len(names) != len(set(names)) or not names or any(x not in CASES for x in names):
        raise ValueError("Список тестовых сценариев пуст, содержит дубликаты или неизвестные сценарии")
    if timeout <= 0:
        raise ValueError("Тайм-аут должен быть положительным")
    report_path = report_path.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schemaVersion": "1.0",
        "release": "0.30.12",
        "platform": platform.system().lower(),
        "architecture": platform.machine(),
        "revision": commit,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "results": [],
        "passed": False,
        "fullyCertified": False,
    }
    # Вызывающая сторона должна указать закрытый промежуточный каталог. Не помещайте
    # исполняемые вспомогательные программы и отчёты в дерево исходников.
    replacements = {
        "{cli}": cli,
        "{root}": str(ROOT),
        "{parity}": str(report_path.with_suffix(".parity.json")),
    }
    for name in names:
        started = time.monotonic()
        entry = {"case": name, "status": "failed", "steps": [], "elapsedSeconds": 0}
        report["results"].append(entry)
        for cmd in CASES[name]:
            command = [replacements.get(arg, arg) for arg in cmd]
            cwd = case_directory(name) if command[0] == "go" else ROOT
            try:
                # Эта фикстура обязательна для реального теста Go-супервизор → дочерняя
                # JVM. Без неё Go t.Skip создаст ложный успех.
                env = os.environ.copy()
                if name == "java-supervisor-go":
                    env["LAUNCHER_TEST_JAVA_HOST_JAR"] = str(
                        (
                            ROOT
                            / "examples/extensions/java-host/build/package/backend/java-host.jar"
                        ).resolve()
                    )
                # По тайм-ауту убивайте всю группу процессов POSIX; один subprocess.run
                # завершит shell, но может оставить дочерние Java/Go.
                if os.name == "posix":
                    proc = subprocess.Popen(
                        command,
                        cwd=cwd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        start_new_session=True,
                        env=env,
                    )
                    try:
                        out, err = proc.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        import signal

                        os.killpg(proc.pid, signal.SIGKILL)
                        out, err = proc.communicate()
                        code, outcome = -1, "timeout"
                    else:
                        code, outcome = (
                            proc.returncode,
                            "passed" if proc.returncode == 0 else "failed",
                        )
                else:
                    result = subprocess.run(
                        command, cwd=cwd, capture_output=True, timeout=timeout, env=env
                    )
                    out, err = result.stdout, result.stderr
                    code, outcome = (
                        result.returncode,
                        "passed" if result.returncode == 0 else "failed",
                    )
            except subprocess.TimeoutExpired:
                out, err, code, outcome = b"", b"", -1, "timeout"
            except (OSError, ValueError) as exc:
                out, err, code, outcome = (
                    b"",
                    str(type(exc).__name__).encode(),
                    -1,
                    "failed",
                )
            # Успешный go test с пропущенными тестами, зависящими от фикстур, не
            # доказывает выполнение JVM или безопасности платформы.
            if command[0] == "go" and "test" in command:
                if b"--- SKIP:" in out or b"[no tests to run]" in out:
                    outcome = "skipped"
            entry["steps"].append(
                {
                    "command": command,
                    "exitCode": code,
                    "status": outcome,
                    "outputSha256": hashlib.sha256(out + b"\x00" + err).hexdigest(),
                }
            )
            print(f"{name}: {outcome} (exit={code}) {' '.join(command)}", flush=True)
            if outcome != "passed":
                break
        if len(entry["steps"]) == len(CASES[name]) and all(
            s["status"] == "passed" for s in entry["steps"]
        ):
            entry["status"] = "passed"
        entry["elapsedSeconds"] = round(time.monotonic() - started, 3)
        # Записывайте после каждого сценария даже при ошибке: доказательства сбоя сохранятся после прерывания CI.
        report["passed"] = len(report["results"]) == len(names) and all(
            x["status"] == "passed" for x in report["results"]
        )
        tmp = report_path.with_name(report_path.name + ".tmp")
        tmp.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        tmp.replace(report_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases", default=",".join(CASES), help="Точные ID сценариев через запятую"
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument(
        "--cli", default="", help="Абсолютный путь для сборки/запуска nl"
    )
    parser.add_argument("--revision", default="unknown")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        print("\n".join(CASES))
        return 0
    if args.report is None:
        parser.error("Параметр --report обязателен, если не указан --list")
    names = args.cases.split(",")
    if any(x in {"devtools-e2e", "module-parity"} for x in names) and not (
        args.cli and Path(args.cli).is_absolute()
    ):
        parser.error("Для сценариев CLI параметр --cli должен содержать абсолютный путь к подготовленному исполняемому файлу")
    try:
        result = run_cases(
            names, args.report, timeout=args.timeout, cli=args.cli, commit=args.revision
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
