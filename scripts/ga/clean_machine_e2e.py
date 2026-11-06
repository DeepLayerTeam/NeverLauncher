#!/usr/bin/env python3
"""Выполнить *настоящую* цепочку на чистой VM: нативная установка -> Managed Java -> запуск Minecraft.

Никаких заглушек Runtime или поддельных JVM: установленный бинарный Runtime проверяет подпись
манифеста, реально подготавливает Java, синхронизирует файлы и запускает игру. Требуется одноразовая
VM ОС с графическим сеансом и подписанным профилем Minecraft для автономной работы, а не рабочая
станция разработчика.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


def checked(command, timeout=900, env=None):
    result = subprocess.run(
        list(map(str, command)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
        env=env,
    )
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} завершилась с кодом {result.returncode}: {result.stderr[-1000:]}"
        )
    return result.stdout


def from_runtime(binary: Path, *args, timeout=900):
    data = checked([binary, *args], timeout=timeout)
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("Runtime вернул JSON, не являющийся объектом")
    return result


def resolve_installed_runtime(root: Path):
    launcher = root / "launcher"
    for slot in ("active-0.json", "active-1.json"):
        pointer = launcher / slot
        if not pointer.is_file() or pointer.is_symlink():
            continue
        rec = json.loads(pointer.read_text())
        release = rec.get("release", "")
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", release) or ".." in release:
            continue
        path = (
            launcher
            / "releases"
            / release
            / ("runtime.exe" if os.name == "nt" else "runtime")
        )
        if path.is_file() and not path.is_symlink():
            return path
    raise RuntimeError("В активированном выпуске Prestarter отсутствует нативный Runtime")


def real_clean_install(
    *,
    installer: Path,
    root: Path,
    signed_manifest: Path,
    public_key: str,
    java_major: int,
    username: str,
    benchmark_commit: str,
):
    if not re.fullmatch("[0-9a-f]{64}", public_key):
        raise ValueError("Требуется закреплённый публичный ключ")
    if not re.fullmatch("[a-zA-Z0-9_]{3,16}", username):
        raise ValueError("Имя игрока Minecraft в автономном режиме должно содержать 3–16 допустимых символов")
    if not re.fullmatch("[a-f0-9]{40}", benchmark_commit):
        raise ValueError("Необходимо указать точный commit исходного кода")
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("Для GA-теста чистой установки нужен ПУСТОЙ каталог установки")
    if os.environ.get("JAVA_HOME"):
        raise RuntimeError("Для теста запуска на чистом компьютере переменная JAVA_HOME должна быть не задана")
    if not signed_manifest.is_file() or signed_manifest.is_symlink():
        raise RuntimeError("Требуется настоящий подписанный профиль Minecraft")
    # Установка пакета намеренно реальная, а не простая распаковка файлов.
    osname = platform.system()
    if osname == "Linux":
        if os.geteuid() != 0:
            raise RuntimeError(
                "Для чистой установки через dpkg требуются права root внутри временной виртуальной машины"
            )
        checked(["dpkg", "--install", installer], timeout=600)
        checked(
            ["/usr/bin/launcher", "install", "--root", root, "--no-start"],
            timeout=1200,
        )
    elif osname == "Darwin":
        checked(["installer", "-pkg", installer, "-target", "/"], timeout=600)
        checked(
            [
                "/Applications/Launcher.app/Contents/MacOS/Launcher",
                "install",
                "--root",
                root,
                "--no-start",
            ],
            timeout=1200,
        )
    elif osname == "Windows":
        checked([installer, "install", "--root", root, "--no-start"], timeout=1200)
        # Нативный Rust CLI может запускать Minecraft в Windows, но обходит
        # аутентифицированную границу Desktop → Guard. Сертификация ОБЯЗАНА использовать
        # отдельный реальный GUI E2E Desktop/Guard в Windows.
        raise RuntimeError(
            "Сертификация запуска игры на Windows требует внешнего GUI E2E-теста Desktop/Guard; прямой запуск Runtime не считается действительной проверкой безопасности"
        )
    else:
        raise RuntimeError("Неподдерживаемая операционная система для GA")
    runtime = resolve_installed_runtime(root)
    runtime_help = from_runtime(runtime, "--help")
    if runtime_help.get("version") != "0.24.0":
        raise RuntimeError("Установлен Runtime не версии 0.24.0")
    verification = from_runtime(
        runtime,
        "verify",
        "--manifest",
        signed_manifest,
        "--pinned-public-key",
        public_key,
    )
    if verification.get("status") != "ready":
        raise RuntimeError("Подписанный профиль Minecraft не прошёл проверку")
    data = json.loads(signed_manifest.read_text())
    signed_major = data.get("runtime", {}).get("java", {}).get("majorVersion")
    if signed_major != java_major:
        raise RuntimeError("Основная версия Java отличается от указанной в подписанном профиле")
    java = from_runtime(runtime, "java", "ensure", "--major", str(java_major))
    java_path = Path(java.get("javaExecutable", ""))
    if (
        java.get("majorVersion") != java_major
        or not java_path.is_file()
        or java_path.is_symlink()
    ):
        raise RuntimeError("Настоящая управляемая Java не была установлена")
    checked([java_path, "-version"], timeout=40)
    game_root = root / "profiles" / data["projectId"] / data["profileId"]
    result = from_runtime(
        runtime,
        "sync-local",
        "--manifest",
        signed_manifest,
        "--root",
        game_root,
        "--pinned-public-key",
        public_key,
        timeout=1500,
    )
    if result.get("status") != "ready":
        raise RuntimeError("Ошибка установки файлов игры")
    launched = from_runtime(
        runtime,
        "launch",
        "--manifest",
        signed_manifest,
        "--pinned-public-key",
        public_key,
        "--root",
        game_root,
        "--java",
        java_path,
        "--username",
        username,
        "--max-runtime-seconds",
        "90",
        timeout=120,
    )
    log_path = Path(launched.get("log_path", ""))
    if not log_path.is_file() or not log_path.is_relative_to(game_root):
        raise RuntimeError("Для Minecraft отсутствует журнал установленного Runtime")
    log = log_path.read_text(encoding="utf-8", errors="replace")
    # Процесс Java -version или фиктивный исполняемый файл не пройдёт эту проверку.
    if not any(
        marker in log
        for marker in ("LWJGL version", "OpenGL", "Setting user:", "Minecraft")
    ):
        raise RuntimeError(
            "В журнале реального процесса не найдены признаки инициализации Minecraft"
        )
    if not launched.get("timed_out") and not launched.get("success"):
        raise RuntimeError("Процесс Minecraft аварийно завершился до штатного выхода")
    return {
        "schemaVersion": "launcher.ga.clean-machine.v1",
        "productVersion": "0.24.0",
        "commit": benchmark_commit,
        "status": "passed",
        "simulated": False,
        "platform": osname,
        "architecture": platform.machine(),
        "installerSha256": hashlib.sha256(installer.read_bytes()).hexdigest(),
        "runtimeSha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "javaSha256": hashlib.sha256(java_path.read_bytes()).hexdigest(),
        "javaMajor": java_major,
        "minecraftVersion": data.get("minecraft", {}).get("version"),
        "logSha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
        "launcherExitCode": launched.get("exit_code"),
        "launchTimedOut": launched.get("timed_out"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--signed-manifest", type=Path, required=True)
    parser.add_argument("--trusted-game-public-key", required=True)
    parser.add_argument("--java-major", type=int, required=True)
    parser.add_argument("--username", default="NLCertPlayer")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = real_clean_install(
            installer=args.installer.resolve(),
            root=args.install_root.resolve(),
            signed_manifest=args.signed_manifest.resolve(),
            public_key=args.trusted_game_public_key,
            java_major=args.java_major,
            username=args.username,
            benchmark_commit=args.commit,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        report = {
            "status": "failed",
            "productVersion": "0.24.0",
            "commit": args.commit,
            "error": str(exc),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Реальный тест GA на чистой машине: {report['status']}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
