#!/usr/bin/env python3
"""0.35.14: исполняемая нативная приёмка, а не синтетический результат теста.

Использует настоящий скомпилированный Runtime и тестовый подписант Ed25519. Проверяются подписанный
локальный транспорт без зависимости от HTTPS, транзакционное восстановление, повторное использование
кэша, подмена подписи/отпечатка и независимое хеширование файлов. Это НЕ запуск Minecraft и не
аттестация защищённого выпуска.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# This directory contains platform.py; do not shadow the stdlib platform module.
_rc_dir = Path(__file__).resolve().parent
_rc_path = sys.path[:]
try:
    sys.path[:] = [p for p in sys.path if Path(p).resolve() != _rc_dir]
    import platform
finally:
    sys.path[:] = _rc_path
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import rc_extended
from certification_run import identity, CertificationBlocked

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "performance"))
from benchmark import (
    RepeatingRangeServer,
    file_entry,
    hash_file,
    isolated_env,
    manifest_base,
    repeating_hash,
    signed_manifest,
)


class RCBlocked(RuntimeError):
    pass


def require(value: bool, reason: str):
    if not value:
        raise RCBlocked(reason)


def process(
    executable: Path, *args: str, env=None, timeout=180
) -> tuple[int, dict | None]:
    try:
        cmd = subprocess.run(
            [str(executable), *map(str, args)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RCBlocked(
            f"Не удалось запустить нативный процесс: {type(exc).__name__}"
        ) from exc
    require(
        len(cmd.stdout) <= 2**20 and len(cmd.stderr) <= 2**20,
        "Ответ нативного компонента превышает допустимый размер",
    )
    try:
        obj = json.loads(cmd.stdout) if cmd.stdout else None
    except ValueError:
        obj = None
    return cmd.returncode, obj


def pass_native(result: tuple[int, dict | None], status: str = "ready"):
    code, response = result
    require(
        code == 0 and isinstance(response, dict) and response.get("status") == status,
        f"Нативная операция не вернула состояние {status}",
    )
    return response


def reject_native(result: tuple[int, dict | None], message: str):
    code, response = result
    # Нативная ошибка может возвращать ненулевой код или структурированный
    # status=invalid; в обоих случаях запрос должен явно отклоняться. Ненулевой код
    # с ready недопустим.
    require(
        not (isinstance(response, dict) and response.get("status") == "ready"), message
    )
    require(
        code != 0
        or (isinstance(response, dict) and response.get("status") == "invalid"),
        message,
    )


def check_binary(path: Path) -> Path:
    require(
        path.is_file() and not path.is_symlink(),
        "Нативный исполняемый файл отсутствует или является символической ссылкой",
    )
    require(
        os.name == "nt" or os.access(path, os.X_OK),
        "Нативный файл не имеет права на выполнение",
    )
    return path.resolve()


def execute(runtime: Path, signer: Path, version: str, commit: str) -> dict:
    runtime, signer = check_binary(runtime), check_binary(signer)
    require(rc_extended(version), "Версия кандидата в выпуск не совпадает")
    require(
        re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "Отсутствует точный исходный коммит"
    )
    checkout = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(
        checkout.returncode == 0 and checkout.stdout.strip() == commit,
        "Нативные тесты не соответствуют рабочей копии исходников",
    )
    help_result = pass_native(process(runtime, "--help"))
    require(
        help_result.get("version") == version,
        "Скомпилированная среда выполнения отличается от канонической версии выпуска",
    )
    require(
        "sync-local" in help_result.get("commands", []),
        "Отсутствует реальная команда транзакционной синхронизации",
    )
    checks = ["binary-version-and-runtime-cli"]
    with tempfile.TemporaryDirectory(prefix="nl-rc-03514-") as tmp:
        work = Path(tmp)
        root = work / "installed"
        block = hashlib.shake_256(b"launcher-03514-native-e2e").digest(128 * 1024)
        size = len(block) * 4
        digest = repeating_hash(block, size)
        with RepeatingRangeServer(block, size) as network:
            manifest, pubkey = signed_manifest(
                signer,
                work,
                manifest_base(
                    [file_entry("libraries/rc/fixture.jar", size, digest, network.url)],
                    version=version,
                ),
            )
            require(
                hash_file(manifest) and len(pubkey) == 64,
                "Не удалось подписать реальный тестовый образец Ed25519",
            )
            env = isolated_env(work / "cache")
            before = network.transferred
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                    timeout=180,
                )
            )
            file = root / "libraries/rc/fixture.jar"
            require(
                file.is_file()
                and file.stat().st_size == size
                and hash_file(file) == digest,
                "Нативная синхронизация не опубликовала проверенные тестовые данные",
            )
            require(
                network.transferred - before >= size,
                "Реальные данные по сети не передавались",
            )
            checks.append("signed-transactional-http-download-and-independent-sha256")
            pass_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                )
            )
            checks.append("installed-signature-and-file-verification")
            before = network.transferred
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                )
            )
            require(
                network.transferred == before,
                "Уже установленный идентичный выпуск вызвал повторную загрузку",
            )
            checks.append("warm-update-without-network-download")
            # Повредите установленный файл, не изменяя его подписанный манифест.
            with file.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"TAMPERED-03514")
                handle.flush()
                os.fsync(handle.fileno())
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                ),
                "Повреждённый установленный файл ошибочно признан готовым",
            )
            checks.append("corrupt-file-rejected-by-native-verifier")
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                    timeout=180,
                )
            )
            require(
                hash_file(file) == digest, "Нативное восстановление не вернуло корректные данные"
            )
            checks.append("real-transactional-repair-and-independent-sha256")
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    "00" * 32,
                    env=env,
                ),
                "Принят неверный закреплённый ключ Ed25519",
            )
            checks.append("wrong-trust-root-denied")
            altered = work / "altered-manifest.json"
            doc = json.loads(manifest.read_text(encoding="utf-8"))
            doc["version"] = "forged-without-resigning"
            altered.write_text(json.dumps(doc), encoding="utf-8")
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    altered,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                ),
                "Приняты изменённые подписанные данные",
            )
            checks.append("modified-signed-manifest-denied")
            return {
                "schemaVersion": "launcher.rc.native.v1",
                "version": version,
                "status": "passed",
                "simulated": False,
                "commit": commit,
                "platform": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "runtimeSha256": hash_file(runtime),
                "signerSha256": hash_file(signer),
                "signedFixtureSha256": hash_file(manifest),
                "fixtureBytes": size,
                "checks": checks,
                "certificationScope": "Выполнены только реальные нативные проверки подписанной синхронизации, верификации, восстановления и отказа; E2E Minecraft/GUI не проводились",
                "timestampUtc": datetime.now(timezone.utc).isoformat(),
                "certificationRun": identity(version, commit, root=ROOT),
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    args.output.unlink(
        missing_ok=True
    )  # устаревший артефакт PASSED не должен сохраняться после неудачного повторного запуска
    try:
        result = execute(args.runtime, args.signer, version, args.commit)
    except (RCBlocked, ValueError, OSError, RuntimeError, CertificationBlocked) as exc:
        print("Выпуск нативного RC заблокирован: " + str(exc), file=sys.stderr)
        return 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name("." + args.output.name + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8") as f:
            os.chmod(tmp, 0o600)
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, args.output)
    finally:
        tmp.unlink(missing_ok=True)
    print(
        f"Нативный кандидат 0.35.14: пройдено {len(result['checks'])} реальных проверок ({result['platform']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
