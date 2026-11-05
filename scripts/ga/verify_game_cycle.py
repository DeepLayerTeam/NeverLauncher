#!/usr/bin/env python3
"""Проверка свидетельств реального обновления/отката Minecraft по текущим исходникам с блокировкой при
неопределённости.

Читает только вывод run-minecraft-e2e.sh. Даже проверенный JSON-отчёт не заменяет настоящего
раннера: независимо проверяются хеши байтов, версия, идентификатор запуска, текущие подписанные
манифесты и новые свидетельства входа.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HEX = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
SCHEMA = "launcher.game-cycle.0364/v1"
CHANGE = "resources/launcher-game-cycle-0364.txt"
REQUIRED_CHECKS = (
    "postgresBackend",
    "signedBaseline",
    "signedUpdate",
    "productionGoTransactionalUpdate",
    "updateMinecraftJVMJoin",
    "productionGoTransactionalRollback",
    "rollbackMinecraftJVMJoin",
    "serverBridgeJoin",
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def load(root: Path, name: str) -> dict:
    p = root / name
    require(
        p.is_file() and not p.is_symlink() and p.stat().st_size <= 32 * 1024 * 1024,
        "Некорректное или отсутствующее свидетельство JSON: " + name,
    )

    def unique(pairs):
        value = {}
        for key, entry in pairs:
            require(key not in value, "Повторяющееся поле подтверждения: " + key)
            value[key] = entry
        return value

    doc = json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique)
    require(isinstance(doc, dict), "Значение не является объектом JSON: " + name)
    return doc


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(
    root: Path, version: str, source_sha: str, run_id: str = "", run_attempt: str = ""
) -> dict:
    require(COMMIT.fullmatch(source_sha) is not None, "Недопустимый ожидаемый коммит")
    game = load(root, "game-cycle-0364-result.json")
    parent = load(root, "result.json")
    require(
        parent.get("status") == "passed"
        and parent.get("version") == version
        and parent.get("mode") == "full"
        and parent.get("checks", {}).get("realGameUpdateRollback") is True
        and "game-cycle-0364-result.json" in parent.get("evidence", []),
        "Родительский результат реального Minecraft не требует цикл версии 0.36.4",
    )
    require(
        game.get("schemaVersion") == SCHEMA
        and game.get("status") == "passed"
        and game.get("version") == version
        and game.get("sourceCommit") == source_sha,
        "Циклическая проверка имеет неверную версию, SHA исходников или статус",
    )
    if run_id:
        require(
            game.get("githubRunId") == run_id
            and game.get("githubRunAttempt") == run_attempt
            and run_id.isdigit()
            and run_attempt.isdigit(),
            "Устаревшее свидетельство запуска или попытки",
        )
    checks = game.get("checks")
    require(
        isinstance(checks, dict)
        and all(checks.get(k) is True for k in REQUIRED_CHECKS),
        "Обязательный реальный запуск не подтверждён",
    )
    binaries = game.get("executablesSha256", {})
    require(
        isinstance(binaries, dict)
        and all(
            HEX.fullmatch(str(binaries.get(k, "")))
            for k in ("javaExecutable", "Runtime", "paperServerBridge")
        ),
        "Отсутствуют идентификаторы реальных исполняемых файлов JVM, Runtime или ServerBridge",
    )
    require(
        HEX.fullmatch(str(game.get("clientCLIsha256", "")))
        and HEX.fullmatch(str(game.get("changedResourceSha256", ""))),
        "Отсутствует клиент Go или контрольная сумма изменённого файла",
    )
    evidence = game.get("artifacts")
    require(
        isinstance(evidence, dict) and len(evidence) >= 20,
        "Неполный индекс игровых свидетельств",
    )
    required_files = (
        "client-package.json",
        "manifest.json",
        "cycle-package-update.json",
        "cycle-manifest-update.json",
        "cycle-runtime-verify-update.json",
        "runtime-launch-minecraft.json",
        "cycle-runtime-launch-update.json",
        "cycle-runtime-launch-rollback.json",
        "cycle-install.json",
        "cycle-update.json",
        "cycle-rollback.json",
        "cycle-verify-rollback.json",
        "cycle-join-update.log",
        "cycle-join-rollback.log",
        "cycle-game-update.log",
        "cycle-game-rollback.log",
        "cycle-join-update.json",
        "cycle-join-rollback.json",
        "game-cycle-0364-state.json",
    )
    require(
        all(f in evidence for f in required_files),
        "Обязательный файл игрового свидетельства отсутствует в индексе",
    )
    for name, expected_sha in evidence.items():
        require(
            isinstance(name, str)
            and "/" not in name
            and "\\" not in name
            and name not in ("", ".", ".."),
            "Небезопасный путь к файлу свидетельства",
        )
        require(
            isinstance(expected_sha, str) and HEX.fullmatch(expected_sha) is not None,
            "Недопустимая контрольная сумма свидетельства в индексе: " + name,
        )
        p = root / name
        require(
            p.is_file()
            and not p.is_symlink()
            and 0 < p.stat().st_size <= 256 * 1024 * 1024
            and digest(p) == expected_sha,
            "Свидетельство Runtime отсутствует или изменено: " + name,
        )
    base, updated = (
        load(root, "manifest.json"),
        load(root, "cycle-manifest-update.json"),
    )
    state = load(root, "game-cycle-0364-state.json")
    require(
        base.get("version") == game.get("baselineVersion")
        and updated.get("version") == game.get("updateVersion")
        and base["version"] != updated["version"]
        and state.get("baselineVersion") == base["version"]
        and state.get("updateVersion") == updated["version"]
        and state.get("sourceCommit") == source_sha
        and state.get("status") == "rolled-back-and-verified",
        "signed baseline/update identity or updater state is inconsistent",
    )
    require(
        base.get("signature", {}).get("algorithm") == "Ed25519"
        and updated.get("signature", {}).get("algorithm") == "Ed25519"
        and base.get("signature", {}).get("publicKey")
        == updated.get("signature", {}).get("publicKey")
        and bool(base["signature"].get("signature"))
        and bool(updated["signature"].get("signature")),
        "Не хватает свидетельств подписанного манифеста Runtime",
    )
    require(
        load(root, "cycle-runtime-verify-update.json").get("signature", {}).get("valid")
        is True,
        "Подпись обновления не прошла независимую проверку Runtime",
    )
    before_files = {x["path"]: x["sha256"] for x in base.get("files", [])}
    after_files = {x["path"]: x["sha256"] for x in updated.get("files", [])}
    require(
        len(after_files) == len(before_files) + 1
        and CHANGE not in before_files
        and after_files.get(CHANGE) == game["changedResourceSha256"]
        and all(after_files.get(k) == v for k, v in before_files.items()),
        "Обновление не соответствует единственному действительно изменённому ресурсу клиента",
    )
    require(
        load(root, "cycle-update.json").get("status") == "applied-and-verified"
        and load(root, "cycle-rollback.json").get("status") == "rolled-back"
        and load(root, "cycle-verify-rollback.json").get("verify", {}).get("valid")
        is True,
        "Реальное Go-обновление или откат завершились ошибкой",
    )
    for stage in ("update", "rollback"):
        launch = load(root, f"cycle-runtime-launch-{stage}.json")
        require(
            launch.get("success") is True or launch.get("timedOut") is True,
            f"Отсутствует подтверждение реального запуска Minecraft: {stage}",
        )
        counts = load(root, f"cycle-join-{stage}.json")
        require(
            all(
                type(counts.get(k)) is int and counts[k] >= 0
                for k in (
                    "allowedBefore",
                    "allowedAfter",
                    "joinedBefore",
                    "joinedAfter",
                )
            )
            and counts["allowedAfter"] > counts["allowedBefore"]
            and counts["joinedAfter"] > counts["joinedBefore"],
            f"Нет нового подключения к Paper после {stage}",
        )
        require(
            (root / f"cycle-game-{stage}.log").stat().st_size > 0,
            f"Нет подлинного игрового журнала Java после {stage}",
        )
    return {
        "status": "verified",
        "version": version,
        "sourceCommit": source_sha,
        "artifactsVerified": len(evidence),
        "realJoinsAfterUpdateAndRollback": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--e2e-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--run-attempt", default="")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                verify(
                    args.e2e_dir,
                    args.version,
                    args.source_commit,
                    args.run_id,
                    args.run_attempt,
                ),
                sort_keys=True,
            )
        )
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        print("[0364] BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
