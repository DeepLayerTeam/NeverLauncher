#!/usr/bin/env python3
"""Проверка настоящих свидетельств Minecraft и восстановления Paper от CI с блокировкой при неопределённости.

Авторитетный запуск — e2e/scripts/run-minecraft-e2e.sh. Валидатор не создаёт свидетельства и не
заменяет реальный E2E: изучает файлы задания, отвергает пропущенные/подменённые отчёты и
несовпадающие коммиты.
"""

import argparse
import json
from pathlib import Path
import re
import sys

DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def strict_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError(f"Подтверждающий файл отсутствует, является символической ссылкой или слишком велик: {path.name}")

    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value:
                raise ValueError(f"Обнаружен дубликат: «ключ свидетельства» {k}")
            value[k] = v
        return value

    data = json.loads(path.read_text("utf-8"), object_pairs_hook=unique)
    if not isinstance(data, dict):
        raise ValueError(f"Файл не содержит объект JSON: {path.name}")
    return data


def verify(root: Path, version: str, commit: str):
    result = strict_json(root / "result.json")
    proof = strict_json(root / "world-backup-0290.json")
    if (
        result.get("version") != version
        or result.get("status") != "passed"
        or result.get("mode") != "full"
    ):
        raise ValueError("Отсутствует: «полный результат E2E-проверки с настоящим клиентом Minecraft»")
    mc = result.get("minecraft", {})
    if (
        not isinstance(mc, dict)
        or mc.get("client") != "actual-mojang-client"
        or mc.get("paperJoin") != "passed"
    ):
        raise ValueError("Нет доказательств реального подключения клиента Minecraft к серверу Paper")
    checks = result.get("checks", {})
    required = (
        "signedManifest",
        "cleanSync",
        "actualClient",
        "paperJoin",
        "sessionRevokeDeny",
        "bukkitFamilyRuntime",
        "proxyFamilyRuntime",
    )
    if not isinstance(checks, dict) or any(checks.get(k) is not True for k in required):
        raise ValueError("Отсутствует: «проверки настоящего входа, повторного запроса или маршрутизации»")
    if (
        proof.get("schemaVersion") != "launcher.server-control.real-world-restore.v1"
        or proof.get("version") != version
        or proof.get("status") != "passed"
    ):
        raise ValueError("Для релиза отсутствует отчёт о реальном восстановлении мира Paper")
    if proof.get("source") != "docker-compose-real-paper-after-minecraft-client-join":
        raise ValueError("Восстановленный источник не является реальным контейнером Minecraft Paper")
    for name in (
        "actualMinecraftWorld",
        "gracefulPaperExit",
        "minecraftSaveFlushAcknowledged",
        "worldBackupVerified",
        "isolatedRestoreVerified",
        "overwriteRejected",
        "returnedToHealthyService",
    ):
        if proof.get(name) is not True:
            raise ValueError(f"Ошибка: «проверка выполнения резервного копирования мира»: {name}")
    for name in ("playerDataFiles", "pluginDataFiles", "filesVerified"):
        if type(proof.get(name)) is not int or proof[name] <= 0:
            raise ValueError(f"Резервная копия мира не содержит фактический файл {name}")
    if not DIGEST.fullmatch(str(proof.get("worldFileSha256", ""))):
        raise ValueError("Отсутствует: «сохранённая контрольная сумма настоящего игрового мира»")
    if commit:
        if not COMMIT.fullmatch(commit) or proof.get("sourceCommit") != commit:
            raise ValueError("Доказательство восстановления мира Paper относится к другому коммиту")
    # Проверяйте независимые результаты, а не один заявленный boolean в result.json.
    join = strict_json(root / "join-paper-real-client-fresh.json")
    if (
        join.get("data", {}).get("oneTime") is not True
        or join.get("data", {}).get("ticketVersion") != 2
    ):
        raise ValueError("Реальный клиент Minecraft не получил одноразовый билет подключения")
    denied = strict_json(root / "validate-paper-e2e-p3-deny.json")
    if denied.get("data", {}).get("allowed") is not False:
        raise ValueError("Повторное использование запроса ServerBridge не было отклонено")
    if (
        "world-backup-0290.json" in result.get("evidence", [])
        and checks.get("realWorldBackupRestore") is not True
    ):
        raise ValueError("Индекс подтверждений резервного копирования содержит несогласованные данные")
    handoff = strict_json(root / "handoff-velocity-paper.json")
    if (
        handoff.get("data", {}).get("oneTime") is not True
        or handoff.get("data", {}).get("status") != "handoff-created"
    ):
        raise ValueError("Отсутствует доказательство реальной однократной передачи от прокси к Backend")
    return {
        "version": version,
        "sourceCommit": commit,
        "status": "verified",
        "realPlayerDataFiles": proof["playerDataFiles"],
        "realPluginDataFiles": proof["pluginDataFiles"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--e2e-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                verify(args.e2e_dir, args.version, args.source_commit), sort_keys=True
            )
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"[0290] Доказательства готовности GA отклонены: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
