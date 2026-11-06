#!/usr/bin/env python3
"""Проверить настоящее резервное копирование/восстановление мира Paper после настоящего входа в Minecraft.

Работает в одноразовой сети E2E Docker Compose, НЕ на производственном хосте. Намеренно отклоняет
отсутствие файла playerdata, неуспешное завершение сервера, отсутствие конфигурации плагина,
неправильные хеши и перезапись восстановленных данных.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def execute(argv, *, output=True, timeout=180):
    result = subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout if output else None


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def check_files(root):
    level_name = "world"
    properties = root / "server.properties"
    if not properties.is_file():
        raise RuntimeError("Файл server.properties реального сервера Paper не был скопирован")
    for line in properties.read_text(errors="replace").splitlines():
        if line.startswith("level-name="):
            level_name = line.partition("=")[2].strip()
    world = root / level_name
    if not (world / "level.dat").is_file():
        raise RuntimeError("После штатной остановки Paper отсутствует файл level.dat")
    players = sorted((world / "playerdata").glob("*.dat"))
    if not players:
        raise RuntimeError(
            "После входа клиента не сохранены реальные данные UUID игрока Minecraft"
        )
    plugin_root = root / "plugins"
    plugins = sorted(
        p
        for p in plugin_root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in (".yml", ".yaml", ".json", ".properties", ".db")
    )
    if not plugins:
        raise RuntimeError(
            "Реальные файлы конфигурации или данных плагинов Minecraft не были сохранены"
        )
    chosen = [world / "level.dat", *players, *plugins]
    return {p.relative_to(root).as_posix(): digest(p) for p in chosen}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--compose-file", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--override-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()
    if not args.cli.is_file():
        parser.error("Собранный CLI Launcher не найден")
    compose = [
        "docker",
        "compose",
        "--env-file",
        str(args.env_file),
        "-f",
        str(args.compose_file),
        "-f",
        str(args.override_file),
    ]
    paper = execute([*compose, "ps", "-q", "paper"]).strip()
    if not paper:
        raise RuntimeError("Реальный контейнер Paper недоступен")
    # Docker SIGTERM НЕ доказывает сохранение Minecraft. Отправляйте настоящие аутентифицированные
    # консольные команды Minecraft по недоступному снаружи внутреннему каналу E2E RCON.
    flush = execute(
        [*compose, "exec", "-T", "paper", "rcon-cli", "save-all", "flush"], timeout=45
    )
    if not flush.strip():
        raise RuntimeError("Paper не подтвердил сброс сохранённых данных командой save-all")
    execute([*compose, "exec", "-T", "paper", "rcon-cli", "stop"], timeout=45)
    deadline = time.monotonic() + 95
    while True:
        state = json.loads(
            execute(["docker", "inspect", "--format", "{{json .State}}", paper])
        )
        if not state.get("Running"):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Paper не завершился после команды остановки в консоли Minecraft")
        time.sleep(1)
    if state.get("OOMKilled") or state.get("ExitCode") != 0:
        raise RuntimeError(
            f"Завершение Paper прошло с ошибкой: exit={state.get('ExitCode')}, OOM={state.get('OOMKilled')}"
        )
    with tempfile.TemporaryDirectory(prefix="nl-real-world-0290-") as temp:
        root = Path(temp) / "paper-real"
        store = Path(temp) / "world-backups"
        restored = Path(temp) / "restored"
        root.mkdir(mode=0o700)
        # Docker cp из НАСТОЯЩЕГО остановленного E2E-контейнера Paper, а не из
        # фиктивного процесса Java или придуманной описи.
        execute([*compose, "cp", "paper:/data/.", str(root)], timeout=180)
        source = check_files(root)
        base = [str(args.cli), "server-bridge", "host", "world-backup"]
        extra = ["--server-root", str(root), "--backup-root", str(store)]
        created = json.loads(
            execute([*base, "create", *extra, "--consistency", "stopped"], timeout=180)
        )
        backup_id = created["manifest"]["id"]
        if created["manifest"]["consistency"] != "confirmed-stopped":
            raise RuntimeError("В резервной копии указана другая политика согласованности")
        execute([*base, "verify", *extra, "--id", backup_id], timeout=180)
        execute(
            [
                *base,
                "restore",
                *extra,
                "--id",
                backup_id,
                "--confirm",
                backup_id,
                "--destination",
                str(restored),
            ],
            timeout=180,
        )
        actual = check_files(restored)
        if actual != source:
            raise RuntimeError(
                "Восстановленные данные мира, игроков или плагинов отличаются от источника"
            )
        # Перезапись завершённого восстановления должна вызывать ошибку, а не молча проходить.
        second = subprocess.run(
            [
                *base,
                "restore",
                *extra,
                "--id",
                backup_id,
                "--confirm",
                backup_id,
                "--destination",
                str(restored),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if second.returncode == 0:
            raise RuntimeError("Восстановление неожиданно перезаписало существующий целевой каталог")
        # Проверяйте реальное восстановление, а не простой перезапуск неизменённых данных
        # Paper. В одноразовом окружении Docker E2E повредите сохранённый инвентарь игрока в
        # ОСТАНОВЛЕННОМ исходном контейнере, затем верните в /data независимо проверенный
        # восстановленный снимок. НИКОГДА не применяйте эти разрушительные действия к
        # производственному контейнеру.
        player_file = next(k for k in source if "/playerdata/" in k)
        poisoned = Path(temp) / "damaged-player.dat"
        poisoned.write_bytes(b"NL-TEST-CORRUPTED-PLAYER-DATA")
        execute(
            [*compose, "cp", str(poisoned), f"paper:/data/{player_file}"], timeout=90
        )
        with tempfile.TemporaryDirectory(prefix="nl-paper-poison-") as damaged_dir:
            damaged = Path(damaged_dir)
            execute(
                [
                    *compose,
                    "cp",
                    f"paper:/data/{player_file}",
                    str(damaged / "player.dat"),
                ],
                timeout=90,
            )
            if digest(damaged / "player.dat") == source[player_file]:
                raise RuntimeError(
                    "Не удалось намеренно повредить данные игрока в остановленном контейнере перед восстановлением"
                )
        # Изолированное восстановление CLI публикуется атомарно. Тест затем
        # восстанавливает снимок на одноразовом томе Minecraft.
        execute([*compose, "cp", f"{restored}/.", "paper:/data/"], timeout=180)
        with tempfile.TemporaryDirectory(prefix="nl-paper-applied-") as applied_dir:
            applied = Path(applied_dir)
            execute([*compose, "cp", "paper:/data/.", str(applied)], timeout=180)
            if check_files(applied) != source:
                raise RuntimeError(
                    "Данные контейнера Paper отличаются от восстановленного снимка"
                )
        # Повторное восстановление CLI уже отклонено выше; резервное копирование и
        # изолированное восстановление не запускают JVM автоматически. Верните в работу ТОТ
        # ЖЕ настоящий сервер Paper и потребуйте нового перехода статуса Docker health.
        # Успешное офлайновое восстановление само по себе не доказывает, что живая сеть
        # оправится после обслуживания.
        execute([*compose, "up", "-d", "paper"], timeout=180)
        restarted = execute([*compose, "ps", "-q", "paper"]).strip()
        if not restarted:
            raise RuntimeError("Контейнер Paper исчез во время восстановления")
        for _ in range(120):
            state = json.loads(
                execute(["docker", "inspect", "--format", "{{json .State}}", restarted])
            )
            if (
                state.get("Running")
                and state.get("Health", {}).get("Status") == "healthy"
            ):
                break
            if not state.get("Running"):
                raise RuntimeError("Не удалось перезапустить Paper после резервного копирования мира")
            time.sleep(2)
        else:
            raise RuntimeError(
                "После резервного копирования мира Paper не вернулся в работоспособное состояние"
            )
        report = {
            "schemaVersion": "launcher.server-control.real-world-restore.v1",
            "version": args.version,
            "sourceCommit": args.source_commit,
            "source": "docker-compose-real-paper-after-minecraft-client-join",
            "status": "passed",
            "actualMinecraftWorld": True,
            "gracefulPaperExit": True,
            "minecraftSaveFlushAcknowledged": True,
            "worldBackupVerified": True,
            "isolatedRestoreVerified": True,
            "restoredDataAppliedToPaper": True,
            "overwriteRejected": True,
            "returnedToHealthyService": True,
            "worldFileSha256": source[
                next(k for k in source if k.endswith("/level.dat"))
            ],
            "playerDataFiles": sum("/playerdata/" in k for k in source),
            "pluginDataFiles": sum(k.startswith("plugins/") for k in source),
            "filesVerified": len(source),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"[0290] Проверена реальная резервная копия Paper, её целостность и изолированное восстановление {len(source)} файлов"
    )


if __name__ == "__main__":
    main()
