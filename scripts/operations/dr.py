#!/usr/bin/env python3
"""Docker Compose Standard/Network-HA: полное холодное резервное копирование, восстановление и DR-проверки.

Резервирование Standard замораживает все службы записи приложения, убеждается в отсутствии других
клиентских сеансов PostgreSQL, создаёт дамп PostgreSQL и фиксирует хранилище, factory, резервные
копии и координатор SQLite как единый снимок в окне обслуживания. Восстановление выполняется только
в пустой проект с проверкой чтения томов и БД. Внешние секреты/файлы TLS НЕ экспортируются: их
восстанавливают из одобренного отдельного менеджера секретов.
"""

from __future__ import annotations

import argparse
import io
import stat
from datetime import datetime, timezone
import hashlib
import sqlite3
import json
import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/production/docker-compose.yml"
COMPOSE_FILES = [COMPOSE]
COMPOSE_PROFILES: list[str] = []
VOLUMES = (
    "launcher_storage",
    "launcher_backups",
    "launcher_factory",
    "launcher_coordinator",
    "launcher_redis",
)
STANDARD_VOLUMES = VOLUMES[:-1]
# Redis AOF намеренно не переносится в новый кластер: он содержит временные аренды и сведения о
# присутствии, которые НЕ ДОЛЖНЫ переживать восстановление после аварии.
WORLD_NAME = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
WORLD_BACKUP_ID = re.compile(r"^[0-9a-f]{32}$")


def required_volumes() -> tuple[str, ...]:
    return STANDARD_VOLUMES


CHUNK = 1024 * 1024
PROJECT_PATTERN = re.compile(r"^nl-dr-[a-z0-9][a-z0-9-]{0,35}$")
VALID_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")


class DrillError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    args: list[str], *, stdin=None, stdout=None, timeout=600, env=None
) -> subprocess.CompletedProcess:
    # Не печатайте команды: окружение Compose и вызовы pg_dump могут содержать секреты.
    result = subprocess.run(
        args,
        stdin=stdin,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
        check=False,
    )
    if result.returncode:
        # Ограничивайте объём диагностики; никогда не выводите учётные данные и DSN из результатов инструментов.
        raise DrillError(f"Команда {args[0]} завершилась с ошибкой (код {result.returncode})")
    return result


def compose(
    project: str, env_file: Path, *args: str, stdout=None, stdin=None, timeout=600
):
    return run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "--env-file",
            str(env_file),
            *[
                entry
                for profile in COMPOSE_PROFILES
                for entry in ("--profile", profile)
            ],
            *[entry for path in COMPOSE_FILES for entry in ("-f", str(path))],
            *args,
        ],
        stdin=stdin,
        stdout=stdout,
        timeout=timeout,
    )


def compose_states(project: str, env_file: Path) -> dict[str, str]:
    """Читать настоящие состояния контейнеров Docker Compose, не делать выводы только по кодам завершения."""
    result = compose(project, env_file, "ps", "--all", "--format", "json", timeout=45)
    raw = result.stdout.decode("utf-8", errors="strict").strip()
    if not raw:
        return {}
    try:
        decoded = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
    except (ValueError, UnicodeError) as exc:
        raise DrillError("Не удалось разобрать состояния служб Docker Compose") from exc
    if isinstance(decoded, dict):
        decoded = [decoded]
    if not isinstance(decoded, list):
        raise DrillError("Некорректное значение: состояния служб Docker Compose")
    states = {}
    for item in decoded:
        if not isinstance(item, dict) or not isinstance(item.get("Service"), str):
            raise DrillError("Некорректное описание службы Docker Compose")
        name, state = item["Service"], str(item.get("State", "")).lower()
        if name in states or not state:
            raise DrillError("Повторяющееся или неизвестное состояние Docker Compose")
        states[name] = state
    return states


def assert_quiescent(project: str, env_file: Path) -> str:
    states = compose_states(project, env_file)
    if states.get("postgres") != "running":
        raise DrillError("Для создания логического снимка PostgreSQL должен быть запущен")
    for name in (("api", "api-b", "worker-a", "worker-b", "admin", "nginx", "redis")
                 if "network-ha" in COMPOSE_PROFILES else ("api", "admin", "nginx")):
        if states.get(name) in ("running", "restarting", "paused"):
            raise DrillError(f"Запись не заблокирована: служба {name} активна")
    # Штатная PostgreSQL изолирована внутри этого проекта Compose. При неожиданном активном клиенте завершайте
    # операцию с отказом; внешние процессы записи должны быть также заблокированы на границе развёртывания в
    # течение ВСЕГО окна обслуживания.
    query = (
        "SELECT (SELECT count(*) FROM pg_stat_activity "
        "WHERE datname=current_database() "
        "AND backend_type='client backend' AND pid<>pg_backend_pid()) "
        "|| '|' || pg_current_wal_insert_lsn()::text"
    )
    command = (
        'exec psql -X -A -t -v ON_ERROR_STOP=1 '
        '-U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "' + query + '"'
    )
    result = compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec", command, timeout=60)
    observation = result.stdout.decode("ascii", errors="replace").strip()
    match = re.fullmatch(r"(\d+)\|([0-9A-F]+/[0-9A-F]+)", observation)
    if not match:
        raise DrillError("Некорректные сведения о сессиях PostgreSQL или журнале WAL")
    if int(match.group(1)) != 0:
        raise DrillError("В PostgreSQL есть дополнительные активные клиентские сеансы; резервное копирование заблокировано")
    return match.group(2)


def verify_coordinator(archive_path: Path) -> None:
    """Проверять восстановленный SQLite-координатор с учётом WAL, а не только контрольные суммы tar."""
    if "network-ha" in COMPOSE_PROFILES:
        return
    safe_tar(archive_path)
    parts = {"state.db", "state.db-wal", "state.db-shm"}
    with tempfile.TemporaryDirectory(prefix="launcher-coordinate-verify-") as tmp:
        base = Path(tmp)
        seen = set()
        with tarfile.open(archive_path, "r:gz") as archive:
            for entry in archive:
                relative = PurePosixPath(entry.name)
                if not entry.isfile() or len(relative.parts) != 1 or relative.name not in parts:
                    continue
                if relative.name in seen:
                    raise DrillError("Обнаружен дубликат файла координатора SQLite")
                seen.add(relative.name)
                input_stream = archive.extractfile(entry)
                if input_stream is None:
                    raise DrillError("Не удалось прочитать базу координатора SQLite")
                with input_stream, (base / relative.name).open("xb") as out:
                    shutil.copyfileobj(input_stream, out, length=CHUNK)
        if "state.db" not in seen:
            raise DrillError("В стандартном снимке отсутствует база координатора SQLite")
        try:
            connection = sqlite3.connect(
                "file:" + quote(str(base / "state.db")) + "?mode=ro", uri=True, timeout=10
            )
            try:
                if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise DrillError("Проверка целостности базы координатора SQLite завершилась ошибкой")
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise DrillError("Проверка внешних ключей базы координатора SQLite завершилась ошибкой")
                version = connection.execute(
                    "SELECT value FROM coord_meta WHERE key='version'"
                ).fetchone()
                if version != (1,):
                    raise DrillError("Схема базы координатора SQLite несовместима")
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise DrillError("Некорректная база данных координатора SQLite") from exc


def volume_name(project: str, logical: str) -> str:
    if logical not in VOLUMES:
        raise DrillError("Неизвестный том Docker")
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError("Некорректное имя проекта Docker Compose")
    return project + "_" + logical


def authorize_project(
    project: str,
    confirmation: str,
    *,
    production: bool = False,
    approved: bool = False,
    chaos_mode: bool = False,
) -> None:
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError("Некорректное имя проекта Docker Compose")
    if confirmation != project:
        raise DrillError(
            "Разрушающая операция отклонена: значение --confirm должно точно совпадать с --project"
        )
    if PROJECT_PATTERN.fullmatch(project):
        return
    if chaos_mode or not (production and approved):
        raise DrillError(
            "Для рабочего проекта требуются явно выбранный производственный режим и разрешение на обслуживание"
        )


def ensure_isolated(project: str, confirmation: str) -> None:
    authorize_project(project, confirmation, chaos_mode=True)


def docker_volume_exists(volume: str) -> bool:
    result = subprocess.run(
        ["docker", "volume", "inspect", volume],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    return result.returncode == 0


def safe_tar(path: Path) -> tuple[int, int]:
    total, count = 0, 0
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            # Аварийный архив не должен добавлять символические и жёсткие ссылки, устройства или пути за пределами
            # разрешённого каталога.
            name = PurePosixPath(entry.name)
            if (
                entry.name.startswith("/")
                or "\\" in entry.name
                or ".." in name.parts
                or "\x00" in entry.name
            ):
                raise DrillError("Небезопасный путь элемента архива")
            if not (entry.isfile() or entry.isdir()):
                raise DrillError("Небезопасный тип элемента архива")
            canonical = str(name)
            if canonical in seen and canonical != ".":
                raise DrillError("Обнаружен повторяющийся путь в архиве")
            seen.add(canonical)
            if entry.isfile():
                count += 1
                total += entry.size
    return count, total


def stream_to_file(cmd: list[str], destination: Path, timeout: int = 1800) -> None:
    # Крупные архивы и дампы потоково записываются на диск; полная буферизация в памяти запрещена.
    with destination.open("xb") as out:
        run(cmd, stdout=out, timeout=timeout)
    if not destination.is_file() or destination.stat().st_size == 0:
        raise DrillError("Пустой результат создания снимка")


def docker_tar_backup(volume: str, output: Path) -> None:
    stream_to_file(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            f"type=volume,src={volume},dst=/source,readonly",
            "alpine:3.20",
            "tar",
            "-czf",
            "-",
            "-C",
            "/source",
            ".",
        ],
        output,
    )
    safe_tar(output)


def tar_digests(path: Path) -> dict[str, dict]:
    """Потоково читать каждый восстановленный файл тома и сравнивать реальные байты, а не заголовки tar."""
    safe_tar(path)
    result = {}
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            if entry.isfile():
                digest = hashlib.sha256()
                contents = archive.extractfile(entry)
                if contents is None:
                    raise DrillError("Некорректный элемент TAR-архива")
                with contents:
                    for chunk in iter(lambda: contents.read(CHUNK), b""):
                        digest.update(chunk)
                result[str(PurePosixPath(entry.name))] = {
                    "sha256": digest.hexdigest(),
                    "size": entry.size,
                }
    return result


def docker_tar_restore(volume: str, archive: Path) -> None:
    safe_tar(archive)
    # Распаковывайте исключительно в новый пустой изолированный том.
    cmd = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--mount",
        f"type=volume,src={volume},dst=/target",
        "alpine:3.20",
        "tar",
        "-xzf",
        "-",
        "-C",
        "/target",
    ]
    with archive.open("rb") as source:
        run(cmd, stdin=source, timeout=1800)
    with tempfile.TemporaryDirectory(prefix="launcher-volume-check-") as work:
        actual = Path(work) / "readback.tar.gz"
        docker_tar_backup(volume, actual)
        if tar_digests(archive) != tar_digests(actual):
            raise DrillError("Данные восстановленного тома Docker не совпадают с резервной копией")


def compose_pg_dump(project: str, env_file: Path, dst: Path) -> None:
    prefix = [
        "docker",
        "compose",
        "-p",
        project,
        "--env-file",
        str(env_file),
        *[entry for profile in COMPOSE_PROFILES for entry in ("--profile", profile)],
        *[entry for path in COMPOSE_FILES for entry in ("-f", str(path))],
    ]
    stream_to_file(
        prefix
        + [
            "exec",
            "-T",
            "postgres",
            "sh",
            "-ec",
            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-acl',
        ],
        dst,
    )


def compose_pg_restore(project: str, env_file: Path, dump: Path) -> None:
    # --single-transaction обеспечивает атомарность неудачного восстановления БД в PostgreSQL.
    with dump.open("rb") as source:
        compose(
            project,
            env_file,
            "exec",
            "-T",
            "postgres",
            "sh",
            "-ec",
            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error --no-owner --no-acl',
            stdin=source,
            timeout=1800,
        )


def pg_validate(dump: Path) -> None:
    # Проверяйте структуру архива соответствующим клиентом PostgreSQL внутри Alpine.
    with dump.open("rb") as f:
        run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "postgres:16-alpine",
                "sh",
                "-ec",
                "cat > /tmp/backup.dump && pg_restore --list /tmp/backup.dump >/dev/null",
            ],
            stdin=f,
            timeout=1800,
        )


def aws(*args: str, timeout: int = 1800) -> str:
    result = run(["aws", *args], timeout=timeout)
    return result.stdout.decode("utf-8", errors="replace")


def s3_options(endpoint: str | None) -> list[str]:
    if endpoint and not (
        endpoint.startswith("https://")
        or endpoint.startswith("http://127.0.0.1:")
        or endpoint.startswith("http://localhost:")
    ):
        raise DrillError("Адрес S3: требуется HTTPS или адрес петлевого интерфейса")
    return ["--endpoint-url", endpoint] if endpoint else []


def s3_download(bucket: str, root: Path, endpoint: str | None) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket):
        raise DrillError("Некорректное имя корзины S3")
    root.mkdir(parents=True, exist_ok=False)
    aws(
        *s3_options(endpoint),
        "s3",
        "sync",
        "s3://" + bucket,
        str(root),
        "--only-show-errors",
    )
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise DrillError("Снимок S3 содержит небезопасную запись файловой системы")


def s3_list_first(bucket: str, endpoint: str | None) -> bool:
    value = aws(
        *s3_options(endpoint),
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--max-keys",
        "1",
        "--query",
        "KeyCount",
        "--output",
        "text",
    ).strip()
    if value not in ("0", "1"):
        raise DrillError("Неожиданный ответ при получении списка объектов S3")
    return value == "1"


def s3_upload_fresh(
    bucket: str, root: Path, endpoint: str | None, expected: dict
) -> None:
    if s3_list_first(bucket, endpoint):
        raise DrillError("Не указан бакет S3 для восстановления")
    aws(
        *s3_options(endpoint),
        "s3",
        "sync",
        str(root),
        "s3://" + bucket,
        "--only-show-errors",
    )
    # Восстановление считается проверенным лишь после повторного чтения каждого загруженного байта.
    with tempfile.TemporaryDirectory(prefix="launcher-s3-verify-") as temp:
        second = Path(temp) / "objects"
        s3_download(bucket, second, endpoint)
        files = {
            p.relative_to(second).as_posix(): {
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in second.rglob("*")
            if p.is_file()
        }
        if files != expected:
            raise DrillError("Повторно прочитанные данные S3 не совпадают с проверенным исходным снимком")



def parse_world_args(values: list[str]) -> dict[str, Path]:
    result = {}
    for entry in values:
        name, separator, path = entry.partition("=")
        if not separator or not WORLD_NAME.fullmatch(name) or name in result or not path:
            raise DrillError("Для каждого игрового мира укажите уникальное значение NAME=/абсолютный/путь")
        location = Path(path)
        if not location.is_absolute() or location.is_symlink():
            raise DrillError("Для игрового мира требуется существующий абсолютный путь")
        result[name] = Path(os.path.abspath(location))
    return result


def safe_world_backup(folder: Path) -> dict:
    """Независимо сверять по байтам настоящий формат Go world-backup/v1."""
    if not folder.is_dir() or folder.is_symlink() or not WORLD_BACKUP_ID.fullmatch(folder.name):
        raise DrillError("Для резервной копии игрового мира требуется каталог с идентификатором без символических ссылок")
    manifest = folder / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 32 * 1024 * 1024:
        raise DrillError("Манифест игрового мира отсутствует или небезопасен")
    try:
        data = json.loads(manifest.read_text(encoding="utf8"))
    except (ValueError, UnicodeError) as exc:
        raise DrillError("Некорректный манифест резервной копии игрового мира") from exc
    if (not isinstance(data, dict) or data.get("schema") != "launcher-world-backup/v1"
            or data.get("id") != folder.name or data.get("consistency") != "confirmed-stopped"
            or not isinstance(data.get("entries"), list) or not data["entries"]):
        raise DrillError("Резервная копия игрового мира не поддерживается либо неполная")
    expected = {}
    if len(data["entries"]) > 1000000:
        raise DrillError("Манифест игрового мира превышает допустимое число записей")
    for item in data["entries"]:
        if not isinstance(item, dict):
            raise DrillError("Некорректная запись игрового мира")
        name = item.get("path")
        if (not isinstance(name, str) or not name or name.startswith("/") or "\\" in name
                or "\x00" in name or any(part in ("", ".", "..") for part in name.split("/"))
                or name in expected or item.get("type") not in ("dir", "file")):
            raise DrillError("Некорректный или повторяющийся путь игрового мира")
        if item["type"] == "file" and (not isinstance(item.get("size"), int) or item["size"] < 0
                or not isinstance(item.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", item["sha256"])):
            raise DrillError("Некорректная контрольная сумма файла игрового мира")
        mode = item.get("mode")
        if not isinstance(mode, int) or mode < 0 or mode > 0o777:
            raise DrillError("Некорректные права доступа к файлу игрового мира")
        if "/" in name:
            parent = name.rsplit("/", 1)[0]
            if parent not in expected or expected[parent]["type"] != "dir":
                raise DrillError("В манифесте игрового мира отсутствует родительский каталог либо нарушен порядок записей")
        expected[name] = item
    root = folder / "payload"
    if root.is_symlink() or not root.is_dir():
        raise DrillError("Отсутствуют данные игрового мира")
    actual = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        entry = expected.get(relative)
        mode = path.lstat().st_mode
        if entry is None or stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise DrillError("Обнаружен небезопасный или неожиданный файл резервной копии игрового мира")
        if (entry["type"] == "dir") != stat.S_ISDIR(mode):
            raise DrillError("Тип файла игрового мира не совпадает с манифестом")
        if entry["type"] == "file" and (path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]):
            raise DrillError("Контрольная сумма резервной копии игрового мира не совпадает")
        actual[relative] = True
    if set(actual) != set(expected):
        raise DrillError("Отсутствуют файлы резервной копии игрового мира")
    if not isinstance(data.get("worlds"), list) or not data["worlds"] or any(
        not isinstance(w, str) or w not in expected or expected[w]["type"] != "dir"
        for w in data["worlds"]
    ):
        raise DrillError("Не выбрана резервная копия игрового мира")
    if data.get("totalBytes") != sum(v["size"] for v in expected.values() if v["type"] == "file"):
        raise DrillError("Общий размер файлов игрового мира не совпадает с манифестом (totalBytes)")
    return data


def archive_world_backups(stage: Path, sources: dict[str, Path]) -> list[dict]:
    if not sources:
        raise DrillError("Для резервного копирования Network-HA необходимы снимки остановленных миров (--world-backup)")
    receipts = []
    for name, source in sorted(sources.items()):
        manifest = safe_world_backup(source)
        target = stage / "worlds" / name / source.name
        target.parent.mkdir(parents=True, mode=0o700)
        shutil.copytree(source, target, symlinks=False)
        again = safe_world_backup(target)
        if again != manifest or safe_world_backup(source) != manifest:
            raise DrillError("Резервная копия игрового мира изменилась при копировании")
        receipts.append({"name": name, "backupId": source.name, "fileCount": len(manifest["entries"]),
                         "totalBytes": manifest["totalBytes"], "manifestSha256": sha256_file(target / "manifest.json")})
    return receipts


def validate_world_receipts(folder: Path, receipts: object) -> None:
    if not isinstance(receipts, list) or not receipts:
        raise DrillError("Список игровых миров Network-HA пуст")
    seen = set()
    for r in receipts:
        if (not isinstance(r, dict) or not WORLD_NAME.fullmatch(str(r.get("name", "")))
                or not WORLD_BACKUP_ID.fullmatch(str(r.get("backupId", ""))) or r["name"] in seen):
            raise DrillError("Некорректное значение: квитанция резервного копирования мира")
        seen.add(r["name"])
        source = folder / "worlds" / r["name"] / r["backupId"]
        manifest = safe_world_backup(source)
        if (r.get("fileCount") != len(manifest["entries"]) or r.get("totalBytes") != manifest["totalBytes"]
                or r.get("manifestSha256") != sha256_file(source / "manifest.json")):
            raise DrillError("Несовпадение: квитанция резервного копирования мира")
    worlds = folder / "worlds"
    if worlds.is_symlink() or not worlds.is_dir():
        raise DrillError("Корневой каталог списка игровых миров небезопасен")
    for name in worlds.iterdir():
        if name.is_symlink() or not name.is_dir() or name.name not in seen:
            raise DrillError("Неожиданное содержимое списка игровых миров")
        expected_id = next(r["backupId"] for r in receipts if r["name"] == name.name)
        if sorted(p.name for p in name.iterdir()) != [expected_id]:
            raise DrillError("Неожиданное содержимое резервной копии игрового мира")


def validate_world_destinations(worlds: list[dict], destinations: dict[str, Path], folder: Path) -> None:
    if set(destinations) != {r["name"] for r in worlds}:
        raise DrillError("Для каждого сохранённого мира необходимо указать ровно один --world-destination")
    targets = list(destinations.values())
    for name, path in destinations.items():
        if path.exists() or path.is_symlink():
            raise DrillError(f"Каталог назначения для мира {name} уже существует; требуется новый каталог")
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise DrillError("Родительский каталог назначения игрового мира должен существовать")
        for parent in [path.parent, *path.parent.parents]:
            if parent.is_symlink():
                raise DrillError("Родительский каталог назначения игрового мира является символической ссылкой")
        if folder == path or folder in path.parents or path in folder.parents:
            raise DrillError("Каталог назначения игрового мира пересекается со снимком")
    for i, left in enumerate(targets):
        for right in targets[i+1:]:
            if left == right or left in right.parents or right in left.parents:
                raise DrillError("Каталоги назначения игровых миров пересекаются")


def restore_world_backup(source: Path, destination: Path) -> None:
    manifest = safe_world_backup(source)
    staging = Path(tempfile.mkdtemp(prefix=".world-restore-", dir=destination.parent))
    try:
        for item in manifest["entries"]:
            rel = item["path"]
            target = staging / rel
            if item["type"] == "dir":
                target.mkdir(mode=0o700)
            else:
                with (source / "payload" / rel).open("rb") as stream, target.open("xb") as out:
                    digest = hashlib.sha256()
                    while chunk := stream.read(CHUNK):
                        out.write(chunk)
                        digest.update(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if digest.hexdigest() != item["sha256"] or target.stat().st_size != item["size"]:
                    raise DrillError("Игровой мир изменился во время восстановления")
                target.chmod(item["mode"])
        for item in reversed(manifest["entries"]):
            if item["type"] == "dir":
                (staging / item["path"]).chmod(item["mode"])
        safe_world_restored(staging, manifest)
        if destination.exists() or destination.is_symlink():
            raise DrillError("Каталог назначения игрового мира появился до публикации")
        staging.rename(destination)
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def safe_world_restored(folder: Path, manifest: dict) -> None:
    # Проверяйте фактически восстановленные байты, а не только дайджест транспортного архива.
    for item in manifest["entries"]:
        path = folder / item["path"]
        if item["type"] == "file" and (not path.is_file() or path.is_symlink()
                or path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]):
            raise DrillError("Восстановленный файл игрового мира не совпадает с резервной копией")
        if item["type"] == "dir" and (not path.is_dir() or path.is_symlink()):
            raise DrillError("Восстановленный каталог игрового мира не совпадает с резервной копией")


def ensure_empty_redis_volume(project: str) -> None:
    name = volume_name(project, "launcher_redis")
    if not docker_volume_exists(name):
        raise DrillError("Docker Compose не создал новый том Redis")
    run(["docker", "run", "--rm", "--network", "none", "--mount",
         f"type=volume,src={name},dst=/data,readonly", "alpine:3.20",
         "sh", "-ec", 'test -z "$(ls -A /data)"'], timeout=60)


FENCE_SQL_0454 = """BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '120s';
SELECT pg_advisory_xact_lock(4504, 1);
-- Отправленные побочные действия нельзя повторно воспроизводить после аварии.
UPDATE server_bridge_control_commands_v3
 SET status='indeterminate', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='Аварийное восстановление: прежняя аренда недоверенная; проверьте внешние последствия'
 WHERE status='leased';
UPDATE server_bridge_control_commands_v3
 SET status='expired', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='Аварийное восстановление: ожидающая команда отброшена' WHERE status='pending';
UPDATE server_bridge_join_tickets_v2
 SET status='invalidated', invalidated_at=now() WHERE status='active';
UPDATE server_bridge_handoffs_v2
 SET status='invalidated', invalidated_at=now() WHERE status='active';
UPDATE server_bridge_player_transfers_v3
 SET status='invalidated' WHERE status='issued';
UPDATE server_bridge_player_sessions_v3
 SET status='invalidated', recheck_required=false, invalidated_at=now(),
 invalidated_reason='Аварийное восстановление: предыдущая среда выполнения недоверенная', updated_at=now()
 WHERE status='active';
UPDATE server_bridge_runtime_instances_v3 SET ended_at=now() WHERE ended_at IS NULL;
-- Восстановленные учётные данные не должны допускать ранее запущенную JVM. Требуйте явную
-- ротацию и повторную регистрацию; никогда автоматически не возобновляйте подписанные команды хоста.
UPDATE server_bridge_nodes_v2 SET
 status='credential-rotation-required', last_heartbeat_at=NULL,
 runtime_previous_id=runtime_id, runtime_id='', runtime_epoch=runtime_epoch+1,
 routing_accepting=false, routing_state='maintenance', routing_health='unknown'
 WHERE status='active';
-- Блокируйте прочие устойчивые операции. Не повторяйте незаметно побочное действие,
-- подтверждение которого могло быть потеряно на разрушенном исходном кластере.
UPDATE durable_jobs SET status='failed', lease_owner='', lease_token='', lease_fence=lease_fence+1,
 lease_expires_at=NULL, completed_at=now(), updated_at=now(),
 last_error='Аварийное восстановление: выполняемая операция требует согласования состояния' WHERE status='running';
UPDATE event_outbox SET status='dead', lease_owner='', lease_token='', lease_fence=lease_fence+1,
 lease_expires_at=NULL, updated_at=now(),
 last_error='Аварийное восстановление: выполняемая доставка требует согласования состояния' WHERE status='running';
UPDATE durable_scope_leases SET fencing_token=fencing_token+1,
 owner='disaster-recovery-fenced', lease_token='disaster-recovery-fenced',
 expires_at='-infinity', updated_at=now();
UPDATE extension_event_deliveries SET status='dead', lease_until=NULL, lease_token='',
 last_error='Аварийное восстановление: выполняемая операция расширения', updated_at=now()
 WHERE status='processing';
DELETE FROM extension_update_leases;
UPDATE extension_update_transactions SET status='failed', lease_owner='', finished_at=now(),
 failure='Аварийное восстановление: согласуйте состояние частично обновлённого расширения' WHERE status='running';
UPDATE migration_runs_0331 SET status='paused', fence=fence+1, lease_owner=NULL, lease_until=NULL,
 last_error='Аварийное восстановление: необходимо согласовать состояние миграции', updated_at=now()
 WHERE status='running' OR lease_owner IS NOT NULL;
COMMIT;
SELECT (SELECT count(*) FROM server_bridge_control_commands_v3 WHERE status IN ('leased','pending')) || '|' ||
 (SELECT count(*) FROM server_bridge_nodes_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_player_sessions_v3 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_handoffs_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_player_transfers_v3 WHERE status='issued') || '|' ||
 (SELECT count(*) FROM durable_jobs WHERE status='running') || '|' ||
 (SELECT count(*) FROM event_outbox WHERE status='running') || '|' ||
 (SELECT count(*) FROM extension_event_deliveries WHERE status='processing') || '|' ||
 (SELECT count(*) FROM migration_runs_0331 WHERE lease_owner IS NOT NULL);
"""


def fence_restored_serverbridge(project: str, env_file: Path) -> None:
    result = compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec",
                     'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -X -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                     stdin=io.BytesIO(FENCE_SQL_0454.encode("utf-8")), timeout=180)
    if not result.stdout.decode("utf-8", errors="replace").strip().endswith("0|0|0|0|0|0|0|0|0|0"):
        raise DrillError("Проверка повторного чтения блокировки ServerBridge после восстановления не пройдена")


def snapshot(
    project: str,
    env_file: Path,
    dest: Path,
    confirm: str,
    s3_bucket: str | None = None,
    s3_endpoint: str | None = None,
    production: bool = False,
    approved: bool = False,
    world_backups: dict[str, Path] | None = None,
    *,
    resume_after: bool = True,
    source_version: str | None = None,
) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    if "network-ha" in COMPOSE_PROFILES and not world_backups:
        raise DrillError("Для Network-HA требуются проверенные резервные копии игровых миров")
    if dest.exists():
        raise DrillError("Каталог назначения снимка уже существует; перезапись запрещена")
    if not env_file.is_file() or env_file.is_symlink():
        raise DrillError("Файл окружения Docker Compose отсутствует либо является символической ссылкой")
    started = time.monotonic()
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".dr-stage-", dir=dest.parent))
    stopped = []
    published = False
    try:
        # Сохраняйте исходно остановленные службы: резервное копирование не должно незаметно запускать службу,
        # намеренно выключенную оператором.
        states = compose_states(project, env_file)
        if states.get("postgres") != "running":
            raise DrillError("PostgreSQL не запущен")
        for svc in (
            ("nginx", "admin", "api", "api-b", "worker-a", "worker-b", "redis")
            if "network-ha" in COMPOSE_PROFILES
            else ("nginx", "admin", "api")
        ):
            if states.get(svc) == "running":
                compose(project, env_file, "stop", "-t", "30", svc)
                stopped.append(svc)
            elif states.get(svc) in ("paused", "restarting"):
                raise DrillError(f"Нельзя приостановить неисправную службу: {svc}")
        pg_lsn_before = assert_quiescent(project, env_file)
        compose_pg_dump(project, env_file, stage / "database.dump")
        pg_validate(stage / "database.dump")
        for item in required_volumes():
            name = volume_name(project, item)
            if not docker_volume_exists(name):
                raise DrillError(f"Не найден том Docker: {item}")
            docker_tar_backup(name, stage / (item + ".tar.gz"))
            if item == "launcher_coordinator":
                verify_coordinator(stage / (item + ".tar.gz"))
        worlds = archive_world_backups(stage, world_backups or {}) if "network-ha" in COMPOSE_PROFILES else []
        s3_files = {}
        if s3_bucket:
            s3_root = stage / "s3-objects"
            s3_download(s3_bucket, s3_root, s3_endpoint)
            s3_files = {
                p.relative_to(s3_root).as_posix(): {
                    "sha256": sha256_file(p),
                    "size": p.stat().st_size,
                }
                for p in s3_root.rglob("*")
                if p.is_file()
            }
            if "network-ha" in COMPOSE_PROFILES:
                # Повторно считывайте каждый удалённый байт, а не только метаданные S3 LIST: параллельный писатель
                # объектов не должен создавать несогласованный образ восстановления PostgreSQL и объектов.
                with tempfile.TemporaryDirectory(dir=stage, prefix=".s3-recheck-") as checkdir:
                    second_root = Path(checkdir) / "objects"
                    s3_download(s3_bucket, second_root, s3_endpoint)
                    second_files = {
                        p.relative_to(second_root).as_posix(): {
                            "sha256": sha256_file(p), "size": p.stat().st_size
                        }
                        for p in second_root.rglob("*") if p.is_file()
                    }
                    if second_files != s3_files:
                        raise DrillError("Объекты S3 изменились во время резервного копирования Network-HA")
        # После копирования объектов повторно проверяйте наличие посторонних клиентов PostgreSQL в течение окна
        # обслуживания, а не только до дампа.
        pg_lsn_after = assert_quiescent(project, env_file)
        if pg_lsn_before != pg_lsn_after:
            raise DrillError("Журнал WAL PostgreSQL изменился во время холодного снимка; повторите после блокировки ВСЕХ писателей")
        files = {
            p.name: {"sha256": sha256_file(p), "size": p.stat().st_size}
            for p in stage.iterdir()
            if p.is_file()
        }
        result = {
            "schema": 3 if "network-ha" in COMPOSE_PROFILES else 2,
            "mode": "network-ha" if "network-ha" in COMPOSE_PROFILES else "standard",
            "worlds": worlds,
            "ephemeralRedis": "network-ha" in COMPOSE_PROFILES,
            "version": source_version or (ROOT / "VERSION").read_text().strip(),
            "sourceProject": project,
            "createdUtc": datetime.now(timezone.utc).isoformat(),
            "repository": "postgres-logical",
            "storage": "s3-objects" if s3_bucket else "local-volume",
            "s3SourceBucket": s3_bucket,
            "s3Files": s3_files,
            "volumes": list(required_volumes()),
            "redis": "fresh-ephemeral-not-restored"
            if "network-ha" in COMPOSE_PROFILES
            else "not-used",
            "files": files,
            "credentialPolicy": "Ключи подписи, пароли, материалы TLS и KMS необходимо восстановить отдельно",
            "consistentWrites": "Пишущие процессы Compose остановлены; WAL PostgreSQL не изменился, а дополнительных клиентских сеансов при создании снимка нет",
            "postgresWalLsn": pg_lsn_before,
            "serviceStateAtBackup": {key: states.get(key, "absent") for key in (
                ("api", "api-b", "worker-a", "worker-b", "admin", "nginx")
                if "network-ha" in COMPOSE_PROFILES else ("api", "admin", "nginx"))},
            "coordinatorIntegrity": "проверка целостности SQLite (integrity_check) и версии схемы coord_meta" if "network-ha" not in COMPOSE_PROFILES else "not-used",
        }
        (stage / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        verify_snapshot(stage)
        if dest.exists() or dest.is_symlink():
            raise DrillError("Каталог назначения снимка появился во время резервного копирования")
        stage.rename(dest)
        result["durationSeconds"] = round(time.monotonic() - started, 3)
        published = True
        return result
    finally:
        # При обновлении БД допускается явно держать все записи остановленными на протяжении копирования, миграции
        # и проверки схемы. При неудачном снимке обязательно возобновляйте исходные службы; успешное обновление
        # само управляет их запуском.
        try:
            if resume_after or not published:
                for svc in reversed(stopped):
                    compose(project, env_file, "up", "-d", svc)
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def verify_snapshot(folder: Path) -> dict:
    if not folder.is_dir() or folder.is_symlink():
        raise DrillError("Снимок: требуется существующий каталог")
    manifest_file = folder / "manifest.json"
    if manifest_file.is_symlink() or not manifest_file.is_file() or manifest_file.stat().st_size > 16 * 1024 * 1024:
        raise DrillError("Манифест снимка небезопасен или превышает допустимый размер")
    data = json.loads(manifest_file.read_text())
    if data.get("schema") not in (1, 2, 3) or data.get("storage") not in (
        "local-volume",
        "s3-objects",
    ):
        raise DrillError("Неподдерживаемая схема снимка или тип хранилища")
    volumes = data.get("volumes", [])
    if data.get("schema") == 3:
        if (data.get("mode") != "network-ha" or data.get("storage") != "s3-objects"
                or data.get("ephemeralRedis") is not True or volumes != list(STANDARD_VOLUMES)):
            raise DrillError("При восстановлении Network-HA нельзя возвращать прежние блокировки Redis")
        validate_world_receipts(folder, data.get("worlds"))
    elif volumes not in (list(STANDARD_VOLUMES), list(VOLUMES)):
        raise DrillError("Некорректные сведения о томах")
    expected = {"database.dump", *(v + ".tar.gz" for v in volumes)}
    if set(data.get("files", {})) != expected:
        raise DrillError("Файлы снимка не совпадают с манифестом")
    if data["storage"] == "s3-objects":
        s3_root = folder / "s3-objects"
        if not s3_root.is_dir() or s3_root.is_symlink():
            raise DrillError("Отсутствует снимок объектов S3")
        actual = {}
        for obj in s3_root.rglob("*"):
            if obj.is_symlink() or (not obj.is_file() and not obj.is_dir()):
                raise DrillError("Небезопасный объект S3")
            if obj.is_file():
                actual[obj.relative_to(s3_root).as_posix()] = {
                    "size": obj.stat().st_size,
                    "sha256": sha256_file(obj),
                }
        if actual != data.get("s3Files"):
            raise DrillError("Контрольная сумма снимка объектов S3 не совпадает")
    for filename, meta in data["files"].items():
        path = folder / filename
        if not path.is_file() or path.is_symlink():
            raise DrillError("В снимке отсутствует файл")
        if path.stat().st_size != meta["size"] or sha256_file(path) != meta["sha256"]:
            raise DrillError("Ошибка проверки SHA-256 снимка")
        if filename.endswith(".tar.gz"):
            safe_tar(path)
    if data.get("schema") == 2 and data["storage"] == "local-volume":
        verify_coordinator(folder / "launcher_coordinator.tar.gz")
    return data


def validate_ready_url(url: str) -> None:
    parsed = urlsplit(url)
    if (parsed.path != "/ready" or parsed.query or parsed.fragment
            or parsed.username or parsed.password or not parsed.hostname
            or parsed.scheme not in ("https", "http")):
        raise DrillError("Для проверки готовности требуется HTTPS-адрес /ready или HTTP-адрес /ready на петлевом интерфейсе")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise DrillError("Отклонена небезопасная проверка готовности по адресу вне петлевого интерфейса")


def target_release(env_file: Path) -> str | None:
    """Определять выпуск для восстановления без раскрытия недоверенного env-файла оболочке."""
    result = None
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == "LAUNCHER_IMAGE_TAG":
            if result is not None:
                raise DrillError("Обнаружен дубликат: LAUNCHER_IMAGE_TAG")
            result = value.strip().strip("\"").strip("'")
    return result


def check_restored_backend(project: str, env_file: Path, *, version: str | None, storage: str, timeout: int = 120, service: str = "api") -> dict:
    """Читать фактически ВОССТАНОВЛЕННЫЙ контейнер API, а не потенциально устаревший публичный DNS-маршрут."""
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            result = compose(
                project, env_file, "exec", "-T", service, "wget", "-qO-",
                "http://127.0.0.1:8080/ready", timeout=10,
            )
            payload = json.loads(result.stdout)
            if (isinstance(payload, dict) and payload.get("status") == "ready"
                    and payload.get("repository") == "postgres"
                    and payload.get("storage") == storage
                    and (version is None or payload.get("version") == version)):
                return payload
        except (DrillError, ValueError, UnicodeError, OSError):
            pass
        time.sleep(1)
    raise DrillError(f"Восстановленный контейнер {service.upper()} не перешёл в состояние готовности с требуемой версией и хранилищем")


def has_split_ha_roles_0455(version: str | None) -> bool:
    if not isinstance(version, str):
        return False
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:$|[-+])", version)
    return bool(match and tuple(map(int, match.groups())) >= (0, 45, 5))


def check_restored_worker_0455(project: str, env_file: Path, service: str, timeout: int = 120) -> None:
    if service not in ("worker-a", "worker-b"):
        raise DrillError("Некорректная служба рабочего узла HA")
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            result = compose(project, env_file, "exec", "-T", service, "wget", "-qO-",
                             "http://127.0.0.1:8080/ready", timeout=10)
            payload = json.loads(result.stdout)
            if (isinstance(payload, dict) and payload.get("status") == "ready"
                    and payload.get("repository") == "postgres" and payload.get("storage") == "s3"):
                return
        except (DrillError, ValueError, UnicodeError, OSError):
            pass
        time.sleep(1)
    raise DrillError(f"Восстановленный рабочий процесс {service} не готов")


def restore_fresh(
    project: str,
    env_file: Path,
    folder: Path,
    confirm: str,
    ready_url: str | None = None,
    target_s3_bucket: str | None = None,
    s3_endpoint: str | None = None,
    production: bool = False,
    approved: bool = False,
    world_destinations: dict[str, Path] | None = None,
) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    manifest = verify_snapshot(folder)
    if "network-ha" in COMPOSE_PROFILES:
        if manifest.get("schema") != 3:
            raise DrillError("Безопасное восстановление устаревших снимков Network-HA с Redis не поддерживается")
        validate_world_destinations(manifest["worlds"], world_destinations or {}, folder)
    elif manifest.get("schema") == 3:
        raise DrillError("Для снимка Network-HA требуется --network-ha")
    # На новом хосте может использоваться то же ИМЯ проекта. Совпадение имён не означает наличия прежних
    # томов; подходят только проверенные пустые цели.
    if not env_file.is_file() or env_file.is_symlink():
        raise DrillError("Файл окружения Docker Compose отсутствует либо является символической ссылкой")
    if not ready_url:
        raise DrillError("Для restore-fresh требуется действующий адрес проверки готовности приложения")
    validate_ready_url(ready_url)
    if manifest.get("schema") in (2, 3) and target_release(env_file) != manifest.get("version"):
        raise DrillError("Версия целевого образа отличается от резервной копии; сначала восстановите точную версию")
    if manifest["volumes"] != list(required_volumes()):
        raise DrillError("Режим восстановления не соответствует топологии томов снимка")
    if manifest["storage"] == "s3-objects":
        if not target_s3_bucket or target_s3_bucket == manifest["s3SourceBucket"]:
            raise DrillError("Для восстановления укажите отдельный бакет через --target-s3-bucket")
        if s3_list_first(target_s3_bucket, s3_endpoint):
            raise DrillError("Не указан целевой бакет S3")
    for item in (VOLUMES if "network-ha" in COMPOSE_PROFILES else manifest["volumes"]):
        if docker_volume_exists(volume_name(project, item)):
            raise DrillError(
                "В целевой системе уже есть данные: требуется новый проект; перезапись отклонена"
            )
    # Проверяйте дамп PostgreSQL до любых изменений; отклоняйте существующие целевые контейнеры, даже если их
    # тома были вручную переименованы или удалены.
    pg_validate(folder / "database.dump")
    if compose_states(project, env_file):
        raise DrillError("В целевом окружении уже есть контейнеры Compose; используйте новый хост или проект")
    started = time.monotonic()
    # Не запускайте API с частично восстановленными данными.
    compose(project, env_file, "create")
    for item in manifest["volumes"]:
        name = volume_name(project, item)
        if not docker_volume_exists(name):
            raise DrillError("Docker Compose не создал обязательный том")
        docker_tar_restore(name, folder / (item + ".tar.gz"))
    if "network-ha" in COMPOSE_PROFILES:
        ensure_empty_redis_volume(project)
    compose(project, env_file, "up", "-d", "postgres")
    for attempt in range(45):
        try:
            compose(
                project,
                env_file,
                "exec",
                "-T",
                "postgres",
                "sh",
                "-ec",
                'exec pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                timeout=10,
            )
            break
        except DrillError:
            time.sleep(1)
    else:
        raise DrillError("PostgreSQL не перешёл в работоспособное состояние")
    try:
        compose_pg_restore(project, env_file, folder / "database.dump")
    except Exception:
        # Оставьте API остановленным; требуется ручная проверка.
        raise
    if "network-ha" in COMPOSE_PROFILES:
        # До блокировки восстановленной БД нельзя запускать API, обработчики или игровые процессы.
        fence_restored_serverbridge(project, env_file)
        for receipt in manifest["worlds"]:
            name = receipt["name"]
            source = folder / "worlds" / name / receipt["backupId"]
            restore_world_backup(source, (world_destinations or {})[name])
    if manifest["storage"] == "s3-objects":
        s3_upload_fresh(
            target_s3_bucket, folder / "s3-objects", s3_endpoint, manifest["s3Files"]
        )
    for svc in (
        ("redis", "api", "api-b", "worker-a", "worker-b", "admin", "nginx")
        if "network-ha" in COMPOSE_PROFILES
        else ("api", "admin", "nginx")
    ):
        compose(project, env_file, "up", "-d", svc)
    outcome = {
        "status": "restored-and-started",
        "source": manifest["sourceProject"],
        "target": project,
        "rtoSeconds": round(time.monotonic() - started, 3),
        "dataChecks": "проверка SHA-256 снимка, безопасных путей в архиве и транзакции pg_restore",
        "credentials": "передаётся извне через окружение целевой системы",
        "applicationVerified": False,
        "serverbridgeFenced": "network-ha" in COMPOSE_PROFILES,
        "redisRestored": False if "network-ha" in COMPOSE_PROFILES else None,
        "restoredWorlds": sorted((world_destinations or {}).keys()),
    }
    try:
        check_restored_backend(
            project, env_file,
            version=manifest.get("version") if manifest.get("schema") == 2 else None,
            storage="local" if manifest["storage"] == "local-volume" else "s3",
        )
        if "network-ha" in COMPOSE_PROFILES and has_split_ha_roles_0455(target_release(env_file)):
            check_restored_backend(project, env_file, version=manifest.get("version"), storage="s3", service="api-b")
            check_restored_worker_0455(project, env_file, "worker-a")
            check_restored_worker_0455(project, env_file, "worker-b")
        await_readiness(
            ready_url, expected=True, limit=120,
            expected_version=manifest.get("version") if manifest.get("schema") == 2 else None,
            expected_storage="local" if manifest["storage"] == "local-volume" else "s3",
        )
    except Exception:
        # Не открывайте снаружи доступ к непроверенной установке. Частично восстановленная цель сохраняется для
        # расследования и никогда не используется автоматически повторно.
        for svc in (("nginx", "admin", "api", "api-b", "worker-a", "worker-b")
                    if "network-ha" in COMPOSE_PROFILES else ("nginx", "admin", "api")):
            try:
                compose(project, env_file, "stop", "-t", "10", svc)
            except Exception:
                pass
        raise
    outcome["applicationVerified"] = True
    return outcome


def ready(url: str, *, expected_version: str | None = None, expected_storage: str | None = None) -> bool:
    validate_ready_url(url)
    try:
        with urlopen(url, timeout=4) as response:
            if response.status != 200:
                return False
            value = json.load(response)
            return (isinstance(value, dict) and value.get("status") == "ready"
                    and (expected_version is None or value.get("version") == expected_version)
                    and (expected_storage is None or value.get("storage") == expected_storage)
                    and (expected_storage is None or value.get("repository") == "postgres"))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return False


def await_readiness(url: str, expected: bool, limit=90, **checks) -> float:
    start = time.monotonic()
    while time.monotonic() - start <= limit:
        if ready(url, **checks) == expected:
            return round(time.monotonic() - start, 3)
        time.sleep(1)
    raise DrillError(f"Эндпоинт /ready не достиг ожидаемого состояния за {limit} с")


def chaos(
    project: str, env_file: Path, url: str, confirm: str, network_ha: bool
) -> dict:
    ensure_isolated(project, confirm)
    if not (
        url.startswith("http://127.0.0.1:") or url.startswith("http://localhost:")
    ) or not url.endswith("/ready"):
        raise DrillError("Для проверки готовности в chaos-тесте требуется адрес /ready на петлевом интерфейсе")
    await_readiness(url, expected=True, limit=30)
    outcomes = []
    for svc in ("postgres", "redis") if network_ha else ("postgres",):
        down_start = time.monotonic()
        try:
            compose(project, env_file, "stop", "-t", "5", svc)
            # При потере БД выполняйте отказ с закрытием доступа; для network-ha Redis обязателен.
            down_sec = await_readiness(url, expected=False, limit=35)
        finally:
            compose(project, env_file, "up", "-d", svc)
        up_sec = await_readiness(url, expected=True, limit=120)
        outcomes.append(
            {
                "service": svc,
                "failClosedSeconds": down_sec,
                "recoverySeconds": up_sec,
                "totalSeconds": round(time.monotonic() - down_start, 3),
            }
        )
    try:
        compose(project, env_file, "kill", "api")
        compose(project, env_file, "stop", "-t", "1", "api")
        await_readiness(url, expected=False, limit=25)
    finally:
        compose(project, env_file, "up", "-d", "api")
    outcomes.append(
        {
            "service": "api",
            "recoverySeconds": await_readiness(url, expected=True, limit=120),
        }
    )
    return {
        "status": "measured",
        "project": project,
        "mode": "network-ha" if network_ha else "standard",
        "events": outcomes,
        "haDisclaimer": "Восстановление и готовность одного узла; высокая доступность Backend не подтверждается",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["backup", "verify", "restore-fresh", "chaos"]
    )
    parser.add_argument("--project", help="Изолированный проект docker compose, nl-dr-*")
    parser.add_argument("--confirm", help="Точное имя проекта обязательно для изменений")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--ready-url")
    parser.add_argument("--network-ha", action="store_true")
    parser.add_argument("--s3-source-bucket")
    parser.add_argument("--target-s3-bucket")
    parser.add_argument("--s3-endpoint")
    parser.add_argument("--world-backup", action="append", default=[],
                        metavar="NAME=/absolute/path/backup-id",
                        help="Ранее остановленная проверенная копия мира Go CLI на смонтированной ФС оператора")
    parser.add_argument("--world-destination", action="append", default=[],
                        metavar="NAME=/absolute/fresh/server-root",
                        help="Новая цель на смонтированном хранилище хоста; JVM игры автоматически не запускается")
    parser.add_argument(
        "--production-source",
        action="store_true",
        help="Разрешить резервирование явно одобренного источника в окно обслуживания",
    )
    parser.add_argument(
        "--production-target",
        action="store_true",
        help="Разрешить восстановление на явно одобренную новую цель; без перезаписи",
    )
    parser.add_argument(
        "--maintenance-approved",
        action="store_true",
        help="Явное подтверждение оператора: все службы записи отсечены, простой согласован",
    )
    args = parser.parse_args()
    if args.network_ha:
        COMPOSE_FILES.append(ROOT / "deploy/production/docker-compose.network-ha.yml")
        COMPOSE_PROFILES.append("network-ha")
    try:
        world_backups = parse_world_args(args.world_backup)
        world_destinations = parse_world_args(args.world_destination)
        if args.network_ha and args.action == "backup" and world_destinations:
            raise DrillError("Параметры назначения игровых миров допустимы только для restore-fresh")
        if args.network_ha and args.action == "restore-fresh" and world_backups:
            raise DrillError("Параметры резервных копий игровых миров допустимы только для backup")
        if not args.network_ha and (world_backups or world_destinations):
            raise DrillError("Для восстановления мира требуется --network-ha")
        if args.network_ha and args.action == "backup" and not args.s3_source_bucket:
            raise DrillError("Для резервного копирования Network-HA требуется --s3-source-bucket")
        if args.action == "restore-fresh" and not args.ready_url:
            raise DrillError("Для restore-fresh укажите --ready-url для проверки фактического Backend")
        if args.action == "verify":
            verified = verify_snapshot(args.snapshot)
            pg_validate(args.snapshot / "database.dump")
            report = {"status": "verified", "postgresArchiveChecked": True, "manifest": verified}
        else:
            if not args.project or not args.env_file:
                raise DrillError("Требуются параметры проекта и файла окружения")
            if args.action == "backup":
                report = snapshot(
                    args.project,
                    args.env_file,
                    args.snapshot,
                    args.confirm or "",
                    args.s3_source_bucket,
                    args.s3_endpoint,
                    args.production_source,
                    args.maintenance_approved,
                    world_backups,
                )
            elif args.action == "restore-fresh":
                report = restore_fresh(
                    args.project,
                    args.env_file,
                    args.snapshot,
                    args.confirm or "",
                    args.ready_url,
                    args.target_s3_bucket,
                    args.s3_endpoint,
                    args.production_target,
                    args.maintenance_approved,
                    world_destinations,
                )
            else:
                if not args.ready_url:
                    raise DrillError("Необходимо указать --ready-url")
                report = chaos(
                    args.project,
                    args.env_file,
                    args.ready_url,
                    args.confirm or "",
                    args.network_ha,
                )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (
        DrillError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        KeyError,
    ) as exc:
        print(
            json.dumps({"status": "failed", "reason": str(exc)[:160]}), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
