#!/usr/bin/env python3
"""NeverLauncher 0.51.8: настоящее холодное копирование многохостовой группы и PostgreSQL WAL/PITR.

Требуются готовый репозиторий pgBackRest с непрерывной архивацией WAL, версионируемый бакет S3,
отдельные хосты с агентом 0.51.8 и остановленные миры Minecraft. Горячая копия не выдаётся за
межсистемную транзакцию.

Утилита фиксирует *единую замороженную группу приложения*, а не произвольный момент времени PG. PITR
PostgreSQL на другое время не имеет соответствующего снимка S3 или миров и НЕ ДОЛЖЕН использоваться
для автоматически согласованного восстановления.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

import dr_03512 as dr
import multi_host_0512 as multi
import nn1_compat_0516 as nn

SCHEMA = "neverlauncher.consistent-backup/0.51.8"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PG_STANZA = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}\Z")
BACKUP_LABEL = re.compile(r"[0-9]{8}-[0-9]{6}F(?:_[0-9]{8}-[0-9]{6}[DI])?\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
# Все потенциально хранящие состояние локальные контейнеры должны попасть в образ восстановления: не
# пропускайте установки расширений на узлах, локальные копии и кеши фабрики/конфигурации.
VOLUMES = ("api_storage", "api_backups", "api_factory", "api_coordinator",
           "api_extensions", "worker_storage", "worker_backups", "worker_factory",
           "worker_coordinator", "worker_extensions")
STATE_FILE = ".backup-freeze-0518.json"
STREAM_CHUNK = 1024 * 1024

class BackupError(RuntimeError):
    pass


def require(test, message):
    if not test:
        raise BackupError(message)


def safe_file(path: Path, *, max_size=65536):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
            stat.S_IMODE(st.st_mode) & 0o077 == 0 and 0 < st.st_size <= max_size,
            "Требуется закрытый файл")
    return path.read_bytes()


def save_exclusive(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        sync_dir(path.parent)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def sync_dir(path: Path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def execute(args, *, timeout=120, env=None, input=None, cwd=None):
    try:
        cp = subprocess.run(args, timeout=timeout, env=env, input=input, cwd=cwd,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("Недоступно или превышено время ожидания: " + args[0]) from exc
    require(cp.returncode == 0 and len(cp.stdout) <= 16 * 1024 * 1024,
            "Команда завершилась ошибкой: " + args[0])
    return cp.stdout


def stream_command(args, target: Path, *, timeout=7200, cwd=None):
    require(not target.exists() and not target.is_symlink(), "Результат резервного копирования уже существует")
    with target.open("xb") as fd:
        try:
            proc = subprocess.Popen(args, cwd=cwd, stdout=fd, stderr=subprocess.PIPE)
            try:
                _, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.communicate()
                raise BackupError("Превышено время ожидания потоковой операции")
            require(proc.returncode == 0, "Потоковая команда завершилась ошибкой: " + args[0])
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        fd.flush(); os.fsync(fd.fileno())
    require(target.stat().st_size > 0, "empty archive")


def ssh(target, script, command, *args):
    require(bool(multi.HOST_REGEX.fullmatch(target)), "unsafe SSH target")
    require(script.startswith("/") and re.fullmatch(r"/[a-zA-Z0-9_./-]+", script)
            and ".." not in Path(script).parts, "unsafe remote agent path")
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", target,
            shlex.join(["python3", script, command, *map(str, args)])]


def local_services(directory, project):
    raw = execute(multi.compose_command(directory, project, "ps", "--all", "--format", "json"),
                  timeout=45, cwd=directory).decode()
    try:
        values = json.loads(raw) if raw.lstrip().startswith("[") else [json.loads(x) for x in raw.splitlines() if x.strip()]
    except ValueError as exc:
        raise BackupError("Некорректное значение: «Docker service inventory»") from exc
    if isinstance(values, dict):
        values = [values]
    return {item["Service"]: str(item["State"]).lower() for item in values}


def freeze(directory: Path, project: str, run_id: str):
    require(bool(RUN_ID.fullmatch(run_id)), "Недопустимый идентификатор запуска")
    require(directory.is_dir() and not directory.is_symlink(), "Недопустимый каталог развёртывания узла")
    require(not (directory / STATE_FILE).exists(), "Узел уже заморожен; используйте явное восстановление")
    # Проверяйте реально сформированную конфигурацию, идентификаторы Runtime и внешние зависимости.
    config = multi.resolved_compose(directory, project)
    states = local_services(directory, project)
    require(states.get("api") == "running" and states.get("worker") == "running", "Перед заморозкой должны работать и API, и обработчик")
    record = {"schema": SCHEMA, "runId": run_id, "project": project,
              "nodeId": config["nodeId"], "phase": "stopping", "services": ["api", "worker"]}
    path = directory / STATE_FILE
    save_exclusive(path, (json.dumps(record, sort_keys=True) + "\n").encode())
    try:
        execute(multi.compose_command(directory, project, "stop", "-t", "45", "worker", "api"),
                timeout=160, cwd=directory)
        states = local_services(directory, project)
        require(all(states.get(k) not in ("running", "restarting", "paused") for k in ("api", "worker")),
                "a writer is still active after freeze")
        record["phase"] = "frozen"
        atomic_replace(path, (json.dumps(record, sort_keys=True) + "\n").encode())
        return {"status": "frozen", "nodeId": config["nodeId"], "runId": run_id,
            "machineIdentity": config["machineIdentity"],
            "sharedEndpoints": config["sharedEndpoints"]}
    except BaseException:
        # При неудачной остановке журнал восстановления намеренно остаётся на хосте.
        raise


def atomic_replace(path, content):
    tmp = path.with_name(path.name + ".new")
    save_exclusive(tmp, content)
    os.replace(tmp, path)
    sync_dir(path.parent)


def frozen_record(directory, project, run_id):
    try:
        data = json.loads(safe_file(directory / STATE_FILE))
    except (OSError, ValueError) as exc:
        raise BackupError("Журнал приостановки хоста отсутствует или повреждён") from exc
    require(data.get("schema") == SCHEMA and data.get("project") == project and
            data.get("runId") == run_id, "host belongs to a different backup operation")
    return data


def assert_frozen(directory, project, run_id):
    data = frozen_record(directory, project, run_id)
    require(data.get("phase") == "frozen", "host freeze is incomplete")
    states = local_services(directory, project)
    require(all(states.get(k) not in ("running", "restarting", "paused") for k in ("api", "worker")),
            "host resumed during snapshot")
    return data


def thaw(directory, project, run_id):
    data = frozen_record(directory, project, run_id)
    require(data.get("phase") in ("stopping", "frozen"), "Узел уже разморожен")
    execute(multi.compose_command(directory, project, "up", "-d", "--no-build", "--no-deps", "--wait", "api", "worker"),
            cwd=directory, timeout=180)
    states = local_services(directory, project)
    require(states.get("api") == "running" and states.get("worker") == "running", "API/worker not restarted")
    (directory / STATE_FILE).unlink()
    sync_dir(directory)
    return {"status": "resumed", "nodeId": data["nodeId"], "runId": run_id}


def stream_volume(directory, project, run_id, logical, image):
    assert_frozen(directory, project, run_id)
    require(logical in VOLUMES, "Неизвестный локальный том состояния")
    require(bool(multi.DIGEST_REGEX.fullmatch(image)), "Образ tar должен быть закреплён по хешу")
    volume = project + "_" + logical
    out = subprocess.Popen(["docker", "run", "--rm", "--network", "none", "--read-only",
                            "--mount", f"type=volume,src={volume},dst=/source,readonly",
                            image, "tar", "-czf", "-", "-C", "/source", "."],
                           stdout=sys.stdout.buffer, stderr=subprocess.PIPE)
    try:
        _, _ = out.communicate(timeout=7200)
    except subprocess.TimeoutExpired:
        out.kill(); out.communicate()
        raise BackupError("Превышено время ожидания архивации тома")
    require(out.returncode == 0, "Резервное копирование тома завершилось ошибкой")


def pg_query(dsn: Path):
    env = nn.dsn_environment(dsn)
    sql = ("SELECT (NOT pg_is_in_recovery())::int || '|' || "
           "(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
           "AND backend_type='client backend' AND pid<>pg_backend_pid())::text || '|' || "
           "pg_current_wal_insert_lsn()::text;")
    raw = execute(["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-c", sql],
                  env=env, timeout=35).decode().strip()
    m = re.fullmatch(r"([01])\|(\d+)\|([0-9A-F]+/[0-9A-F]+)", raw)
    require(bool(m) and m.group(1) == "1" and int(m.group(2)) == 0,
            "PostgreSQL не является единственным доступным для записи основным узлом или существуют посторонние клиентские сеансы")
    return m.group(3)


def pgbackrest(stanza, *args):
    require(bool(PG_STANZA.fullmatch(stanza)), "Недопустимая конфигурация pgBackRest stanza")
    return execute(["pgbackrest", "--stanza=" + stanza, *args], timeout=7200)


def pg_info(stanza):
    try:
        value = json.loads(pgbackrest(stanza, "info", "--output=json"))
    except (ValueError, UnicodeError) as exc:
        raise BackupError("Некорректное значение: «pgBackRest inventory»") from exc
    require(isinstance(value, list) and len(value) == 1 and value[0].get("name") == stanza,
            "Конфигурация pgBackRest stanza не найдена")
    require(value[0].get("status", {}).get("code") == 0, "pgBackRest repository unhealthy")
    return value[0]


def backup_physical(stanza):
    pgbackrest(stanza, "check")
    before = {x.get("label") for x in pg_info(stanza).get("backup", [])}
    pgbackrest(stanza, "backup", "--type=full", "--no-resume")
    pgbackrest(stanza, "check")
    after = pg_info(stanza)
    fresh = [x for x in after.get("backup", []) if x.get("label") not in before]
    require(len(fresh) == 1, "pgBackRest did not register one new physical backup")
    row = fresh[0]
    require(row.get("type") == "full" and bool(BACKUP_LABEL.fullmatch(str(row.get("label", ""))))
            and isinstance(row.get("timestamp", {}).get("stop"), int)
            and isinstance(row.get("archive", {}).get("start"), str)
            and isinstance(row.get("archive", {}).get("stop"), str),
            "physical backup/WAL range incomplete")
    pgbackrest(stanza, "verify", "--set=" + row["label"])
    return {"stanza": stanza, "label": row["label"], "archive": row["archive"],
            "lsn": row.get("lsn", {}), "timestamps": row["timestamp"]}


def s3_version_inventory(bucket, endpoint):
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket)), "Некорректное имя корзины S3")
    options = dr.s3_options(endpoint)
    versioning = json.loads(execute(["aws", *options, "s3api", "get-bucket-versioning",
                                     "--bucket", bucket, "--output", "json"]))
    require(versioning.get("Status") == "Enabled", "В бакете S3 должно быть включено версионирование")
    rows = []
    marker = None
    seen_markers = set()
    while True:
        command = ["aws", *options, "s3api", "list-object-versions", "--bucket", bucket,
                   "--max-keys", "1000", "--no-paginate", "--output", "json"]
        if marker is not None:
            command.extend(("--key-marker", marker[0]))
            if marker[1]:
                command.extend(("--version-id-marker", marker[1]))
        payload = json.loads(execute(command, timeout=180))
        for kind in ("Versions", "DeleteMarkers"):
            for entry in payload.get(kind, []):
                require(isinstance(entry.get("Key"), str) and isinstance(entry.get("VersionId"), str)
                        and isinstance(entry.get("IsLatest"), bool), "Недопустимая инвентаризация версий S3")
                rows.append((kind, entry["Key"], entry["VersionId"], entry["IsLatest"],
                             entry.get("Size") if kind == "Versions" else None))
        require(len(rows) <= 2_000_000, "Инвентаризация S3 превышает допустимый объём резервного копирования")
        if not payload.get("IsTruncated", False):
            break
        next_marker = (payload.get("NextKeyMarker"), payload.get("NextVersionIdMarker"))
        require(isinstance(next_marker[0], str) and next_marker[0] and
                next_marker not in seen_markers, "S3 pagination did not advance")
        marker = next_marker
        seen_markers.add(marker)
    return sorted(rows)


def tree_files(folder):
    result = {}
    require(folder.is_dir() and not folder.is_symlink(), "Дерево резервной копии отсутствует или небезопасно")
    for entry in folder.rglob("*"):
        st = entry.lstat()
        require(not stat.S_ISLNK(st.st_mode) and (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)),
                "unsafe backup tree entry")
        if stat.S_ISREG(st.st_mode):
            require(st.st_nlink == 1, "hardlinked backup payload")
            result[entry.relative_to(folder).as_posix()] = {"size": st.st_size, "sha256": dr.sha256_file(entry)}
    return dict(sorted(result.items()))


def archive_payload_file(folder, source):
    require(source.is_file() and not source.is_symlink(), "Данные резервной копии отсутствуют")
    return {"size": source.stat().st_size, "sha256": dr.sha256_file(source)}


def read_private_json(path):
    try:
        return json.loads(safe_file(path, max_size=512 * 1024))
    except (ValueError, UnicodeError) as exc:
        raise BackupError("Некорректное значение: «private JSON document»") from exc


def world_spec(path):
    # Произвольные строки команд запрещены: каждое удалённое задание вызывает реальный CLI Launcher.
    spec = read_private_json(path)
    require(isinstance(spec, list) and len(spec) > 0, "Необходим хотя бы один игровой мир")
    seen = set()
    for row in spec:
        require(isinstance(row, dict) and set(row) == {"name", "target", "serverRoot", "backupRoot", "world"},
                "Недопустимое описание узла игрового мира")
        require(bool(NAME.fullmatch(row["name"])) and row["name"] not in seen and
                bool(multi.HOST_REGEX.fullmatch(row["target"])), "Недопустимый или повторяющийся целевой игровой мир")
        for field in ("serverRoot", "backupRoot"):
            require(isinstance(row[field], str) and row[field].startswith("/") and
                    ".." not in Path(row[field]).parts, "unsafe world host path")
        require(bool(NAME.fullmatch(row["world"])), "Недопустимое имя игрового мира")
        seen.add(row["name"])
    return spec


def local_world_create(cli, server_root, backup_root, world, run_id):
    require(cli.startswith("/") and Path(cli).is_file() and not Path(cli).is_symlink(), "Отсутствует доверенный исполняемый файл CLI")
    require(server_root.startswith("/") and backup_root.startswith("/") and
            bool(NAME.fullmatch(world)) and bool(RUN_ID.fullmatch(run_id)),
            "unsafe world backup input")
    out = execute([cli, "server-bridge", "host", "world-backup", "create",
                   "--server-root", server_root, "--backup-root", backup_root,
                   "--consistency", "stop", "--world", world,
                   "--hold-id", run_id], timeout=3600)
    try:
        data = json.loads(out)
    except (ValueError, UnicodeError) as exc:
        raise BackupError("Некорректное значение: «world CLI response»") from exc
    m = data.get("manifest", {})
    require(m.get("consistency") == "confirmed-stopped" and bool(dr.WORLD_BACKUP_ID.fullmatch(str(m.get("id", "")))),
            "real world stop/backup not confirmed")
    dr.safe_world_backup(Path(backup_root) / m["id"])
    return {"backupId": m["id"], "createdAt": m["createdAt"], "holdId": run_id}


def local_world_release(cli, server_root, run_id):
    require(cli.startswith("/") and Path(cli).is_file() and not Path(cli).is_symlink()
            and server_root.startswith("/") and bool(RUN_ID.fullmatch(run_id)),
            "Недопустимый запрос выпуска игрового мира")
    execute([cli, "server-bridge", "host", "world-backup", "release",
             "--server-root", server_root, "--hold-id", run_id], timeout=60)
    return {"status": "world-released", "holdId": run_id}


def local_world_stream(backup_root, backup_id):
    require(backup_root.startswith("/") and bool(dr.WORLD_BACKUP_ID.fullmatch(backup_id)), "unsafe world archive request")
    dr.safe_world_backup(Path(backup_root) / backup_id)
    proc = subprocess.Popen(["tar", "-czf", "-", "-C", backup_root, backup_id],
                            stdout=sys.stdout.buffer, stderr=subprocess.PIPE)
    try:
        proc.communicate(timeout=7200)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.communicate()
        raise BackupError("Превышено время ожидания архивации игрового мира")
    require(proc.returncode == 0, "Архивация игрового мира завершилась ошибкой")


def unpack_safe_tar(path: Path, dest: Path):
    require(not dest.exists(), "unpack destination exists")
    dest.mkdir(parents=True, mode=0o700)
    with tarfile.open(path, "r:gz") as archive:
        seen = set()
        for entry in archive:
            name = entry.name.removeprefix("./")
            parts = name.rstrip("/").split("/")
            require(name not in seen and not entry.name.startswith("/") and
                    all(x not in ("", ".", "..") for x in parts) and "\\" not in name and
                    (entry.isfile() or entry.isdir()), "unsafe archive member")
            seen.add(name)
            target = dest.joinpath(*parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                require(target.parent.is_dir() and not target.is_symlink(), "Недопустимый родительский каталог архива")
                require(entry.size >= 0 and entry.size < (1 << 43), "Недопустимый размер архива")
                source = archive.extractfile(entry)
                require(source is not None, "Недопустимый файл архива")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, STREAM_CHUNK)
                os.chmod(target, 0o600)


def local_agent(args):
    directory = Path(args.directory)
    if args.action == "local-freeze":
        return freeze(directory, args.project, args.run_id)
    if args.action == "local-thaw":
        return thaw(directory, args.project, args.run_id)
    if args.action == "local-check":
        row = assert_frozen(directory, args.project, args.run_id)
        return {"status": "frozen", "nodeId": row["nodeId"], "runId": args.run_id}
    if args.action == "local-volume":
        stream_volume(directory, args.project, args.run_id, args.volume, args.tar_image)
        return None
    if args.action == "local-world-create":
        return local_world_create(args.world_cli, args.server_root, args.backup_root, args.world, args.run_id)
    if args.action == "local-world-stream":
        local_world_stream(args.backup_root, args.backup_id)
        return None
    if args.action == "local-world-release":
        return local_world_release(args.world_cli, args.server_root, args.run_id)
    raise BackupError("Неизвестное значение: «local operation»")


def remote_json(target, script, action, *, directory, project, run_id, extras=(), timeout=240):
    raw = execute(ssh(target, script, action, "--directory", directory, "--project", project,
                      "--run-id", run_id, *extras), timeout=timeout)
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise BackupError("Некорректное значение: «remote agent receipt»") from exc


def validate_backup(folder, *, stanza=None):
    require(folder.is_dir() and not folder.is_symlink(), "Каталог резервной копии отсутствует или небезопасен")
    path = folder / "manifest.json"
    try:
        document = json.loads(safe_file(path, max_size=8 * 1024 * 1024))
    except (ValueError, UnicodeError, OSError) as exc:
        raise BackupError("Некорректное значение: «backup manifest»") from exc
    require(document.get("schema") == SCHEMA and bool(RUN_ID.fullmatch(str(document.get("runId", "")))),
            "Неподдерживаемый формат резервной копии")
    expected = document.get("files")
    require(isinstance(expected, dict) and expected, "Отсутствуют хеши файлов резервной копии")
    actual = tree_files(folder)
    actual.pop("manifest.json", None)
    require(expected == actual, "Несовпадение контрольных сумм данных резервной копии и инвентаризации")
    require(document.get("postgres", {}).get("backup", {}).get("label") and
            len(document.get("nodes", [])) >= 2 and len(document.get("worlds", [])) >= 1,
            "backup lacks PostgreSQL, nodes or worlds")
    # Проверяйте реальные байты и структуру файлов, а не только SHA-256 архива.
    for filename in expected:
        if filename.endswith(".tar.gz"):
            dr.safe_tar(folder / filename)
    for row in document["worlds"]:
        world_path = folder / "worlds" / row["name"] / row["backupId"]
        dr.safe_world_backup(world_path)
        require(dr.sha256_file(world_path / "manifest.json") == row["manifestSha256"],
                "world receipt changed")
    s3_inventory = folder / "s3-versions.json"
    require(s3_inventory.is_file() and not s3_inventory.is_symlink(), "Отсутствует инвентаризация версий S3")
    require(hashlib.sha256(json.dumps(json.loads(s3_inventory.read_text()),
                                   separators=(",", ":")).encode()).hexdigest() ==
            document["s3"]["versionInventorySha256"], "S3 version inventory changed")
    require(tree_files(folder / "s3") == document["s3"]["files"], "S3 object payload changed")
    if stanza:
        require(stanza == document["postgres"]["backup"]["stanza"], "wrong PostgreSQL stanza")
        pgbackrest(stanza, "check")
        pgbackrest(stanza, "verify", "--set=" + document["postgres"]["backup"]["label"])
        info = pg_info(stanza)
        found = [x for x in info.get("backup", []) if x.get("label") == document["postgres"]["backup"]["label"]]
        require(len(found) == 1 and found[0].get("archive") == document["postgres"]["backup"]["archive"],
                "В хранилище отсутствует резервная копия PITR или диапазон WAL")
    return {"status": "verified", "runId": document["runId"],
            "physicalBackup": document["postgres"]["backup"]["label"], "files": len(expected)}


def orchestrate(args):
    require(args.acknowledge_maintenance, "Требуется явное подтверждение --acknowledge-maintenance")
    require(bool(RUN_ID.fullmatch(args.run_id)), "Недопустимый идентификатор запуска")
    nodes = multi.parse_nodes(args.node)
    require(bool(multi.PROJECT_REGEX.fullmatch(args.project)), "Недопустимый проект")
    require(args.directory.startswith("/") and not args.directory.endswith("/.."), "Недопустимый каталог развёртывания")
    require(bool(multi.DIGEST_REGEX.fullmatch(args.tar_image)), "Требуется неизменяемый tar-образ OCI")
    require(bool(PG_STANZA.fullmatch(args.stanza)), "Недопустимая конфигурация pgBackRest stanza")
    worlds = world_spec(Path(args.world_file))
    trust = read_private_json(Path(args.trust_file))
    require(isinstance(trust, dict) and trust and all(isinstance(k, str) and HEX64.fullmatch(str(v)) for k,v in trust.items()),
            "Хеши доверенных корневых ключей в защищённом хранении необходимо указать явно")
    require(args.external_auth_policy in ("none", "included"), "Необходимо явно определить охват внешней аутентификации")
    if args.external_auth_policy == "included":
        require(args.external_source, "Требуются источники внешней аутентификации")
    else:
        require(not args.external_source, "external source contradicts none policy")
    dest = Path(args.destination)
    require(not dest.exists() and not dest.is_symlink(), "Путь назначения резервной копии должен быть новым")
    require(dest.parent.is_dir() and stat.S_IMODE(dest.parent.stat().st_mode) & 0o077 == 0,
            "Родительский каталог резервной копии должен иметь права 0700")
    start = datetime.now(timezone.utc)
    stage = Path(tempfile.mkdtemp(prefix=".cohort-0518-", dir=dest.parent))
    os.chmod(stage, 0o700)
    frozen = []
    frozen_reports = []
    world_holds = []
    resume_errors = []
    success = False
    try:
        for label, host in nodes.items():
            # Сначала добавьте запись в журнал: SSH может потеряться ПОСЛЕ остановки удалённого узла. Позднее
            # размораживание всё равно должно попытаться восстановить этот узел.
            frozen.append((label, host))
            report = remote_json(host, args.remote_script, "local-freeze", directory=args.directory,
                                 project=args.project, run_id=args.run_id, timeout=240)
            require(report.get("status") == "frozen" and report.get("runId") == args.run_id,
                    "Не удалось заморозить удалённый узел")
            frozen_reports.append(report)
        require(len({r.get("nodeId") for r in frozen_reports}) == len(nodes) and
                len({r.get("machineIdentity") for r in frozen_reports}) == len(nodes) and
                all(isinstance(r.get("machineIdentity"), str) and r["machineIdentity"] for r in frozen_reports),
                "multi-host backup requires different real machine IDs and replica IDs")
        require(all(r.get("sharedEndpoints") == frozen_reports[0]["sharedEndpoints"] for r in frozen_reports),
                "cohort hosts disagree on shared dependencies")
        require(frozen_reports[0]["sharedEndpoints"].get("bucket") == args.s3_bucket,
                "requested S3 bucket differs from the active deployment")
        frozen_at = datetime.now(timezone.utc)
        # ОСТАНОВИТЕ запись игровых миров ДО контрольной точки PostgreSQL. Мир, изменённый после точки БД, не
        # образует согласованную группу данных.
        world_receipts = []
        for row in worlds:
            # Регистрируйте возможную задержку до SSH: удалённый узел может зафиксировать действие и потерять ответ. В
            # блоке finally всегда пытайтесь явно освободить ресурсы.
            world_holds.append(row)
            data = remote_json(row["target"], args.remote_script, "local-world-create",
                               directory=args.directory, project=args.project, run_id=args.run_id,
                               extras=("--world-cli", args.world_cli, "--server-root", row["serverRoot"],
                                       "--backup-root", row["backupRoot"], "--world", row["world"]), timeout=4000)
            require(data.get("holdId") == args.run_id, "game host did not retain the launch gate")
            moment = datetime.fromisoformat(data["createdAt"].replace("Z", "+00:00"))
            require(moment >= frozen_at and moment <= datetime.now(timezone.utc),
                    "Снимок игрового мира не был создан в период заморозки резервного копирования")
            name = row["name"]
            wid = data["backupId"]
            loc = stage / "worlds" / name
            stream = stage / (".world-" + name + ".tar.gz")
            stream_command(ssh(row["target"], args.remote_script, "local-world-stream",
                               "--directory", args.directory, "--project", args.project,
                               "--run-id", args.run_id, "--backup-root", row["backupRoot"], "--backup-id", wid), stream)
            unpack_safe_tar(stream, loc)
            stream.unlink()
            manifest = dr.safe_world_backup(loc / wid)
            world_receipts.append({"name": name, "backupId": wid,
                                   "manifestSha256": dr.sha256_file(loc / wid / "manifest.json"),
                                   "bytes": manifest["totalBytes"]})
        first = pg_query(Path(args.pg_dsn_file))
        physical = backup_physical(args.stanza)
        # Проверяйте ПОСЛЕ pgBackRest, который записывает собственные метки копии WAL.
        pg_boundary = pg_query(Path(args.pg_dsn_file))
        # Реальный логический дамп даёт независимое доказательство согласованности идентичностей и схемы.
        with (stage / "identity-and-metadata.dump").open("xb") as fd:
            env = nn.dsn_environment(Path(args.pg_dsn_file))
            proc = subprocess.run(["pg_dump", "--format=custom", "--no-owner", "--no-acl"],
                                  env=env, stdout=fd, stderr=subprocess.PIPE, timeout=3600, check=False)
            require(proc.returncode == 0, "Логическая выгрузка учётных записей PostgreSQL завершилась ошибкой")
        execute(["pg_restore", "--list", str(stage / "identity-and-metadata.dump")], timeout=120)
        s3_before = s3_version_inventory(args.s3_bucket, args.s3_endpoint)
        # Всё локальное устойчивое состояние каждого узла считывается, пока запись остановлена.
        for label, host in nodes.items():
            report = remote_json(host, args.remote_script, "local-check", directory=args.directory,
                                 project=args.project, run_id=args.run_id)
            require(report.get("status") == "frozen", "host resumed during backup")
            loc = stage / "hosts" / label
            loc.mkdir(parents=True, mode=0o700)
            for volume in VOLUMES:
                stream_command(ssh(host, args.remote_script, "local-volume", "--directory", args.directory,
                                   "--project", args.project, "--run-id", args.run_id,
                                   "--volume", volume, "--tar-image", args.tar_image),
                               loc / (volume + ".tar.gz"))
                dr.tar_digests(loc / (volume + ".tar.gz"))
        # Версии до и после копирования позволяют обнаружить независимую запись объектов.
        s3_dir = stage / "s3"
        dr.s3_download(args.s3_bucket, s3_dir, args.s3_endpoint)
        s3_files = tree_files(s3_dir)
        s3_after = s3_version_inventory(args.s3_bucket, args.s3_endpoint)
        require(s3_before == s3_after, "S3 object versions changed during snapshot")
        with tempfile.TemporaryDirectory(dir=stage, prefix=".s3-readback-") as tmp:
            again = Path(tmp) / "objects"
            dr.s3_download(args.s3_bucket, again, args.s3_endpoint)
            require(tree_files(again) == s3_files and s3_version_inventory(args.s3_bucket, args.s3_endpoint) == s3_before,
                    "S3 readback or version inventory disagrees")
        (stage / "s3-versions.json").write_text(json.dumps(s3_before, separators=(",", ":")))
        os.chmod(stage / "s3-versions.json", 0o600)
        # На протяжении сбора S3 и миров запись должна быть заморожена, а внешние записи PostgreSQL исключены.
        for _,host in nodes.items():
            row = remote_json(host, args.remote_script, "local-check", directory=args.directory,
                              project=args.project, run_id=args.run_id)
            require(row.get("status") == "frozen", "API/worker restarted during cohort")
        final_lsn = pg_query(Path(args.pg_dsn_file))
        require(final_lsn == pg_boundary, "PostgreSQL WAL advanced during S3/world snapshot")
        # После снимка обязательно повторно проверяйте архив; затем pgBackRest verify проверяет фактические байты
        # резервной копии и WAL, а не одну квитанцию.
        pgbackrest(args.stanza, "check")
        data = {"schema": SCHEMA, "version": "0.51.8", "runId": args.run_id,
                "startUtc": start.isoformat(), "frozenUtc": frozen_at.isoformat(),
                "completedUtc": datetime.now(timezone.utc).isoformat(),
                "postgres": {"backup": physical, "admissionLsn": first,
                             "cohortLsn": pg_boundary, "finalLsn": final_lsn},
                "nodes": [{"label": label, "nodeId": r["nodeId"], "machineIdentity": r["machineIdentity"]}
                          for (label, _), r in zip(nodes.items(), frozen_reports)], "worlds": world_receipts,
                "s3": {"bucket": args.s3_bucket, "versionInventorySha256":
                       hashlib.sha256(json.dumps(s3_before, separators=(",", ":")).encode()).hexdigest(),
                       "files": s3_files},
                "trustEscrowSha256": trust, "externalAuthPolicy": args.external_auth_policy,
                "limitations": "PITR вне общей контрольной точки применим только к PostgreSQL; игровые миры и S3 требуют соответствующей контрольной точки",
                "files": {}}
        for entry in args.external_source:
            key, sep, path = entry.partition("=")
            require(sep and bool(NAME.fullmatch(key)) and Path(path).is_file() and not Path(path).is_symlink(),
                    "Недопустимый источник внешнего провайдера")
            dest_file = stage / "external" / key
            dest_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with Path(path).open("rb") as src, dest_file.open("xb") as target:
                shutil.copyfileobj(src, target, STREAM_CHUNK)
            require(dr.sha256_file(Path(path)) == dr.sha256_file(dest_file), "external provider file changed")
        data["files"] = tree_files(stage)
        (stage / "manifest.json").write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
        os.chmod(stage / "manifest.json", 0o600)
        validate_backup(stage, stanza=args.stanza)
        # Публикуйте на той же файловой системе только после полной проверки.
        require(not dest.exists(), "backup destination appeared during execution")
        os.rename(stage, dest)
        sync_dir(dest.parent)
        success = True
        return {"status": "complete", "runId": args.run_id, "destination": str(dest),
                "pgBackup": physical["label"], "cohortLsn": final_lsn,
                "nodes": len(nodes), "worlds": len(world_receipts)}
    finally:
        # Держите миры заблокированными во время снимка PostgreSQL/S3. Освобождайте их только после всех чтений и
        # проверки WAL, прежде чем возобновить API/обработчики.
        for row in reversed(world_holds):
            try:
                result = remote_json(row["target"], args.remote_script, "local-world-release",
                                     directory=args.directory, project=args.project, run_id=args.run_id,
                                     extras=("--world-cli", args.world_cli,
                                             "--server-root", row["serverRoot"]), timeout=90)
                require(result.get("status") == "world-released" and
                        result.get("holdId") == args.run_id, "Блокировка запуска игрового мира не снята")
            except (BackupError, ValueError):
                resume_errors.append(row["name"] + "(world-gate)")
        # Возобновляйте службы даже при ошибке, но НЕ заявляйте об успехе, если перезапуск не удался. Никогда не
        # возобновляйте плоскость управления, если блокировку мира нельзя снять: это откроет доступ к опасно
        # частично восстановленному игровому хосту.
        if not resume_errors:
            for label,host in reversed(frozen):
                try:
                    report = remote_json(host, args.remote_script, "local-thaw", directory=args.directory,
                                         project=args.project, run_id=args.run_id, timeout=240)
                    require(report.get("status") == "resumed", "host did not resume")
                except (BackupError, ValueError):
                    resume_errors.append(label)
        if not success and stage.exists():
            shutil.rmtree(stage)
        if resume_errors:
            raise BackupError("Необходимо ручное восстановление: API или рабочий процесс не перезапустились на " + ",".join(resume_errors))


def restore_pg_fresh(args):
    # Восстанавливаются только физические данные PostgreSQL в НОВЫЙ ПУСТОЙ PGDATA. Устаревшие аренды Redis не
    # импортируются; миры и S3 автоматически не откатываются к несогласованным моментам времени.
    data = read_private_json(Path(args.backup) / "manifest.json")
    require(data.get("schema") == SCHEMA, "wrong backup manifest")
    label = data.get("postgres", {}).get("backup", {}).get("label", "")
    require(bool(BACKUP_LABEL.fullmatch(label)), "Недопустимая метка физической резервной копии")
    require(args.confirm == label, "PITR restore requires exact --confirm backup label")
    target = Path(args.pgdata)
    require(target.is_absolute() and not target.exists() and not target.is_symlink(),
            "Каталог восстановления PostgreSQL должен отсутствовать (чистый узел)")
    parent = target.parent
    require(parent.is_dir() and not parent.is_symlink(), "Родительский каталог восстановления должен быть настоящим каталогом")
    for ancestor in (parent, *parent.parents):
        require(not ancestor.is_symlink(), "symlink in restore destination ancestry")
    require(bool(PG_STANZA.fullmatch(args.stanza)) and args.stanza == data["postgres"]["backup"]["stanza"],
            "Несовпадение конфигурации stanza при восстановлении")
    validate_backup(Path(args.backup), stanza=args.stanza)
    if args.action == "cohort-pg-restore-fresh":
        # Восстанавливайте ТОЧНЫЙ LSN, закреплённый вместе со снимком S3/миров; нельзя незаметно продвигать
        # PostgreSQL дальше согласованной группы.
        lsn = data["postgres"].get("cohortLsn", "")
        require(bool(re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", lsn)), "Недопустимый общий LSN")
        recovery = ("--type=lsn", "--target=" + lsn)
        target_desc = lsn
    else:
        require(args.target_time and args.pg_only_reconciliation_ack,
                "non-cohort PostgreSQL PITR requires explicit reconciliation acknowledgement")
        date = datetime.fromisoformat(args.target_time.replace("Z", "+00:00"))
        require(date.tzinfo is not None, "Время PITR должно содержать часовой пояс")
        recovery = ("--type=time", "--target=" + date.isoformat(sep=" "))
        target_desc = date.astimezone(timezone.utc).isoformat()
    # pgBackRest восстанавливает файлы данных и конфигурацию восстановления, но НЕ воспроизводит WAL до
    # запуска PostgreSQL на изолированном целевом узле. Не возвращайте табличные пространства на исходные пути
    # прежнего кластера.
    tablespaces = target.with_name(target.name + "-tablespaces")
    require(not tablespaces.exists() and not tablespaces.is_symlink(),
            "Целевой каталог нового табличного пространства PostgreSQL уже существует")
    pgbackrest(args.stanza, "--pg1-path=" + str(target), "--tablespace-map-all=" + str(tablespaces),
               "--set=" + label, *recovery, "--target-action=pause", "restore")
    require(target.is_dir() and (target / "PG_VERSION").is_file(),
            "pgBackRest did not write an actual PostgreSQL data directory")
    return {"status": "restored-not-started", "dataDirectory": str(target),
            "target": target_desc,
            "warning": "Воспроизведение журнала PG WAL ещё не проверено; согласованность группы S3/миров не подтверждена для произвольного момента восстановления"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("backup", "verify", "pitr-restore-fresh", "cohort-pg-restore-fresh", "local-freeze",
                                      "local-thaw", "local-check", "local-volume",
                                      "local-world-create", "local-world-stream", "local-world-release"))
    p.add_argument("--directory", default="/opt/launcher/deploy/production")
    p.add_argument("--project", default="launcher")
    p.add_argument("--run-id", default="")
    p.add_argument("--node", action="append", default=[])
    p.add_argument("--remote-script", default="/opt/launcher/scripts/operations/consistent_backup_0518.py")
    p.add_argument("--destination")
    p.add_argument("--backup")
    p.add_argument("--pgdata")
    p.add_argument("--pg-dsn-file")
    p.add_argument("--stanza")
    p.add_argument("--s3-bucket")
    p.add_argument("--s3-endpoint")
    p.add_argument("--tar-image")
    p.add_argument("--volume")
    p.add_argument("--world-file")
    p.add_argument("--world-cli", default="/opt/launcher/bin/nl")
    p.add_argument("--server-root")
    p.add_argument("--backup-root")
    p.add_argument("--world")
    p.add_argument("--backup-id")
    p.add_argument("--trust-file")
    p.add_argument("--external-auth-policy", choices=("none", "included"))
    p.add_argument("--external-source", action="append", default=[])
    p.add_argument("--acknowledge-maintenance", action="store_true")
    p.add_argument("--target-time")
    p.add_argument("--confirm")
    p.add_argument("--pg-only-reconciliation-ack", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.action.startswith("local-"):
            result = local_agent(args)
        elif args.action == "backup":
            result = orchestrate(args)
        elif args.action == "verify":
            result = validate_backup(Path(args.backup), stanza=args.stanza)
        else:
            result = restore_pg_fresh(args)
        if result is not None:
            print(json.dumps(result, sort_keys=True))
        return 0
    except (BackupError, dr.DrillError, multi.DeploymentError, nn.CompatibilityError,
            OSError, ValueError, KeyError, TypeError) as exc:
        # Не раскрывайте аргументы или окружение: они могут содержать учётные данные.
        print(json.dumps({"status": "failed", "reason": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
