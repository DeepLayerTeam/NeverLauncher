#!/usr/bin/env python3
"""Автономное транзакционное резервное копирование, проверка и восстановление минимальной установки Launcher.

Все службы записи приложения ДОЛЖНЫ быть остановлены. Утилита берёт тот же Linux flock, что и API, и
блокировки владельца SQLite; она не выдаёт живое копирование за согласованное с моментом фиксации
SQLite. Пакеты содержат незашифрованные учётные данные: храните их закрыто и шифруйте при переносе с
хоста. Контрольные суммы обнаруживают повреждения, но не злоумышленника, способного переписать и
данные, и манифест.
"""

import argparse
import ctypes
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import sqlite3
import stat
import sys
import tempfile
from urllib.parse import quote

FORMAT = "launcher-minimal-offline-backup-v1"
DB_NAMES = ("db/http.sqlite", "db/coordinator.sqlite")
RELOCATED = {
    "LAUNCHER_DATABASE_DSN": "db/http.sqlite",
    "LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH": "db/coordinator.sqlite",
    "LAUNCHER_STORAGE_LOCAL_PATH": "storage",
    "LAUNCHER_BACKUP_ROOT": "backups",
    "LAUNCHER_EXTENSION_ROOT": "extensions",
}
OPTIONAL_RELOCATED = {"LAUNCHER_FACTORY_ROOT": "factory"}
EXCLUDED_FILES = (".launcher-api.owner.lock",)
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


class BackupError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise BackupError(message)


def fsync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_path(path, *, directory=False, owner=True):
    st = path.lstat()
    require(
        (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)),
        f"Небезопасный тип объекта по пути: {path}",
    )
    require(not stat.S_ISLNK(st.st_mode), f"Символические ссылки запрещены: {path}")
    if owner:
        require(st.st_uid == os.geteuid(), f"Путь не принадлежит пользователю службы: {path}")
    require((st.st_mode & 0o022) == 0, f"Путь доступен для записи группе или другим пользователям: {path}")
    if not directory:
        require(st.st_nlink == 1, f"Файл с несколькими жёсткими ссылками запрещён: {path}")
    return st


def publish_new_directory(source, destination):
    """Linux renameat2(RENAME_NOREPLACE): другой процесс не может подменить цель."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))


def private_directory(path):
    st = check_path(path, directory=True)
    require((st.st_mode & 0o077) == 0, f"Закрытый каталог должен иметь права 0700: {path}")


def safe_absolute(path):
    p = Path(os.path.abspath(path))
    require(p.is_absolute() and p != Path("/"), "Требуется абсолютный путь, отличный от корневого каталога")
    # Проверяйте все существующие сегменты пути, включая родительские каталоги назначения.
    for parent in reversed((p, *p.parents)):
        if parent.is_symlink():
            raise BackupError(f"Символическая ссылка в компоненте пути: {parent}")
    return p


def read_install(root):
    private_directory(root)
    env = root / "config/backend.env"
    st = check_path(env)
    require(st.st_mode & 0o077 == 0, "Файл backend.env должен иметь права 0600")
    values = {}
    for line in env.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        require("=" in line, "Некорректная запись в backend.env")
        key, value = line.split("=", 1)
        require(
            key.startswith("LAUNCHER_") and key not in values,
            "bad/duplicate backend.env key",
        )
        values[key] = value
    require(
        values.get("LAUNCHER_DEPLOYMENT_MODE") == "single-node"
        and values.get("LAUNCHER_REPOSITORY_DRIVER") == "sqlite"
        and values.get("LAUNCHER_STORAGE_DRIVER") == "local",
        "Установка не соответствует минимальному варианту SQLite",
    )
    for key, suffix in RELOCATED.items():
        require(
            values.get(key) == str(root / suffix),
            f"Нестандартный путь {key}: резервная копия должна быть самодостаточной",
        )
    for key, suffix in OPTIONAL_RELOCATED.items():
        if key in values:
            require(
                values[key] == str(root / suffix),
                f"Нестандартный путь {key}: невозможно создать полную резервную копию",
            )
    require(not values.get("LAUNCHER_REDIS_URL"), "Минимальная установка не должна использовать Redis")
    return values


@contextmanager
def offline_locks(root):
    """Всегда соблюдать одинаковый порядок блокировок. Обязателен flock API, одной проверки PID недостаточно."""
    with ExitStack() as stack:
        for relative in (
            "storage/.launcher-api.owner.lock",
            "db/http.sqlite.owner.lock",
            "db/coordinator.sqlite.owner.lock",
        ):
            lock = root / relative
            private_directory(lock.parent)
            fd = os.open(
                lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            stack.callback(os.close, fd)
            fd_stat = os.fstat(fd)
            require(
                stat.S_ISREG(fd_stat.st_mode)
                and fd_stat.st_uid == os.geteuid()
                and fd_stat.st_nlink == 1
                and fd_stat.st_mode & 0o077 == 0,
                f"Небезопасная блокировка: {lock}",
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BackupError(
                    f"API или SQLite работает; перед резервным копированием остановите все записывающие процессы: {lock}"
                ) from exc
            require(
                os.path.samestat(os.stat(lock, follow_symlinks=False), fd_stat),
                "lock path changed",
            )
        yield


def sqlite_integrity(path):
    check_path(path)
    # Неизменяемый файл только для запросов; у снимка нет WAL, он должен быть самодостаточным.
    with closing(
        sqlite3.connect(
            "file:" + quote(str(path)) + "?mode=ro&immutable=1", uri=True, timeout=10
        )
    ) as conn:
        require(
            conn.execute("PRAGMA integrity_check").fetchone() == ("ok",),
            f"Проверка целостности SQLite не пройдена: {path}",
        )
        require(
            conn.execute("PRAGMA foreign_key_check").fetchone() is None,
            f"Проверка внешних ключей SQLite не пройдена: {path}",
        )


def copy_sqlite(source, target):
    check_path(source)
    # Backup API захватывает зафиксированные кадры WAL. Никогда не копируйте сырое живое трио WAL.
    with closing(
        sqlite3.connect("file:" + quote(str(source)) + "?mode=ro", uri=True, timeout=15)
    ) as src:
        with closing(sqlite3.connect(target, timeout=15)) as dst:
            src.backup(dst, pages=128, sleep=0.05)
            dst.commit()
    os.chmod(target, 0o600)
    sqlite_integrity(target)
    with target.open("rb") as stream:
        os.fsync(stream.fileno())


def file_copy(source, target):
    before = check_path(source)
    with source.open("rb") as reader, target.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
    os.chmod(target, stat.S_IMODE(before.st_mode) & 0o700)
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"Файл изменился во время резервного копирования: {source}",
    )


def file_record(path, relative, kind):
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            size += len(data)
            digest.update(data)
    return {
        "path": relative,
        "kind": kind,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def paths_in(root):
    """Перечислить все файлы минимальной установки, кроме отдельно хранимых резервных копий и временных
файлов SQLite."""
    dirs = ["."]
    files = []
    for current, names, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        rel_dir = base.relative_to(root)
        check_path(base, directory=True)
        if rel_dir == Path("."):
            require("backups" in names, "Отсутствует каталог резервных копий")
            private_directory(root / "backups")
            names.remove("backups")
        names.sort()
        for name in names:
            check_path(base / name, directory=True)
            dirs.append((base / name).relative_to(root).as_posix())
        for name in sorted(filenames):
            path = base / name
            check_path(path)
            if name in EXCLUDED_FILES or name.endswith(
                (".owner.lock", "-wal", "-shm", "-journal")
            ):
                continue
            files.append((path.relative_to(root).as_posix(), path))
    return sorted(dirs), sorted(files)


def dump_json_atomic(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(
            json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True).encode(
                "utf-8"
            )
            + b"\n"
        )
        stream.flush()
        os.fsync(stream.fileno())


def validate_relative(raw):
    require(
        isinstance(raw, str)
        and raw not in ("", ".")
        and "\\" not in raw
        and "\x00" not in raw,
        "invalid relative path in bundle",
    )
    path = PurePosixPath(raw)
    require(
        not path.is_absolute()
        and all(p not in ("", ".", "..") for p in raw.split("/"))
        and path.as_posix() == raw,
        f"Неканонический путь в пакете: {raw}",
    )
    return path


def verify(bundle):
    bundle = safe_absolute(bundle)
    private_directory(bundle)
    payload = bundle / "payload"
    private_directory(payload)
    st = check_path(bundle / "manifest.json")
    require(
        st.st_size <= MAX_MANIFEST_BYTES and st.st_mode & 0o077 == 0, "unsafe manifest"
    )
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    require(
        manifest.get("format") == FORMAT
        and isinstance(manifest.get("files"), list)
        and isinstance(manifest.get("directories"), list)
        and isinstance(manifest.get("sourceRoot"), str),
        "Неподдерживаемый формат резервной копии",
    )
    declared_dirs = manifest["directories"]
    declared_files = manifest["files"]
    require(
        declared_dirs == sorted(set(declared_dirs)) and "." in declared_dirs,
        "invalid directory index",
    )
    for d in declared_dirs:
        if d != ".":
            validate_relative(d)
            require(not d.startswith("backups/"), "Рекурсивное резервное копирование запрещено")
    filepaths = []
    for record in declared_files:
        require(
            isinstance(record, dict)
            and set(record) == {"path", "kind", "bytes", "sha256", "mode"},
            "invalid record",
        )
        rel = record["path"]
        validate_relative(rel)
        require(
            rel != "backups" and not rel.startswith("backups/"),
            "Рекурсивное резервное копирование запрещено",
        )
        require(
            record["kind"] in ("sqlite", "file")
            and type(record["bytes"]) is int
            and record["bytes"] >= 0
            and type(record["mode"]) is int
            and 0 <= record["mode"] <= 0o700
            and isinstance(record["sha256"], str)
            and len(record["sha256"]) == 64,
            "invalid file metadata",
        )
        path = payload / rel
        st = check_path(path)
        require(st.st_mode & 0o077 == 0, f"Файл пакета доступен посторонним: {path}")
        actual = file_record(path, rel, record["kind"])
        require(
            actual["bytes"] == record["bytes"] and actual["sha256"] == record["sha256"],
            f"Файл резервной копии повреждён: {rel}",
        )
        if rel in DB_NAMES:
            require(
                record["kind"] == "sqlite", f"Обязательная база данных должна быть SQLite: {rel}"
            )
        if record["kind"] == "sqlite":
            sqlite_integrity(path)
        filepaths.append(rel)
    require(filepaths == sorted(set(filepaths)), "Пути дублируются или указаны не по порядку")
    require(
        all(name in filepaths for name in DB_NAMES), "Обязательная база данных SQLite отсутствует"
    )
    actual_dirs, actual_files = paths_payload(payload)
    require(
        declared_dirs == actual_dirs and filepaths == actual_files,
        f"Неполное или неожиданное содержимое пакета: ожидались каталоги {declared_dirs}, обнаружены {actual_dirs}; ожидались файлы {filepaths}, обнаружены {actual_files}",
    )
    require("config/backend.env" in filepaths, "Отсутствует конфигурация резервного копирования")
    return manifest


def paths_payload(payload):
    dirs = ["."]
    files = []
    for current, names, filenames in os.walk(payload, followlinks=False):
        base = Path(current)
        private_directory(base)
        for name in sorted(names):
            check_path(base / name, directory=True)
            dirs.append((base / name).relative_to(payload).as_posix())
        for name in filenames:
            check_path(base / name)
            files.append((base / name).relative_to(payload).as_posix())
    return sorted(dirs), sorted(files)


def backup(root, destination=None):
    root = safe_absolute(root)
    read_install(root)
    with offline_locks(root):
        for name in DB_NAMES:
            require((root / name).is_file(), f"Отсутствует обязательная база данных: {name}")
        directories, sources = paths_in(root)
        if destination is None:
            destination = (
                root
                / "backups"
                / (
                    "minimal-"
                    + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    + "-"
                    + secrets.token_hex(6)
                )
            )
        dest = safe_absolute(destination)
        require(
            not dest.exists() and not dest.is_symlink(),
            "backup destination already exists",
        )
        require(
            dest.parent == root / "backups" or not dest.is_relative_to(root),
            "backup destination inside live root must be a direct child of backups/",
        )
        private_directory(dest.parent)
        stage = Path(tempfile.mkdtemp(prefix=".minimal-incomplete-", dir=dest.parent))
        os.chmod(stage, 0o700)
        try:
            payload = stage / "payload"
            payload.mkdir(mode=0o700)
            for relative in directories:
                if relative != ".":
                    (payload / relative).mkdir(mode=0o700)
            records = []
            for relative, source in sources:
                target = payload / relative
                with source.open("rb") as stream:
                    is_sqlite = stream.read(16) == b"SQLite format 3\x00"
                is_sqlite = is_sqlite or relative in DB_NAMES
                if is_sqlite:
                    copy_sqlite(source, target)
                else:
                    file_copy(source, target)
                records.append(
                    file_record(target, relative, "sqlite" if is_sqlite else "file")
                )
            # Резервная копия фиксирует одно офлайновое состояние, поскольку все блокировки приложения
            # удерживаются при ОБОИХ копированиях SQLite и всех blob-объектов.
            dump_json_atomic(
                stage / "manifest.json",
                {
                    "format": FORMAT,
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                    "sourceRoot": str(root),
                    "files": records,
                    "directories": directories,
                },
            )
            for d in sorted(directories, key=lambda p: p.count("/"), reverse=True):
                fsync_dir(payload if d == "." else payload / d)
            fsync_dir(stage)
            verify(stage)
            require(not dest.exists(), "Каталог назначения резервной копии появился в процессе создания")
            publish_new_directory(stage, dest)
            fsync_dir(dest.parent)
            return dest
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def restore(bundle, target_root):
    source = safe_absolute(bundle)
    manifest = verify(source)  # проверить ВСЁ до изменения целевой системы
    root = safe_absolute(target_root)
    require(
        not root.exists() and not root.is_symlink(),
        "Восстановление разрешено только в новый, ещё не существующий каталог",
    )
    private_directory(root.parent)
    require(
        not source.is_relative_to(root), "bundle must not be inside restore destination"
    )
    stage = Path(tempfile.mkdtemp(prefix=".launcher-restore-", dir=root.parent))
    os.chmod(stage, 0o700)
    try:
        for d in manifest["directories"]:
            if d != ".":
                (stage / d).mkdir(mode=0o700)
        (stage / "backups").mkdir(mode=0o700, exist_ok=True)
        for item in manifest["files"]:
            relative = item["path"]
            target = stage / relative
            file_copy(source / "payload" / relative, target)
            # Сохраняйте файлы закрытыми, даже если оригинал не был таким; не раскрывайте учётные данные.
            os.chmod(target, item["mode"] & 0o700)
            if item["kind"] == "sqlite":
                sqlite_integrity(target)
        envfile = stage / "config/backend.env"
        values = {}
        for line in envfile.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            require("=" in line, "Недопустимое восстановленное окружение")
            key, value = line.split("=", 1)
            values[key] = value
        previous = safe_absolute(manifest["sourceRoot"])
        for key, suffix in RELOCATED.items():
            require(
                values.get(key) == str(previous / suffix),
                f"Переменная окружения резервной копии не соответствует манифесту: {key}",
            )
        for key, suffix in RELOCATED.items():
            values[key] = str(root / suffix)
        for key, suffix in OPTIONAL_RELOCATED.items():
            if key in values:
                require(
                    values[key] == str(previous / suffix),
                    f"Переменная окружения резервной копии не соответствует манифесту: {key}",
                )
                values[key] = str(root / suffix)
        require(
            values.get("LAUNCHER_REPOSITORY_DRIVER") == "sqlite"
            and values.get("LAUNCHER_DEPLOYMENT_MODE") == "single-node",
            "not minimal configuration",
        )
        replacement = envfile.with_name(".backend.env.new")
        dump_env = "".join(f"{k}={v}\n" for k, v in sorted(values.items()))
        fd = os.open(
            replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(dump_env)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(replacement, envfile)
        fsync_dir(envfile.parent)
        for d in sorted(
            manifest["directories"] + ["backups"],
            key=lambda p: p.count("/"),
            reverse=True,
        ):
            fsync_dir(stage if d == "." else stage / d)
        # Атомарная публикация: частично восстановленная установка не видна.
        require(
            not root.exists() and not root.is_symlink(),
            "restore destination appeared during copy",
        )
        publish_new_directory(stage, root)
        fsync_dir(root.parent)
        read_install(root)
        return root
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup", help="Сначала остановить API; неизменяемый согласованный снимок")
    b.add_argument("--root", type=Path, required=True)
    b.add_argument("--destination", type=Path)
    v = sub.add_parser(
        "verify", help="Перед восстановлением проверить каждый байт и целостность SQLite"
    )
    v.add_argument("--bundle", type=Path, required=True)
    r = sub.add_parser(
        "restore", help="Восстанавливать только в новый отсутствующий корень установки"
    )
    r.add_argument("--bundle", type=Path, required=True)
    r.add_argument("--target-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            result = backup(args.root, args.destination)
            print(
                json.dumps(
                    {"status": "ok", "operation": "backup", "bundle": str(result)}
                )
            )
        elif args.command == "verify":
            info = verify(args.bundle)
            print(
                json.dumps(
                    {"status": "ok", "operation": "verify", "files": len(info["files"])}
                )
            )
        else:
            restored = restore(args.bundle, args.target_root)
            print(
                json.dumps(
                    {"status": "ok", "operation": "restore", "root": str(restored)}
                )
            )
        return 0
    except (
        BackupError,
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
        UnicodeError,
    ) as exc:
        print(f"Резервное копирование минимальной установки безопасно прервано: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
