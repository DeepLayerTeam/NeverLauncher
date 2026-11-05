#!/usr/bin/env python3
"""NeverLauncher 0.47.5: автономная возобновляемая миграция SQLite Core с блокировкой при неопределённости.

Она не переносит независимое состояние SQLite HTTP/Coordinator. Такая установка явно не допускается
к переключению Backend, пока преобразование не реализовано и не протестировано. Нельзя выводить
готовность PostgreSQL по промежуточной строке.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

STAGES = ("preflight", "backup", "freeze", "frozen_backup", "import", "copy_files", "verify", "cutover", "health_check")
MAX_OUTPUT = 256 * 1024


class CutoverError(RuntimeError):
    pass


def record(stage: str, status: str, **fields):
    return dict(at=datetime.now(timezone.utc).isoformat(), stage=stage, status=status, **fields)


def refuse_symlink(path: Path):
    if path.is_symlink():
        raise CutoverError(f"symlink not allowed: {path}")


def private_file(path: Path):
    refuse_symlink(path)
    try:
        st = path.stat()
    except FileNotFoundError as exc:
        raise CutoverError(f"Отсутствует обязательный приватный файл: {path}") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise CutoverError(f"Требуется: «private regular file (0600)»: {path}")
    return st


def fsync_dir(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_secure(path: Path, payload: bytes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    refuse_symlink(path)
    fd, temp = tempfile.mkstemp(prefix=".cutover-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def enough_space(path: Path, required_bytes: int, reason: str):
    """Отклонять до опасных действий, резервируя 20% + 64 МиБ для WAL/метаданных.

    Переполненная файловая система может прервать резервное копирование SQLite или копирование файла
    на полпути. Это *предварительная* проверка, а не замена проверки и fsync настоящего результата.
    Проверять файловую систему целевого пути.
    """
    if required_bytes < 0:
        raise CutoverError("Некорректное значение: «storage size estimate»")
    where = path
    while not where.exists():
        where = where.parent
    stats = os.statvfs(where)
    available = stats.f_bavail * stats.f_frsize
    reserve = max(64 * 1024 * 1024, (required_bytes + 4) // 5)
    if available < required_bytes + reserve:
        raise CutoverError(f"insufficient disk space for {reason}: need {required_bytes + reserve} bytes, have {available}")


def sqlite_size_on_disk(path: Path) -> int:
    private_file(path)
    total = path.stat().st_size
    for suffix in ("-wal", "-shm"):
        sibling = Path(str(path) + suffix)
        if sibling.exists():
            refuse_symlink(sibling)
            st = sibling.stat()
            if not stat.S_ISREG(st.st_mode):
                raise CutoverError("Небезопасное значение: «SQLite sidecar»")
            total += st.st_size
    return total


def storage_fingerprint(root: Path) -> tuple[str, int, int]:
    """Хешировать каждый локальный blob и его относительное имя; отклонять входные ссылки/устройства.

    Вызывается до и после копирования, в том числе при возобновлении. Одно сравнение количества
    файлов не выявляет изменений источника того же размера и количества.
    """
    refuse_symlink(root)
    if not root.is_dir():
        raise CutoverError("source local storage root must exist")
    digest = hashlib.sha256()
    count = total = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs):
            part = Path(folder) / name
            mode = part.lstat().st_mode
            if not stat.S_ISDIR(mode):
                raise CutoverError("non-directory or symlink inside source storage")
        dirs.sort()
        for name in sorted(files):
            part = Path(folder) / name
            before = part.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CutoverError("Небезопасное значение: «source storage blob (link or special file)»")
            relative = part.relative_to(root).as_posix().encode("utf-8")
            fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (before.st_ino, before.st_dev) != (opened.st_ino, opened.st_dev):
                    raise CutoverError("source storage path replaced before reading")
                content_sha = hashlib.sha256()
                for buf in iter(lambda: stream.read(1024 * 1024), b""):
                    content_sha.update(buf)
                after_open = os.fstat(stream.fileno())
            after = part.lstat()
            if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns) or (opened.st_size, opened.st_mtime_ns) != (after_open.st_size, after_open.st_mtime_ns):
                raise CutoverError("source file changed during fingerprint")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(before.st_size.to_bytes(8, "big"))
            digest.update(content_sha.digest())
            total += before.st_size
            count += 1
    return digest.hexdigest(), count, total


def check_stage_chain(state: dict):
    """После сбоя можно повторно воспроизвести только префикс устойчивых квитанций этапов."""
    completed = state.get("completed")
    if not isinstance(completed, list) or completed != list(STAGES[:len(completed)]):
        raise CutoverError("corrupt or out-of-order migration stage journal")
    receipts = state.get("receipts", {})
    if not isinstance(receipts, dict):
        raise CutoverError("corrupt migration receipts")
    if any(stage not in completed for stage in receipts):
        raise CutoverError("receipt for uncommitted migration stage")
    if state.get("importOutcomeUnknown") and "import" in completed:
        raise CutoverError("contradictory import completion receipt")
    if state.get("writeBoundaryCrossed") and "verify" not in completed:
        raise CutoverError("Небезопасное значение: «write-boundary journal without verification; automatic rollback forbidden»")
    if "cutover" in completed and not state.get("writeBoundaryCrossed"):
        raise CutoverError("Запрещено: «cutover recorded without write boundary; automatic rollback»")


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for buf in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def run_cmd(args, *, env=None):
    try:
        p = subprocess.run(args, env=env, capture_output=True, timeout=3600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CutoverError(f"Ошибка: «subprocess»: {args[0]}: {type(exc).__name__}") from exc
    if p.returncode:
        # stderr может содержать аргументы команд, пути и секреты. Нельзя выводить его без фильтрации.
        raise CutoverError(f"{Path(args[0]).name} {args[1] if len(args)>1 else ''} failed (exit {p.returncode}); see private operator service logs")
    if len(p.stdout) > MAX_OUTPUT:
        raise CutoverError("unreasonable CLI response size")
    try:
        return json.loads(p.stdout)
    except (ValueError, UnicodeError) as exc:
        raise CutoverError(f"Некорректное значение: «JSON response from» {args[0]}") from exc


def parse_env(path: Path):
    """Небольшое строго ограниченное подмножество systemd EnvironmentFile, без подстановок оболочки."""
    private_file(path)
    items = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=.*", line):
            raise CutoverError("Не поддерживается: «env syntax; refusing to rewrite service configuration»")
        if line.startswith("export "):
            raise CutoverError("«systemd EnvironmentFile»: запрещено «contain export»")
        key, value = line.split("=", 1)
        if key in items:
            raise CutoverError(f"Обнаружен дубликат: «environment key» {key}")
        if "\x00" in value or "\r" in value:
            raise CutoverError("Небезопасное значение: «environment value»")
        items[key] = value
    return items


def change_env(path: Path, target_dsn: str, driver: str, storage_path: str):
    """Сохранять комментарии и не связанные с задачей настройки; не выполнять оболочку."""
    private_file(path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changes = {
        "LAUNCHER_DATABASE_DSN": target_dsn,
        "LAUNCHER_REPOSITORY_DRIVER": driver,
        "LAUNCHER_SQL_DRIVER": "pgx",
        "LAUNCHER_DATABASE_AUTO_MIGRATE": "false",
        "LAUNCHER_STORAGE_DRIVER": "local",
        "LAUNCHER_STORAGE_LOCAL_PATH": storage_path,
    }
    if any(c in target_dsn + storage_path for c in ("\n", "\r", "\x00", "\"")):
        raise CutoverError("Небезопасное значение: «configuration characters»")
    seen = set()
    new = []
    for line in lines:
        if line.lstrip().startswith("#") or "=" not in line:
            new.append(line)
            continue
        name, _ = line.split("=", 1)
        if name in changes:
            if name in seen:
                raise CutoverError("Обнаружен дубликат: «environment key»")
            new.append(f"{name}={changes[name]}\n")
            seen.add(name)
        else:
            new.append(line)
    for name, value in changes.items():
        if name not in seen:
            new.append(f"{name}={value}\n")
    write_secure(path, "".join(new).encode("utf-8"))


def validate_sqlite_backup(path: Path):
    if not path.is_file():
        raise CutoverError("Отсутствует: резервная копия SQLite")
    private_file(path)
    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db:
        check = db.execute("PRAGMA integrity_check").fetchall()
        if check != [("ok",)]:
            raise CutoverError("Ошибка: «SQLite backup integrity_check»")
        fk = db.execute("PRAGMA foreign_key_check").fetchone()
        if fk:
            raise CutoverError("SQLite backup foreign-key violation")


def verify_http_snapshot(path: Path):
    """Проверять зафиксированный снимок HTTP, а не только целостность страниц SQLite."""
    private_file(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        exists = db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='http_repository_state_0372'").fetchone()[0]
        if exists != 1:
            raise CutoverError("Отсутствует: «HTTP Repository snapshot table»")
        rows = db.execute("SELECT singleton,state_version,sequence,sha256,document FROM http_repository_state_0372").fetchall()
        if len(rows) != 1:
            raise CutoverError("Некорректное значение: «HTTP Repository snapshot singleton»")
        singleton, version, sequence, digest, document = rows[0]
        if singleton != 1 or version != 1 or sequence < 1 or not isinstance(document, bytes):
            raise CutoverError("Некорректное значение: «HTTP Repository snapshot metadata»")
        if hashlib.sha256(document).hexdigest() != digest:
            raise CutoverError("Несовпадение: «HTTP Repository snapshot SHA-256»")
        def reject_duplicate(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise CutoverError("Обнаружен дубликат: «HTTP snapshot JSON key»")
                out[key] = value
            return out
        try:
            data = json.loads(document, object_pairs_hook=reject_duplicate)
        except (UnicodeError, ValueError) as exc:
            raise CutoverError("corrupt HTTP Repository JSON") from exc
        if not isinstance(data, dict) or not data:
            raise CutoverError("Некорректное значение: «HTTP Repository JSON state»")


def sqlite_backup(source_name: str, dest: Path):
    source = Path(source_name)
    private_file(source)
    if dest.exists():
        raise CutoverError("refusing to overwrite independent SQLite backup")
    uri = source.resolve().as_uri() + "?mode=ro"
    # Онлайн-API резервного копирования SQLite создаёт единый транзакционно согласованный снимок БД, включая
    # зафиксированные страницы WAL. Не копируйте только файл .db.
    with closing(sqlite3.connect(uri, uri=True, timeout=20)) as src:
        if src.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise CutoverError("Ошибка: «source SQLite integrity check»")
        fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(dest))) as target:
                src.backup(target)
            validate_sqlite_backup(dest)
            with dest.open("rb") as stream:
                os.fsync(stream.fileno())
            fsync_dir(dest.parent)
        except Exception:
            dest.unlink(missing_ok=True)
            raise


class Operator:
    def __init__(self, args):
        self.a = args
        # Не разрешайте символическую ссылку до того, как её проверит refuse_symlink.
        self.work = Path(os.path.abspath(args.work_dir))
        self.state_path = self.work / "state.json"
        self.journal_path = self.work / "stages.jsonl"
        self.backup = self.work / "core-frozen.db"
        self.early_backup = self.work / "core-preflight.db"
        self.original_env = self.work / "backend-before.env"
        self.http_backup = self.work / "http-frozen.db"
        self.coordinator_backup = self.work / "coordinator-frozen.db"
        self.env = os.environ.copy()
        self.env[args.dsn_env] = os.environ.get(args.dsn_env, "")
        self.state = {"format": "neverlauncher-cutover-0475-v1", "completed": [], "blocked": False, "writeBoundaryCrossed": False}

    def init_workdir(self):
        refuse_symlink(self.work)
        if not self.work.exists():
            self.work.mkdir(mode=0o700, parents=True)
        if self.work.stat().st_mode & 0o077:
            raise CutoverError("work directory: требуется приватные права 0700")
        if self.state_path.exists():
            private_file(self.state_path)
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise CutoverError("Некорректное значение: «persisted cutover journal»")
            if data.get("format") != self.state["format"]:
                raise CutoverError("Неизвестный формат журнала")
            check_stage_chain(data)
            self.state = data
        else:
            write_secure(self.state_path, json.dumps(self.state, sort_keys=True).encode())

    def log(self, stage, status, **fields):
        # Никогда не записывайте в журнал DSN, содержимое env-файлов, ключи шифрования и учётные данные.
        value = json.dumps(record(stage, status, **fields), separators=(",", ":")) + "\n"
        with self.journal_path.open("ab") as stream:
            os.chmod(self.journal_path, 0o600)
            stream.write(value.encode())
            stream.flush()
            os.fsync(stream.fileno())

    def save(self):
        write_secure(self.state_path, json.dumps(self.state, indent=2, sort_keys=True).encode())

    def stage(self, name, fn):
        check_stage_chain(self.state)
        if name in self.state["completed"]:
            return
        if name != STAGES[len(self.state["completed"])]:
            raise CutoverError("migration stages must run in order")
        self.log(name, "started")
        try:
            result = fn() or {}
        except Exception as exc:
            self.state["blocked"] = True
            self.state["failedStage"] = name
            self.save()
            self.log(name, "failed", reason=type(exc).__name__)
            raise
        self.state["completed"].append(name)
        if name == "import":
            # Снимайте неопределённость лишь после надёжной записи завершённого этапа в журнал. При уничтожении
            # процесса сразу после COMMIT в PostgreSQL нельзя безопасно повторять операцию без проверки существующей
            # квитанции.
            self.state["importOutcomeUnknown"] = False
        self.state["blocked"] = False
        self.state.pop("failedStage", None)
        if result:
            self.state.setdefault("receipts", {})[name] = result
        self.save()
        self.log(name, "completed")

    def service(self, cmd, unit):
        # Имена служб не передаются через оболочку; удалённое управление systemd не поддерживается.
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", unit):
            raise CutoverError("Некорректное значение: модуль службы systemd")
        p = subprocess.run(["systemctl", cmd, unit], capture_output=True, timeout=90, check=False)
        return p.returncode, p.stdout.strip()

    def inactive(self):
        for unit in self.a.units:
            code, state = self.service("is-active", unit)
            if code == 0 or state not in (b"inactive", b"failed"):
                raise CutoverError(f"writer unit not reliably stopped: {unit}")

    def preflight(self):
        if not self.a.units or len(set(self.a.units)) != len(self.a.units):
            raise CutoverError("Требуется: «at least one explicit systemd service and no duplicate units»")
        if not self.env[self.a.dsn_env]:
            raise CutoverError("target PostgreSQL DSN: требуется «supplied via an environment variable»")
        private_file(Path(self.a.source_env))
        cfg = parse_env(Path(self.a.source_env))
        if cfg.get("LAUNCHER_REPOSITORY_DRIVER", "").lower() != "sqlite":
            raise CutoverError("source backend must use SQLite; never alter an existing PostgreSQL deployment")
        if cfg.get("LAUNCHER_DATABASE_DSN", "") != self.a.http_db:
            raise CutoverError("--http-db must exactly match current SQLite Backend DSN")
        for source in (self.a.core_db, self.a.http_db):
            private_file(Path(source))
        # Независимая предварительная проверка и замороженные копии Core, одной HTTP-БД и при необходимости
        # Coordinator; учитывайте WAL и запас свободного места.
        required = 2 * sqlite_size_on_disk(Path(self.a.core_db)) + sqlite_size_on_disk(Path(self.a.http_db))
        if self.a.coordinator_db:
            required += sqlite_size_on_disk(Path(self.a.coordinator_db))
        enough_space(self.work, required, "SQLite backups")
        if self.a.coordinator_db:
            private_file(Path(self.a.coordinator_db))
        if cfg.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", "") and cfg["LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"] != self.a.coordinator_db:
            raise CutoverError("Coordinator path: требуется «explicitly supplied and match the source configuration»")
        sources = [self.a.core_db, self.a.http_db]
        if self.a.coordinator_db:
            sources.append(self.a.coordinator_db)
        if len({Path(v).resolve() for v in sources}) != len(sources):
            raise CutoverError("SQLite Core, HTTP and Coordinator: требуется «separate databases»")
        # ЭТО НЕПРЕОДОЛИМАЯ НЕСОВМЕСТИМОСТЬ в 0.47.4. Обход запрещён даже при пустом HTTP-снимке: закрытые данные
        # авторизации, координатора, подписи, установки и Runtime не имеют канонического сопоставления в
        # PostgreSQL.
        self.state["cutoverSupported"] = False
        self.save()
        return {"corePresent": True, "httpMigrationSupported": False}

    def do_backup(self):
        private_file(Path(self.a.source_env))
        if self.original_env.exists():
            private_file(self.original_env)
            if sha256_file(self.original_env) != sha256_file(Path(self.a.source_env)):
                raise CutoverError("previous original environment backup differs")
        else:
            write_secure(self.original_env, Path(self.a.source_env).read_bytes())
        self.state["sourceEnvSHA256"] = sha256_file(Path(self.a.source_env))
        self.save()
        result = run_cmd([self.a.launcher_sqlite, "pre-upgrade", "--db", self.a.core_db, "--backup", str(self.early_backup)], env=self.env)
        if not result.get("verifiedRestore"):
            raise CutoverError("preflight backup restore was not independently verified")
        return {"backupSha256": result["manifest"]["sha256"]}

    def freeze(self):
        for unit in self.a.units:
            code, _ = self.service("stop", unit)
            if code:
                raise CutoverError(f"Не удалось остановить «writer service» {unit}")
        self.inactive()
        return {"stoppedServices": len(self.a.units)}

    def frozen_backup(self):
        self.inactive()
        if self.backup.exists() or self.http_backup.exists() or self.coordinator_backup.exists():
            # Прерванное физическое резервное копирование нельзя считать завершённым и использовать повторно.
            # Сохраните доказательства и разрешите проблему вручную вместо перезаписи.
            raise CutoverError("incomplete frozen backup files exist; inspect before retry")
        if sha256_file(Path(self.a.source_env)) != self.state.get("sourceEnvSHA256"):
            raise CutoverError("service configuration changed since preflight")
        # HTTP и Coordinator не удаляются незаметно. Сохраните и проверьте полное состояние SQLite, даже если для
        # него нет переноса в действующую PostgreSQL.
        sqlite_backup(self.a.http_db, self.http_backup)
        verify_http_snapshot(self.http_backup)
        if self.a.coordinator_db:
            sqlite_backup(self.a.coordinator_db, self.coordinator_backup)
        result = run_cmd([self.a.launcher_sqlite, "pre-upgrade", "--db", self.a.core_db, "--backup", str(self.backup)], env=self.env)
        if not result.get("verifiedRestore"):
            raise CutoverError("frozen backup failed independent restore")
        self.state["sourceSHA256"] = result["manifest"]["sha256"]
        self.save()
        return {"backupSha256": self.state["sourceSHA256"], "httpBackupSHA256": sha256_file(self.http_backup), "coordinatorBackupSHA256": sha256_file(self.coordinator_backup) if self.a.coordinator_db else None}

    def importing(self):
        self.inactive()
        if sha256_file(Path(self.a.source_env)) != self.state.get("sourceEnvSHA256"):
            raise CutoverError("source configuration changed while frozen")
        # ВАЖНО: если процесс завершился после COMMIT, но до записи этапа в журнал, результат фиксации неизвестен.
        # Нельзя слепо повторять операцию.
        self.state["importOutcomeUnknown"] = True
        self.save()
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-live", "--backup", str(self.backup), "--ack-live-import", "--timeout", "45m", *self.mfa_args()], env=self.env)
        if not report.get("verified") or report.get("sourceSha256") != self.state["sourceSHA256"]:
            raise CutoverError("Некорректное значение: «live import receipt»")
        return {"sourceSHA256": self.state["sourceSHA256"], "verified": True}

    def mfa_args(self):
        if self.a.mfa_key_file and self.a.pg_secret_env:
            return ["--sqlite-mfa-key-file", self.a.mfa_key_file, "--postgres-secret-env", self.a.pg_secret_env]
        if self.a.mfa_key_file or self.a.pg_secret_env:
            raise CutoverError("Требуется: «both MFA keys are»")
        return []

    def files(self):
        self.inactive()
        if not self.a.storage_source or not self.a.storage_target:
            raise CutoverError("Требуется: «distinct local source/target storage roots»")
        src = Path(self.a.storage_source)
        dst = Path(self.a.storage_target)
        if not src.is_absolute() or not dst.is_absolute():
            raise CutoverError("source and target storage roots: требуется «absolute»")
        src_path, dst_path = src.resolve(), dst.resolve()
        if (src_path == dst_path or src_path.is_relative_to(dst_path)
                or dst_path.is_relative_to(src_path)):
            raise CutoverError("source and PostgreSQL storage: требуется «disjoint trees»")
        if self.work.is_relative_to(src_path) or self.work.is_relative_to(dst_path):
            raise CutoverError("«private migration journal»: запрещено «be inside storage»")
        refuse_symlink(dst)
        before, count, size = storage_fingerprint(src)
        enough_space(dst, size, "verified local blob copy")
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-files", "--source-root", self.a.storage_source, "--target-root", self.a.storage_target, "--ack-offline"], env=self.env)
        if not report.get("verified") or report.get("sourceSha256") != self.state["sourceSHA256"]:
            raise CutoverError("Некорректное значение: «file-copy receipt»")
        after, after_count, after_size = storage_fingerprint(src)
        if (after, after_count, after_size) != (before, count, size):
            raise CutoverError("source blobs changed during PostgreSQL copy")
        if int(report.get("checked", -1)) < 0 or not report.get("catalogSha256"):
            raise CutoverError("file-copy result missing verified catalog digest")
        return {"verified": True, "objects": report["checked"], "sourceStorageSHA256": after, "sourceStorageObjects": count, "catalogSha256": report["catalogSha256"]}

    def verify(self):
        self.inactive()
        if self.state.get("importOutcomeUnknown"):
            raise CutoverError("ambiguous import commit: inspect PostgreSQL and reconcile before any retry")
        manifest = run_cmd([self.a.launcher_sqlite, "backup-verify", "--backup", str(self.backup)], env=self.env)
        if manifest.get("manifest", {}).get("sha256") != self.state.get("sourceSHA256"):
            raise CutoverError("Обнаружено изменение: «frozen SQLite backup»")
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-cutover-check", "--source-sha256", self.state["sourceSHA256"], "--project", self.a.project, "--owner-email", self.a.owner_email], env=self.env)
        if not all(report.get(k) for k in ("liveVerified", "filesVerified", "repositoryVerified")):
            raise CutoverError("PostgreSQL Repository verification incomplete")
        return {"verified": True, "readyForBackendCutover": report.get("readyForBackendCutover", False), "ownerId": report["ownerId"]}

    def cutover(self):
        self.inactive()
        verdict = self.state.get("receipts", {}).get("verify", {})
        if not verdict.get("readyForBackendCutover") or not self.state.get("cutoverSupported"):
            raise CutoverError("Небезопасное значение: «cutover blocked: HTTP/Coordinator state not migrated; Core receipt is not approval»")
        # Барьер восстановления ОБЯЗАТЕЛЬНО должен попасть в долговременное хранилище до перезаписи env. Иначе
        # сбой между заменой конфигурации и фиксацией флага позволит небезопасный откат на SQLite после возможного
        # начала записей в PostgreSQL.
        self.state["writeBoundaryCrossed"] = True
        self.save()
        self.log("cutover", "write_boundary_armed")
        change_env(Path(self.a.source_env), self.env[self.a.dsn_env], "postgres", self.a.storage_target)
        for unit in self.a.units:
            code, _ = self.service("start", unit)
            if code:
                raise CutoverError("PostgreSQL writer failed to start: check write outcome before rollback")
        return {"backendStarted": True}

    def health_check(self):
        """Аутентифицировать существующего владельца и прочитать его проект через настоящий переключённый
Backend до объявления завершения миграции оператором.

        Это дополнительная *онлайновая* проверка, а не разрешение обойти прежний шлюз паритета
        доменов. При ошибке новые записи PG уже могут существовать: вызывающие стороны останавливают
        службы записи, но никогда не откатываются автоматически к SQLite.
        """
        import urllib.request
        from urllib.parse import quote, urlsplit

        require_credentials = getattr(self.a, "owner_credentials", "")
        if not require_credentials:
            raise CutoverError("private old owner credentials file required for real Backend verification")
        secret_file = Path(require_credentials)
        private_file(secret_file)
        try:
            auth = json.loads(secret_file.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise CutoverError("Некорректное значение: «old owner credential JSON»") from exc
        if (not isinstance(auth, dict) or auth.get("email", "").casefold() != self.a.owner_email.casefold()
                or not isinstance(auth.get("password"), str) or not auth["password"]):
            raise CutoverError("«old owner credential» не совпадает с «migration owner»")
        values = {"email": auth["email"], "password": auth["password"]}
        for optional in ("totp", "recoveryCode", "providerId"):
            if optional in auth:
                values[optional] = auth[optional]
        cfg = parse_env(Path(self.a.source_env))
        if (cfg.get("LAUNCHER_REPOSITORY_DRIVER") != "postgres" or
                cfg.get("LAUNCHER_DATABASE_DSN") != self.env[self.a.dsn_env]):
            raise CutoverError("running service environment is not the verified PostgreSQL target")
        parts = urlsplit(self.a.health_url)
        if (parts.scheme not in ("https", "http") or
                (parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "::1", "localhost")) or
                parts.username or parts.password or parts.query or parts.fragment or parts.path != "/ready"):
            raise CutoverError("Требуется: «a local /ready or HTTPS /ready URL without credentials»")
        base = self.a.health_url.rsplit("/ready", 1)[0]
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        client = urllib.request.build_opener(NoRedirect)
        def request(path, *, payload=None, token=""):
            body = None if payload is None else json.dumps(payload).encode("utf-8")
            headers = {"Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            if token:
                headers["Authorization"] = "Bearer " + token
            query = urllib.request.Request(base + path, body, headers=headers,
                                           method="POST" if body is not None else "GET")
            try:
                with client.open(query, timeout=10) as response:
                    if response.status != 200:
                        raise CutoverError("post-cutover Backend HTTP operation was not successful")
                    data = response.read(4 * 1024 * 1024 + 1)
                    if len(data) > 4 * 1024 * 1024:
                        raise CutoverError("post-cutover API payload exceeded verification limit")
                    return json.loads(data)
            except (OSError, ValueError) as exc:
                raise CutoverError("Ошибка: «live PostgreSQL Backend login or project operation»") from exc
        health = request("/ready")
        if not isinstance(health, dict) or health.get("status") != "ok":
            raise CutoverError("Backend health JSON is not ready")
        login = request("/api/v1/admin/login", payload=values)
        if not isinstance(login, dict) or not isinstance(login.get("token"), str) or len(login["token"]) <= 20:
            raise CutoverError("original owner did not obtain a real administrative session")
        user = login.get("user") or {}
        if not isinstance(user, dict) or user.get("email", "").casefold() != self.a.owner_email.casefold():
            raise CutoverError("authenticated owner differs from the imported owner")
        expected = (self.state.get("receipts", {}).get("verify", {}) or {}).get("ownerId")
        if not expected or user.get("id") != expected:
            raise CutoverError("authenticated owner ID differs from migrated PostgreSQL identity")
        project_path = "/api/v1/projects/" + quote(self.a.project, safe="")
        project = request(project_path, token=login["token"])
        if not isinstance(project, dict) or project.get("id") != self.a.project:
            raise CutoverError("«imported project»: запрещено «be read through Backend API»")
        # Защищённый экспорт Admin требует реального разрешения проекта и подтверждает сопоставление сеанса и
        # роли, а не только доступность общедоступного GET.
        request("/api/v1/admin/projects/" + quote(self.a.project, safe="") + "/export", token=login["token"])
        return {"backendHealthy": True, "ownerAuthenticated": True,
                "ownerId": user["id"], "projectReadAndAuthorized": True}

    def run(self):
        self.init_workdir()
        lock_path = self.work / "operator.lock"
        try:
            with lock_path.open("a+b") as lock:
                os.chmod(lock_path, 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise CutoverError("operator is already running") from exc
                check_stage_chain(self.state)
                if self.state.get("rolledBack"):
                    raise CutoverError("previous operation rolled back; use a fresh work directory")
                if self.state.get("importOutcomeUnknown"):
                    raise CutoverError("previous import outcome unknown: manually reconcile PostgreSQL before continuing")
                pipeline = [self.preflight, self.do_backup, self.freeze, self.frozen_backup, self.importing, self.files, self.verify, self.cutover, self.health_check]
                for stage, function in zip(STAGES, pipeline):
                    self.stage(stage, function)
                return self.state
        except Exception:
            # Если хоть один процесс записи PostgreSQL мог запуститься, ОСТАНОВИТЕ все объявленные службы, но не
            # утверждайте, что остановка делает откат на устаревшую БД безопасным.
            if self.state.get("writeBoundaryCrossed"):
                for unit in self.a.units:
                    try:
                        self.service("stop", unit)
                    except Exception:
                        pass
                self.log("post_cutover_fault", "writes_unknown_rollback_blocked")
            # Перед перезапуском SQLite блокировка выше уже освобождена. PostgreSQL остаётся изолированной до
            # пересечения границы записи.
            if ("backup" in self.state.get("completed", []) and
                    not self.state.get("writeBoundaryCrossed") and
                    not self.state.get("rolledBack")):
                try:
                    self.rollback()
                except Exception as rollback_error:
                    self.log("automatic_rollback", "failed", reason=type(rollback_error).__name__)
            raise

    def rollback(self):
        self.init_workdir()
        with (self.work / "operator.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.state.get("writeBoundaryCrossed"):
                raise CutoverError("Запрещено: «writes may have reached PostgreSQL; automatic rollback»")
            if self.state.get("importOutcomeUnknown"):
                # Импорт SQLRepository мог быть зафиксирован, но до переключения источником истины остаётся старая БД. При
                # восстановлении SQLite не удаляйте данные PostgreSQL и не повторяйте импорт.
                self.log("rollback", "isolated_postgres_commit_unknown")
            # После внезапного завершения между systemctl stop и квитанцией этапа безопасное восстановление возможно
            # лишь при неактивности всех служб.
            if "backup" not in self.state["completed"]:
                raise CutoverError("Отсутствует: «verified preflight backup to restore»")
            self.inactive()
            private_file(self.original_env)
            # Исходные БД ещё не изменялись. Проверьте независимую замороженную копию до восстановления прежней
            # конфигурации служб.
            if "frozen_backup" in self.state["completed"]:
                # Квитанция завершённой копии всегда должна проходить независимую проверку. При прерывании этапа
                # незавершённые файлы — доказательства для расследования, а НЕ источник восстановления.
                validate_sqlite_backup(self.http_backup)
                if self.a.coordinator_db:
                    validate_sqlite_backup(self.coordinator_backup)
                result = run_cmd([self.a.launcher_sqlite, "backup-verify", "--backup", str(self.backup)], env=self.env)
                if result.get("manifest", {}).get("sha256") != self.state.get("sourceSHA256"):
                    raise CutoverError("source backup damaged; rollback blocked")
            elif any(path.exists() for path in (self.backup, self.http_backup, self.coordinator_backup)):
                self.log("rollback", "partial_frozen_backups_ignored_source_only")
            # Проверьте, что все исходные БД по-прежнему читаются; не перезаписывайте исходную БД только потому, что
            # существует отдельная копия.
            for source in [self.a.core_db, self.a.http_db, *([self.a.coordinator_db] if self.a.coordinator_db else [])]:
                private_file(Path(source))
                validate_sqlite_backup(Path(source))
            write_secure(Path(self.a.source_env), self.original_env.read_bytes())
            for unit in self.a.units:
                code, _ = self.service("start", unit)
                if code:
                    for stopped in self.a.units:
                        try:
                            self.service("stop", stopped)
                        except Exception:
                            pass
                    raise CutoverError("SQLite service restart failed; services stopped for investigation")
            self.state["rolledBack"] = True
            self.save()
            self.log("rollback", "completed")
            return {"restoredOriginalEnvironment": True, "sourceDatabaseUntouched": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "status", "rollback"))
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--launcher-sqlite", default="launcher-sqlite")
    parser.add_argument("--source-env", default="")
    parser.add_argument("--core-db", default="")
    parser.add_argument("--http-db", default="")
    parser.add_argument("--coordinator-db", default="")
    parser.add_argument("--storage-source", default="")
    parser.add_argument("--storage-target", default="")
    parser.add_argument("--writer-unit", dest="units", action="append", default=[])
    parser.add_argument("--project", default="")
    parser.add_argument("--owner-email", default="")
    parser.add_argument("--owner-credentials", default="")
    parser.add_argument("--dsn-env", default="LAUNCHER_POSTGRES_DSN")
    parser.add_argument("--mfa-key-file", default="")
    parser.add_argument("--pg-secret-env", default="")
    parser.add_argument("--health-url", default="http://127.0.0.1:8080/ready")
    args = parser.parse_args(argv)
    try:
        operator = Operator(args)
        if args.action == "status":
            operator.init_workdir()
            print(json.dumps(operator.state, sort_keys=True))
            return 0
        required = ("source_env", "core_db", "http_db", "storage_source", "storage_target", "project", "owner_email")
        if any(not getattr(args, field) for field in required):
            raise CutoverError("required source paths, local storage, project and owner-email")
        if args.action == "rollback":
            result = operator.rollback()
        else:
            result = operator.run()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CutoverError, OSError, ValueError, KeyError) as exc:
        print(f"cutover rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
