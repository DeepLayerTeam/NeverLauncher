#!/usr/bin/env python3
"""Launcher 0.32.13 DEP09: промышленное развёртывание (Linux).

Standard Compose = PostgreSQL и координатор SQLite; Redis необязателен.
Native = подписанный пакет установщика, выпуск под владельцем root и systemd.
Нет производственного Backend только с SQLite и автоматического живого переключения SQLite->PostgreSQL.
"""

import argparse
import contextlib
import email.utils
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "production" / "docker-compose.yml"
HA = ROOT / "deploy" / "production" / "docker-compose.network-ha.yml"
UNIT_NAME = "launcher.service"
UNIT = Path("/etc/systemd/system") / UNIT_NAME
INSTALL_ROOT = Path("/opt/launcher")
STATE_ROOT = Path("/var/lib/launcher")
ENV_NATIVE = Path("/etc/launcher/backend.env")
OWNER = ".launcher-dep09-managed"
DATA_MARKER = ".launcher-dep09-data"
MARKER_VALUE = "launcher-0.32.13-deployment-v1\n"
UNIT_MARKER = "# Managed by Launcher DEP09 production-deploy.py"
VERSION_RE = re.compile(r"^verified Launcher ([a-zA-Z0-9][a-zA-Z0-9._-]{0,63})$", re.M)
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def fail(message):
    raise RuntimeError(message)


def execute(argv, *, capture=False, check=True):
    result = subprocess.run(
        [str(p) for p in argv],
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode:
        fail(
            f"Ошибка {argv[0]} {argv[1] if len(argv) > 1 else ''} (код выхода {result.returncode})"
        )
    return result


def safe_file(path, *, private=False, executable=False):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"Объект не является обычным файлом: {path}")
    if info.st_mode & (0o077 if private else 0o022):
        fail(f"Небезопасные права доступа: {path}")
    if executable and not info.st_mode & 0o111:
        fail(f"Файл не является исполняемым: {path}")
    return info


def safe_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        fail(f"Небезопасные права доступа к каталогу: {path}")


def write_exclusive(path, data, mode=0o600):
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    sync_directory(Path(path).parent)


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_text(path, content, perm=0o644):
    temp = Path(str(path) + ".new." + str(os.getpid()))
    write_exclusive(temp, content, perm)
    try:
        os.replace(temp, path)
        sync_directory(Path(path).parent)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def read_env(path):
    safe_file(path, private=True)
    if path.stat().st_size > 256 * 1024:
        fail("Файл переменных окружения слишком велик")
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail("Некорректная строка файла переменных окружения")
        key, value = line.split("=", 1)
        if not ENV_KEY_RE.fullmatch(key) or key in values or "\x00" in value:
            fail("invalid or duplicate env key")
        values[key] = value.strip().strip('"').strip("'")
    return values


def preflight(values, mode, *, docker, tls_required=True):
    needed = [
        "LAUNCHER_PUBLIC_URL",
        "LAUNCHER_AUTH_TOKEN_SECRET",
        "LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY",
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_WEBAUTHN_RP_ID",
        "LAUNCHER_WEBAUTHN_ORIGINS",
        "LAUNCHER_CORS_ALLOWED_ORIGINS",
    ]
    if docker:
        needed += ["POSTGRES_PASSWORD", "LAUNCHER_IMAGE_TAG"]
        if tls_required:
            needed += ["LAUNCHER_TLS_CERT_PATH", "LAUNCHER_TLS_KEY_PATH"]
        if mode == "network-ha":
            needed += [
                "REDIS_PASSWORD",
                "LAUNCHER_REPLICA_ID",
                "LAUNCHER_STORAGE_S3_ENDPOINT",
                "LAUNCHER_STORAGE_S3_BUCKET",
                "LAUNCHER_STORAGE_S3_REGION",
                "LAUNCHER_STORAGE_S3_ACCESS_KEY",
                "LAUNCHER_STORAGE_S3_SECRET_KEY",
            ]
    else:
        needed.append("LAUNCHER_DATABASE_DSN")
    missing = [
        key
        for key in needed
        if not values.get(key)
        or values[key].upper().startswith(("CHANGE_ME", "REPLACE_ME"))
    ]
    if missing:
        fail("Промышленная конфигурация отсутствует или содержит шаблонные значения: " + ", ".join(missing))
    public = values["LAUNCHER_PUBLIC_URL"]
    url = urllib.parse.urlsplit(public)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path not in ("", "/")
        or url.query
        or url.fragment
        or any(c.isspace() for c in public)
    ):
        fail("Промышленное значение PUBLIC_URL должно быть базовым HTTPS-адресом")
    if docker and url.port not in (None, 443):
        fail("Для прямого промышленного развёртывания Compose требуется публичный HTTPS на порту 443")
    if values["LAUNCHER_WEBAUTHN_ORIGINS"] != public or public not in values[
        "LAUNCHER_CORS_ALLOWED_ORIGINS"
    ].split(","):
        fail("Разрешённые источники WebAuthn и CORS должны точно содержать публичный базовый HTTPS-адрес")
    rp = values["LAUNCHER_WEBAUTHN_RP_ID"].lower()
    hostname = url.hostname.lower()
    if not (hostname == rp or hostname.endswith("." + rp)):
        fail("Идентификатор доверяющей стороны WebAuthn не соответствует публичному имени хоста")
    for key in (
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
    ):
        try:
            policy = json.loads(values[key])
        except ValueError:
            fail(f"{key} должен содержать непустую политику JSON")
        if not isinstance(policy, (list, dict)) or not policy:
            fail(f"{key} должен содержать непустую политику JSON")
    if len(values["LAUNCHER_AUTH_TOKEN_SECRET"]) < 32:
        fail("Секрет подписи аутентификации слишком короткий")
    if not re.fullmatch(
        r"[0-9a-fA-F]{64}", values["LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY"]
    ):
        fail("Ключ подписи манифеста должен содержать 32-байтное зерно Ed25519 в формате hex")
    if docker:
        compose_project(values)
        for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
            if key == "REDIS_PASSWORD" and mode != "network-ha":
                continue
            if not re.fullmatch(r"[A-Za-z0-9._~-]{24,}", values[key]):
                fail(f"{key} must be URL-safe and at least 24 characters")
    if not docker and values.get("LAUNCHER_REPOSITORY_DRIVER") != "postgres":
        fail(
            "Нативный Backend должен использовать PostgreSQL; HTTP-хранилище только на SQLite не поддерживается"
        )
    if not docker and not values.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"):
        fail("Для нативного режима Standard требуется постоянный координатор SQLite")
    if (
        mode == "standard"
        and values.get("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "").lower() == "true"
    ):
        fail("В режиме Standard нельзя требовать высокую доступность HA")
    if values.get("LAUNCHER_DEPLOYMENT_MODE", mode) not in ("", mode):
        fail("Режим развёртывания в окружении противоречит выбранному режиму")
    if mode == "network-ha" and not docker:
        fail("Этот установщик локальной службы не поддерживает настройку нативного HA")




def host_preflight(*, fresh):
    """Проверять настоящий Linux-хост и демон Docker до любых манипуляций с данными."""
    if sys.platform != "linux" or os.uname().machine.lower() not in (
        "x86_64", "amd64", "aarch64", "arm64"
    ):
        fail("Для промышленного Compose необходим Linux x64 или ARM64")
    if os.geteuid() != 0:
        fail("Предварительная проверка промышленного Compose должна выполняться от root для чтения TLS-ключей")
    if not shutil.which("docker"):
        fail("Требуются Docker Engine и Compose v2")
    result = execute(["docker", "info", "--format", "{{.DockerRootDir}}"], capture=True)
    docker_root = (result.stdout or "").strip()
    if not docker_root or not Path(docker_root).is_absolute() or not Path(docker_root).is_dir():
        fail("Не удалось определить доступный каталог данных Docker")
    execute(["docker", "compose", "version"], capture=True)
    meminfo = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.M)
    if not match or int(match.group(1)) < 2 * 1024 * 1024:
        fail("Промышленному хосту требуется не менее 2 ГиБ ОЗУ")
    if shutil.disk_usage(docker_root).free < 8 * 1024 ** 3:
        fail("Для первых сборок в файловой системе Docker необходимо не менее 8 ГиБ свободного места")
    if fresh:
        for port in (80, 443):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError:
                    fail(f"Порт {port} уже занят; предварительная проверка чистого хоста не пройдена")


def tls_paths(values):
    """До Compose проверить настоящую цепочку доверия, имя хоста, срок действия и соответствие закрытого ключа."""
    cert = Path(values["LAUNCHER_TLS_CERT_PATH"])
    key = Path(values["LAUNCHER_TLS_KEY_PATH"])
    if not cert.is_absolute() or not key.is_absolute() or cert == key:
        fail("TLS-сертификат и ключ должны находиться по разным абсолютным путям на хосте")
    if cert.is_symlink() or key.is_symlink():
        fail("TLS-файлы не должны быть символическими ссылками (скопируйте файлы ACME командой install)")
    for path, private in ((cert, False), (key, True)):
        safe_file(path, private=private)
        if path.stat().st_size > 1024 * 1024 or path.stat().st_size == 0:
            fail("TLS-файл пуст или слишком велик")
    if key.stat().st_uid != 0:
        fail("Закрытый TLS-ключ должен принадлежать root")
    hostname = urllib.parse.urlsplit(values["LAUNCHER_PUBLIC_URL"]).hostname

    def openssl(*argv):
        try:
            proc = subprocess.run(["openssl", *map(str, argv)], capture_output=True,
                                  check=False, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            fail("openssl is required and must complete certificate validation")
        if proc.returncode:
            fail("TLS-сертификат некорректен, недоверенный, просрочен, не совпадает с ключом или относится к другому хосту")
        return proc.stdout

    openssl("x509", "-in", cert, "-noout", "-checkhost", hostname)
    openssl("x509", "-in", cert, "-noout", "-checkend", "604800")
    openssl("verify", "-CApath", "/etc/ssl/certs", "-untrusted", cert, cert)
    leaf_public = openssl("x509", "-in", cert, "-pubkey", "-noout")
    key_public = openssl("pkey", "-in", key, "-pubout")
    if hashlib.sha256(leaf_public).digest() != hashlib.sha256(key_public).digest():
        fail("Закрытый TLS-ключ не соответствует сертификату")


def public_json(url, *, payload=None, headers=None, expected_status=None):
    """Без прокси, перенаправлений, небезопасного TLS, неявных повторов и вывода учётных данных."""
    if urllib.parse.urlsplit(url).scheme != "https":
        fail("Публичная операция без HTTPS запрещена")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url, data=body,
        headers={"Accept": "application/json", **({"Content-Type": "application/json"} if body else {}), **(headers or {})},
        method="POST" if body is not None else "GET",
    )
    try:
        with opener.open(request, timeout=12) as response:
            if response.status != (expected_status if expected_status is not None else (201 if body is not None else 200)):
                fail(f"Публичный API отклонил операцию (HTTP {response.status})")
            content = response.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                fail("Ответ публичного API неожиданно велик")
            return json.loads(content)
    except urllib.error.HTTPError as exc:
        # Никогда не печатайте тела ответов: они могут отражать секреты.
        fail(f"Публичный API вернул HTTP {exc.code}; проверьте закрытый журнал аудита сервера")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        fail(f"Публичный HTTPS недоступен или не является доверенным ({type(exc).__name__})")
    except (UnicodeError, json.JSONDecodeError):
        fail("public API returned invalid JSON")


def verify_public_ready(values, expected_version=None):
    public = values["LAUNCHER_PUBLIC_URL"].rstrip("/")
    status = public_json(public + "/ready")
    if status.get("status") != "ready":
        fail("Публичная проверка готовности HTTPS /ready не пройдена")
    if expected_version is not None and status.get("version") != expected_version:
        fail("Версия работающего API не соответствует выбранному образу релиза")
    return status


def bootstrap_first_admin(args):
    """Создать, аутентифицировать и проверить одноразового администратора в реально запущенном API."""
    env = Path(args.env).resolve(strict=True)
    safe_file(env, private=True)
    safe_directory(env.parent)
    values = read_env(env)
    preflight(values, "standard", docker=True)
    tls_paths(values)
    if not values.get("LAUNCHER_BOOTSTRAP_TOKEN") or len(values["LAUNCHER_BOOTSTRAP_TOKEN"]) < 32:
        fail("Для создания первого администратора требуется надёжный LAUNCHER_BOOTSTRAP_TOKEN в закрытом файле окружения")
    address = email.utils.parseaddr(args.email)
    if address[1] != args.email or "@" not in args.email or len(args.email) > 254 or any(c.isspace() for c in args.email):
        fail("Некорректный адрес электронной почты администратора")
    password_file = Path(args.password_file)
    info = safe_file(password_file, private=True)
    if info.st_uid != os.geteuid() or info.st_size > 4096 or info.st_size < 12:
        fail("Файл пароля администратора должен принадлежать текущему пользователю и содержать от 12 до 4096 байт")
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if len(password) < 12 or any(c in password for c in "\r\n\x00"):
        fail("Пароль администратора должен содержать не менее 12 символов в одной строке")
    public = values["LAUNCHER_PUBLIC_URL"].rstrip("/")
    with exclusive_lock(env.parent / ".launcher-compose.lock"):
        state_file = env.parent / ".launcher-compose-state.json"
        safe_file(state_file, private=True)
        state = json.loads(state_file.read_text())
        if state != {"mode": "standard", "version": values["LAUNCHER_IMAGE_TAG"]}:
            fail("Для создания первого администратора требуется совпадающее состояние локальной установки Standard Compose")
        verify_public_ready(values, values["LAUNCHER_IMAGE_TAG"])
        before = public_json(public + "/api/v1/install/readiness").get("data", {})
        if before.get("bootstrapTokenConsumed") or any(
            c.get("id") == "admin-user" and c.get("status") == "ready"
            for c in before.get("checks", [])
        ):
            fail("Одноразовый токен уже использован или администратор существует; повторная попытка отменена")
        response = public_json(
            public + "/api/v1/install/bootstrap-admin",
            payload={"email": args.email, "displayName": args.display_name,
                     "password": password, "actor": "production-deploy 0.45.1"},
            headers={"X-Launcher-Bootstrap-Token": values["LAUNCHER_BOOTSTRAP_TOKEN"]},
        )
        if response.get("data", {}).get("status") != "admin-created" or response.get("data", {}).get("email") != args.email:
            fail("API не подтвердил создание указанного администратора")
        after = public_json(public + "/api/v1/install/readiness").get("data", {})
        if not after.get("bootstrapTokenConsumed") or not any(
            c.get("id") == "admin-user" and c.get("status") == "ready"
            for c in after.get("checks", [])
        ):
            fail("Создание администратора не сохранено в состоянии установки")
        # Настоящий аутентифицированный вход доказывает работу пароля и локального механизма авторизации.
        login = public_json(public + "/api/v1/admin/login", payload={"email": args.email, "password": password}, expected_status=200)
        if not login.get("token") or login.get("user", {}).get("email") != args.email:
            fail("Администратор создан, но фактический вход по паролю не удался")
        print("Первый администратор создан; одноразовый токен использован; вход через доверенный HTTPS проверен")
        print("Безопасно удалите файл с паролем; войдите в Admin и создайте первый проект")


@contextlib.contextmanager
def exclusive_lock(path):
    path = Path(path)
    if path.is_symlink():
        fail("Путь блокировки через символическую ссылку отклонён")
    fd = os.open(
        str(path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        if os.fstat(fd).st_mode & 0o077:
            fail("Файл блокировки должен иметь закрытые права доступа")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def compose_project(values):
    # Пространство имён защищает изолированное приёмочное развёртывание от контейнеров,
    # сетей и именованных томов обычного производственного проекта.
    project = values.get("LAUNCHER_COMPOSE_PROJECT", "launcher")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,40}", project):
        fail("Некорректный LAUNCHER_COMPOSE_PROJECT (имя проекта Docker Compose должно быть в нижнем регистре)")
    return project


def compose_args(env, mode):
    project = compose_project(read_env(env))
    args = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        str(env),
        "-f",
        str(COMPOSE),
    ]
    if mode == "network-ha":
        args += ["-f", str(HA), "--profile", "network-ha"]
    values = read_env(env)
    if any(key.startswith("LAUNCHER_0523_HOST_") for key in values):
        if mode != "standard" or not re.fullmatch(r"nl0523[a-z0-9]{8,20}", project):
            fail("Интеграция управления хостом 0523 разрешена только в изолированном проекте Standard")
        for key in ("LAUNCHER_0523_HOST_TARGETS_FILE", "LAUNCHER_0523_HOST_CA_FILE", "LAUNCHER_0523_HOST_TOKEN_FILE"):
            value = values.get(key, "")
            if not value or not Path(value).is_absolute():
                fail("Отсутствует файл доверия управления хостом 0523 с абсолютным путём: " + key)
            safe_file(value, private=True)
        args += ["-f", str(ROOT / "deploy/production/docker-compose.owner-e2e-0523.yml")]
    return args


def compose_run(args):
    env = Path(args.env).resolve(strict=True)
    safe_file(env, private=True)
    safe_directory(env.parent)
    values = read_env(env)
    mode = args.mode
    preflight(values, mode, docker=True, tls_required=args.action in ("check", "up"))
    state_file = env.parent / ".launcher-compose-state.json"
    with exclusive_lock(env.parent / ".launcher-compose.lock"):
        if args.action in ("check", "up"):
            tls_paths(values)
        state = {}
        if state_file.exists():
            safe_file(state_file, private=True)
            state = json.loads(state_file.read_text())
        if state and state.get("mode") != mode:
            fail("Режим развёртывания изменён; сначала удалите прежнюю установку (тома будут сохранены)")
        if args.action in ("check", "up"):
            host_preflight(fresh=not bool(state))
        if (
            args.action == "up"
            and state
            and state.get("version") != values["LAUNCHER_IMAGE_TAG"]
            and not args.backup_confirmed
        ):
            fail(
                "upgrade requires --backup-confirmed after verified database and blob backups"
            )
        if args.action == "up" and not state and len(values.get("LAUNCHER_BOOTSTRAP_TOKEN", "")) < 32:
            fail("Для новой промышленной установки требуется надёжный одноразовый LAUNCHER_BOOTSTRAP_TOKEN")
        base = compose_args(env, mode)
        if args.action == "check":
            execute(base + ["config", "--quiet"])
            print(f"Конфигурация Compose для режима {mode} корректна")
        elif args.action == "up":
            execute(base + ["config", "--quiet"])
            execute(
                base
                + ["up", "--build", "-d", "--wait", "--wait-timeout", "120", "--remove-orphans"]
            )
            verify_public_ready(values, values["LAUNCHER_IMAGE_TAG"])
            atomic_text(
                state_file,
                json.dumps({"mode": mode, "version": values["LAUNCHER_IMAGE_TAG"]})
                + "\n",
                0o600,
            )
            print("Compose запущен: реальный Backend доступен через доверенный публичный HTTPS; первого администратора ещё нужно создать")
        elif args.action == "status":
            execute(base + ["ps"])
        elif args.action in ("down", "uninstall"):
            if args.action == "uninstall" and args.purge_data:
                if args.confirm != "PURGE-LAUNCHER-VOLUMES":
                    fail("Для удаления томов требуется --confirm PURGE-LAUNCHER-VOLUMES")
                execute(base + ["down", "--remove-orphans", "--volumes"])
            else:
                execute(base + ["down", "--remove-orphans"])
            if args.action == "uninstall":
                state_file.unlink(missing_ok=True)
                sync_directory(env.parent)
                print(
                    "Приложение Compose удалено; конфигурация и секреты сохранены; "
                    + (
                        "Тома проекта удалены"
                        if args.purge_data
                        else "Тома проекта сохранены"
                    )
                )
        else:
            fail("Неизвестная операция Compose")


def require_root():
    if os.geteuid() != 0:
        fail("Для операций с нативной службой требуются права root")
    if sys.platform != "linux" or not Path("/run/systemd/system").exists():
        fail("Для операций с нативной службой требуется Linux с работающим systemd")


def no_symlinks_or_mounts(path):
    """Перед удалением обходить дерево без перехода по ссылкам и без пересечения точек монтирования."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_mount():
        fail("Удаление объекта со ссылкой или точкой монтирования отклонено")
    for current, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            target = Path(current) / name
            if target.is_symlink() or target.is_mount():
                fail("refusing to delete tree containing symlink or mount")


def managed_dir(path, marker, *, create=False):
    if create and not path.exists():
        path.mkdir(mode=0o755, parents=True)
    safe_directory(path)
    owner_marker = path / marker
    if not owner_marker.exists():
        if not create:
            fail(f"Отсутствует маркер владельца: {path}")
        # Не присваивайте посторонний существующий непустой каталог.
        if any(path.iterdir()):
            fail(f"Каталог установки не пуст и не управляется установщиком: {path}")
        write_exclusive(owner_marker, MARKER_VALUE)
    safe_file(owner_marker, private=True)
    if owner_marker.read_text() != MARKER_VALUE:
        fail("Маркер владельца не совпадает")


def atomic_symlink(target, link):
    temp = Path(str(link) + ".new." + str(os.getpid()))
    os.symlink(target, temp)
    try:
        os.replace(temp, link)
        sync_directory(link.parent)
    finally:
        temp.unlink(missing_ok=True)


def existing_release():
    link = INSTALL_ROOT / "current"
    if not link.exists() and not link.is_symlink():
        return None
    if not link.is_symlink():
        fail("Указатель текущего релиза не является символической ссылкой")
    target = os.readlink(link)
    if not re.fullmatch(r"releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target):
        fail("Указатель текущего релиза расположен за пределами управляемых релизов")
    if not (INSTALL_ROOT / target).is_dir():
        fail("Указатель текущего релиза повреждён")
    return target


def service_unit(env_path):
    if any(c in str(env_path) for c in "\r\n %\\\"'"):
        fail("Небезопасный путь к окружению нативной службы")
    return f"""{UNIT_MARKER}
[Unit]
Description=Launcher API (DEP09 managed)
Wants=network-online.target
After=network-online.target postgresql.service

[Service]
Type=simple
User=launcher
Group=launcher
WorkingDirectory=/var/lib/launcher
EnvironmentFile={env_path}
ExecStart=/opt/launcher/current/bin/launcher-api
Restart=on-failure
RestartSec=5
TimeoutStopSec=40
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/var/lib/launcher
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
"""


def health_check(url):
    if url != "http://127.0.0.1:8080/ready":
        fail("Нативная проверка состояния поддерживает только фиксированный локальный адрес /ready")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for _ in range(15):
        try:
            with opener.open(urllib.request.Request(url), timeout=2) as resp:
                if resp.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    fail("Проверка готовности нативной службы не пройдена; успешная активация отклонена")


def native_install(args):
    require_root()
    if safe_file(args.env, private=True).st_uid != 0:
        fail("Окружение нативной службы должно принадлежать root")
    values = read_env(Path(args.env))
    preflight(values, "standard", docker=False)
    binary_info = safe_file(args.installer, executable=True)
    key_info = safe_file(args.trusted_key)
    if binary_info.st_uid != 0 or key_info.st_uid != 0:
        fail("trusted installer and pinned public key must be root-owned")
    safe_file(args.bundle)
    with exclusive_lock(Path("/run/launcher-deploy.lock")):
        # Не заменяйте неуправляемые unit-файлы systemd.
        if UNIT.exists() and UNIT_MARKER not in UNIT.read_text():
            fail("Служба systemd не управляется DEP09")
        managed_dir(INSTALL_ROOT, OWNER, create=True)
        releases = INSTALL_ROOT / "releases"
        releases.mkdir(mode=0o755, exist_ok=True)
        safe_directory(releases)
        old = existing_release()
        if old and (not args.upgrade or not args.backup_confirmed):
            fail(
                "Для обновления требуются --upgrade и --backup-confirmed (проверьте резервные копии независимо)"
            )
        verified = execute(
            [
                args.installer,
                "verify",
                "--bundle",
                args.bundle,
                "--trusted-key",
                args.trusted_key,
            ],
            capture=True,
        )
        matched = VERSION_RE.search(verified.stdout or "")
        if not matched:
            fail("Доверенный установщик не сообщил версию подписанного пакета")
        version = matched.group(1)
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or tuple(
            map(int, version.split("."))
        ) < (0, 32, 13):
            fail("DEP09 требует подписанный релиз версии 0.32.13 или новее")
        if old and tuple(map(int, version.split("."))) <= tuple(
            map(int, old.split("/")[1].split("."))
        ):
            fail("Версия нативного обновления должна строго возрастать")
        target = releases / version
        if target.exists() or target.is_symlink():
            fail("Каталог подписанного релиза уже существует (перезапись запрещена)")
        execute(
            [
                args.installer,
                "install",
                "--bundle",
                args.bundle,
                "--trusted-key",
                args.trusted_key,
                "--target",
                target,
            ]
        )
        binary = target / "bin/launcher-api"
        safe_file(binary, executable=True)
        # Только выделенный пользователь API может записывать долговечное состояние, но не бинарные файлы и секреты.
        if not STATE_ROOT.exists():
            STATE_ROOT.mkdir(mode=0o700)
            write_exclusive(STATE_ROOT / DATA_MARKER, MARKER_VALUE)
        safe_directory(STATE_ROOT)
        if not (STATE_ROOT / DATA_MARKER).exists():
            fail("Неуправляемый каталог состояния отклонён")
        safe_file(STATE_ROOT / DATA_MARKER, private=True)
        if (STATE_ROOT / DATA_MARKER).read_text() != MARKER_VALUE:
            fail("Маркер состояния не совпадает")
        if execute(["id", "-u", "launcher"], capture=True, check=False).returncode:
            execute(
                [
                    "useradd",
                    "--system",
                    "--home-dir",
                    str(STATE_ROOT),
                    "--shell",
                    "/usr/sbin/nologin",
                    "launcher",
                ]
            )
        identity = pwd.getpwnam("launcher")
        os.chown(STATE_ROOT, identity.pw_uid, identity.pw_gid)
        os.chmod(STATE_ROOT, 0o700)
        # Создавайте пути Runtime; никаких неявных записей вне управляемого корня данных.
        data_paths = [
            STATE_ROOT / p
            for p in ("storage", "backups", "coordinator", "extensions", "factory")
        ]
        for name in (
            "LAUNCHER_STORAGE_LOCAL_PATH",
            "LAUNCHER_BACKUP_ROOT",
            "LAUNCHER_EXTENSION_ROOT",
            "LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH",
        ):
            value = values.get(name, "")
            if name.endswith("SQLITE_PATH"):
                value = str(Path(value).parent) if value else ""
            if value:
                directory = Path(value)
                if not directory.is_absolute() or STATE_ROOT not in directory.parents:
                    fail(
                        f"{name} должен находиться внутри управляемого корневого каталога состояния нативной установки"
                    )
                data_paths.append(directory)
        for directory in data_paths:
            cursor = directory
            missing = []
            while cursor != STATE_ROOT and not cursor.exists():
                missing.append(cursor)
                cursor = cursor.parent
            if cursor != STATE_ROOT and not (
                cursor.is_dir() and STATE_ROOT in cursor.parents
            ):
                fail("Небезопасный путь Runtime")
            for path in reversed(missing):
                path.mkdir(mode=0o700)
                os.chown(path, identity.pw_uid, identity.pw_gid)
            safe_directory(directory)
            if directory.stat().st_uid != identity.pw_uid:
                fail(f"Каталог Runtime не принадлежит пользователю службы: {directory}")
        # Управляемая первичная установка не должна конфликтовать со сторонним unit.
        old_unit = UNIT.read_text() if UNIT.exists() else None
        if (
            execute(
                ["systemctl", "is-active", "--quiet", UNIT_NAME], check=False
            ).returncode
            == 0
        ):
            execute(["systemctl", "stop", UNIT_NAME])
        try:
            atomic_text(UNIT, service_unit(Path(args.env)), 0o644)
            atomic_symlink("releases/" + version, INSTALL_ROOT / "current")
            execute(["systemctl", "daemon-reload"])
            execute(["systemctl", "enable", "--now", UNIT_NAME])
            health_check("http://127.0.0.1:8080/ready")
        except BaseException:
            execute(["systemctl", "stop", UNIT_NAME], check=False)
            if old is not None:
                atomic_symlink(old, INSTALL_ROOT / "current")
            else:
                (INSTALL_ROOT / "current").unlink(missing_ok=True)
            if old_unit is not None:
                atomic_text(UNIT, old_unit)
            else:
                UNIT.unlink(missing_ok=True)
            execute(["systemctl", "daemon-reload"], check=False)
            if old is not None:
                execute(["systemctl", "start", UNIT_NAME], check=False)
            raise
        print(
            "Нативная служба Launcher 0.32.13 активирована; предыдущий релиз сохранён для отката"
        )


def native_uninstall(args):
    require_root()
    with exclusive_lock(Path("/run/launcher-deploy.lock")):
        managed_dir(INSTALL_ROOT, OWNER)
        if args.purge_data:
            safe_directory(STATE_ROOT)
            safe_file(STATE_ROOT / DATA_MARKER, private=True)
            if (STATE_ROOT / DATA_MARKER).read_text() != MARKER_VALUE:
                fail("Маркер состояния не совпадает")
            no_symlinks_or_mounts(STATE_ROOT)
        if UNIT.exists():
            safe_file(UNIT)
            if UNIT_MARKER not in UNIT.read_text():
                fail("Удаление сторонней службы systemd отклонено")
            execute(["systemctl", "disable", "--now", UNIT_NAME])
            UNIT.unlink()
            execute(["systemctl", "daemon-reload"])
        previous = existing_release()
        link = INSTALL_ROOT / "current"
        if previous:
            link.unlink()
        releases = INSTALL_ROOT / "releases"
        if releases.exists():
            no_symlinks_or_mounts(releases)
            shutil.rmtree(releases)
        (INSTALL_ROOT / OWNER).unlink()
        # Сохраняйте неожиданные файлы, не удаляя данные оператора.
        if not any(INSTALL_ROOT.iterdir()):
            INSTALL_ROOT.rmdir()
        if args.purge_data:
            if args.confirm != "PURGE-LAUNCHER-NATIVE-DATA":
                fail("Для удаления данных требуется --confirm PURGE-LAUNCHER-NATIVE-DATA")
            shutil.rmtree(STATE_ROOT)
        print(
            "Нативная служба удалена; внешняя PostgreSQL и секреты /etc не затронуты; "
            + (
                "Локальные данные приложения удалены"
                if args.purge_data
                else "Локальные данные приложения сохранены"
            )
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="provider", required=True)
    cp = sub.add_parser("compose")
    cp.add_argument("action", choices=["check", "up", "status", "down", "uninstall", "first-admin"])
    cp.add_argument("--env", default=str(COMPOSE.parent / ".env"))
    cp.add_argument("--mode", required=True, choices=["standard", "network-ha"])
    cp.add_argument(
        "--backup-confirmed",
        action="store_true",
        help="Оператор проверил внешнюю копию БД/blob до обновления образа",
    )
    cp.add_argument("--purge-data", action="store_true")
    cp.add_argument("--confirm", default="")
    cp.add_argument("--email", help="Электронная почта первого администратора")
    cp.add_argument("--display-name", default="Administrator")
    cp.add_argument("--password-file", help="Закрытый файл с начальным паролем администратора, права 0600")
    np = sub.add_parser("native")
    np.add_argument("action", choices=["install", "uninstall"])
    np.add_argument("--installer", default="/usr/local/bin/launcher-install")
    np.add_argument("--bundle")
    np.add_argument("--trusted-key")
    np.add_argument("--env", default=str(ENV_NATIVE))
    np.add_argument("--upgrade", action="store_true")
    np.add_argument("--backup-confirmed", action="store_true")
    np.add_argument("--purge-data", action="store_true")
    np.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if args.provider == "compose":
        if args.purge_data and args.action != "uninstall":
            fail("Параметр --purge-data разрешён только при удалении установки")
        if args.action == "first-admin":
            if args.mode != "standard" or not args.email or not args.password_file:
                fail("Для создания первого администратора через Compose требуются --mode standard, --email и --password-file")
            bootstrap_first_admin(args)
        else:
            compose_run(args)
    elif args.action == "install":
        if not args.bundle or not args.trusted_key:
            fail("native install requires --bundle and independent --trusted-key")
        native_install(args)
    else:
        # Проверяйте подтверждение разрушительного действия ДО изменения файлов или служб.
        if args.purge_data and args.confirm != "PURGE-LAUNCHER-NATIVE-DATA":
            fail("Для удаления данных требуется --confirm PURGE-LAUNCHER-NATIVE-DATA")
        native_uninstall(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as e:
        print("launcher-deploy:", e, file=sys.stderr)
        sys.exit(1)
