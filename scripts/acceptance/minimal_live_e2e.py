#!/usr/bin/env python3
"""Минимальная приёмка: настоящий процесс Go API, настоящие SQLite и HTTP.

Нет имитации сервера или свидетельств. Проверяются чистая установка, аутентификация, устойчивое
изменение, перезапуски SIGTERM/SIGKILL, автономное резервное копирование, проверенное восстановление
и отклонение повреждений. Ошибки блокируют продолжение; вывод содержит утверждения тестов, но не
секреты.

Для изолированных CI-тестов политики Guard/Bridge нужно передавать явно. Это ВХОДНЫЕ параметры
конфигурации, а не аттестации публикации. Набор не сертифицирует запуск Minecraft, стабильный GA или
развёртывание HA.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
INSTALLER = HERE.parent / "install" / "minimal-install.py"
PRODUCT_VERSION = (HERE.parents[1] / "VERSION").read_text(encoding="utf-8").strip()


class AcceptanceFailure(RuntimeError):
    pass


def require(value, why):
    if not value:
        raise AcceptanceFailure(why)


def encode_report(path: Path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + "." + secrets.token_hex(5))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def command(*argv, expected=0, timeout=90):
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    require(
        proc.returncode == expected,
        f"command {Path(str(argv[0])).name} exited {proc.returncode} instead of {expected}",
    )
    return proc.stdout


def port_choice():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port, method, path, payload=None, headers=None, *, timeout=5):
    data = (
        None
        if payload is None
        else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    hdr = dict(headers or {})
    if data is not None:
        hdr["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=data, headers=hdr)
        response = conn.getresponse()
        body = response.read(512 * 1024)
        require(len(body) < 512 * 1024, "Ответ HTTP превышает допустимый размер")
        try:
            doc = json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise AcceptanceFailure(f"Ответ {method} {path} не является JSON") from exc
        return response.status, doc
    finally:
        conn.close()


def expect(port, method, path, code, payload=None, headers=None):
    status, doc = request(port, method, path, payload, headers)
    require(status == code, f"{method} {path}: HTTP {status}, expected {code}")
    return doc


class RealAPI:
    def __init__(
        self,
        binary: Path,
        envfile: Path,
        port: int,
        logdir: Path,
        expected_version: str = PRODUCT_VERSION,
    ):
        self.binary, self.envfile, self.port, self.logdir = (
            binary,
            envfile,
            port,
            logdir,
        )
        self.expected_version = expected_version
        self.proc = None
        self.loghandle = None

    def start(self, *, expect_failure=False):
        require(self.proc is None, "Процесс API уже запущен")
        logpath = self.logdir / ("api-" + secrets.token_hex(5) + ".log")
        self.loghandle = logpath.open("xb")
        os.chmod(logpath, 0o600)
        self.proc = subprocess.Popen(
            [
                sys.executable,
                str(INSTALLER),
                "run",
                "--binary",
                str(self.binary),
                "--env-file",
                str(self.envfile),
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.loghandle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        until = time.monotonic() + (12 if expect_failure else 35)
        while time.monotonic() < until:
            if self.proc.poll() is not None:
                if expect_failure:
                    require(
                        self.proc.returncode != 0,
                        "Недопустимый или конфликтующий API неожиданно успешно запустился",
                    )
                    self.proc.wait(timeout=2)
                    self.proc = None
                    self._close_log()
                    return
                raise AcceptanceFailure(
                    "Реальный API завершился до готовности (см. закрытые журналы процессов CI)"
                )
            if not expect_failure:
                try:
                    status, doc = request(self.port, "GET", "/ready", timeout=2)
                    if (
                        status == 200
                        and doc.get("status") == "ready"
                        and doc.get("repository") == "sqlite"
                    ):
                        health = expect(self.port, "GET", "/health", 200)
                        require(
                            health.get("version") == self.expected_version,
                            "running API has wrong product version",
                        )
                        expected_commit = os.environ.get("GITHUB_SHA", "")
                        if expected_commit:
                            require(
                                health.get("sourceCommit") == expected_commit,
                                "running API source commit differs from CI checkout",
                            )
                        return
                except (OSError, TimeoutError):
                    pass
            time.sleep(0.15)
        if expect_failure:
            raise AcceptanceFailure("API с некорректной конфигурацией или конфликтом портов не завершил работу")
        raise AcceptanceFailure(
            "API с SQLite не перешёл в состояние /ready за отведённое время"
        )

    def stop(self, *, crash=False):
        if self.proc is None:
            return
        proc = self.proc
        if proc.poll() is None:
            # Установщик запускает API через exec; SIGKILL проверяет восстановление настоящего WAL после сбоя.
            os.killpg(proc.pid, signal.SIGKILL if crash else signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=8)
            raise AcceptanceFailure("API не завершил обработку запросов после SIGTERM") from exc
        if crash:
            require(proc.returncode < 0, "Сигнал SIGKILL не остановил API")
        elif proc.returncode != 0:
            raise AcceptanceFailure(
                f"API не смог корректно завершиться по SIGTERM, код выхода {proc.returncode}"
            )
        self.proc = None
        self._close_log()

    def _close_log(self):
        if self.loghandle:
            self.loghandle.close()
            self.loghandle = None

    def cleanup(self):
        if self.proc:
            try:
                self.stop(crash=True)
            except Exception:
                pass
        self._close_log()


def step(report, name, fn):
    start = time.monotonic()
    value = fn()
    report["checks"].append(
        {
            "id": name,
            "status": "passed",
            "durationMs": round((time.monotonic() - start) * 1000),
        }
    )
    print(f"ПРОЙДЕНО {name}", flush=True)
    return value


def verify_project(port, identifier, token=None):
    item = expect(port, "GET", "/api/v1/projects/" + identifier, 200)
    require(item.get("id") == identifier, "Идентификатор проекта изменился после перезапуска")
    versions = expect(port, "GET", "/api/v1/projects/" + identifier + "/versions", 200)
    require(
        isinstance(versions.get("items"), list) and versions["items"],
        "draft release lost after restart",
    )
    if token:
        sessions = expect(
            port,
            "GET",
            "/api/v1/auth/sessions",
            200,
            headers={"Authorization": "Bearer " + token},
        )
        require(isinstance(sessions, dict), "Эндпоинт сеансов вернул недопустимый результат")



def owner_admin_crud_0523(port, email, password):
    """Настоящие аутентифицированные изменения администратора в установленном Backend на SQLite."""
    login = expect(port, 'POST', '/api/v1/admin/login', 200,
                   {'email': email, 'password': password})
    token = login.get('token')
    require(isinstance(token, str) and len(token) >= 20,
            'При реальном входе администратора не создан сеанс')
    unauth_status, _ = request(port, 'POST', '/api/v1/admin/projects',
                               {'id': 'unauthenticated-0523', 'name': 'Rejected'})
    require(unauth_status in (401, 403), 'Изменение данных администратора без аутентификации не было запрещено')
    header = {'Authorization': 'Bearer ' + token}
    project = 'owner0523-' + secrets.token_hex(8)
    description = 'Minimal SQLite retained owner project ' + secrets.token_hex(8)
    created = expect(port, 'POST', '/api/v1/admin/projects', 201,
                     {'id': project, 'name': 'Owner acceptance project', 'defaultChannel': 'stable'}, header)
    require(created.get('data', {}).get('project', {}).get('id') == project,
            'Проект владельца не был создан')
    expect(port, 'PATCH', '/api/v1/admin/projects/' + project, 200,
           {'description': description}, header)
    profile = 'owner-vanilla'
    channel = 'owner-review'
    profile_response = expect(port, 'POST', '/api/v1/admin/projects/' + project + '/profiles', 201,
                              {'id': profile, 'name': 'Owner vanilla', 'loader': 'vanilla'}, header)
    require(profile_response.get('data', {}).get('profile', {}).get('id') == profile,
            'Профиль владельца не был создан')
    channel_response = expect(port, 'POST', '/api/v1/admin/projects/' + project + '/channels', 201,
                              {'id': channel, 'name': 'Owner review', 'protected': True}, header)
    require(channel_response.get('data', {}).get('channel', {}).get('id') == channel,
            'Канал владельца не был создан')
    verify_admin_0523(port, email, password, project, description, profile, channel)
    expect(port, 'GET', '/api/v1/projects/' + project + '/profiles/' + profile + '/manifest', 404)
    return (project, description, profile, channel)


def verify_admin_0523(port, email, password, project, description, profile, channel):
    login = expect(port, 'POST', '/api/v1/admin/login', 200,
                   {'email': email, 'password': password})
    token = login.get('token')
    require(isinstance(token, str) and len(token) >= 20, 'Состояние входа администратора потеряно')
    doc = expect(port, 'GET', '/api/v1/projects/' + project, 200)
    require(doc.get('id') == project and doc.get('description') == description,
            'persisted admin project data differs')
    profiles = expect(port, 'GET', '/api/v1/projects/' + project + '/profiles', 200)
    channels = expect(port, 'GET', '/api/v1/projects/' + project + '/channels', 200)
    require(any(p.get('id') == profile for p in profiles.get('items', [])),
            'Сохранённый профиль отсутствует')
    require(any(c.get('id') == channel for c in channels.get('items', [])),
            'Сохранённый канал отсутствует')
    expect(port, 'GET', '/api/v1/admin/audit', 200,
           headers={'Authorization': 'Bearer ' + token})
    denied_status, _ = request(port, 'GET', '/api/v1/admin/audit')
    require(denied_status in (401, 403), 'Чтение аудита без аутентификации не было запрещено')


def run_acceptance(
    binary: Path,
    guard: Path,
    bridge: Path,
    work: Path,
    report,
    expected_version: str = PRODUCT_VERSION,
):
    require(
        binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK),
        "Отсутствует исполняемый бинарный файл реального API",
    )
    require(not binary.stat().st_mode & 0o022, "Небезопасные права доступа к исполняемому файлу API")
    require(
        guard.is_file() and bridge.is_file(),
        "Требуются действительные файлы политик Guard/Bridge",
    )
    require(
        work.is_absolute() and work.is_dir() and not any(work.iterdir()),
        "Рабочий каталог должен быть пустым",
    )
    report["binarySha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    report["sourceCommit"] = os.environ.get("GITHUB_SHA", "")
    report["scope"] = "minimal-linux-real-process-no-ga-attestation"
    port = port_choice()
    root, restored = work / "original", work / "restored"
    envfile = root / "config/backend.env"
    api = RealAPI(binary, envfile, port, work, expected_version)
    rest = RealAPI(
        binary, restored / "config/backend.env", port, work, expected_version
    )
    email = "operator-0378@localhost.invalid"
    password = secrets.token_urlsafe(34)
    project = "e2e0378-" + secrets.token_hex(6)
    try:
        step(
            report,
            "installer_init",
            lambda: command(
                sys.executable,
                INSTALLER,
                "init",
                "--root",
                root,
                "--binary",
                binary,
                "--public-url",
                "https://localhost.invalid",
                "--guard-policy",
                guard,
                "--bridge-policy",
                bridge,
                "--listen",
                f"127.0.0.1:{port}",
            ),
        )
        require(
            stat.S_IMODE(envfile.stat().st_mode) == 0o600,
            "bootstrap secrets not private",
        )
        envvalues = dict(
            line.split("=", 1)
            for line in envfile.read_text().splitlines()
            if "=" in line
        )
        token = envvalues["LAUNCHER_BOOTSTRAP_TOKEN"]
        require(not envvalues.get("LAUNCHER_REDIS_URL"), "В минимальную конфигурацию неожиданно включён Redis")
        step(
            report,
            "installer_diagnose",
            lambda: command(
                sys.executable,
                INSTALLER,
                "check",
                "--env-file",
                envfile,
                "--binary",
                binary,
            ),
        )
        step(report, "cold_start", api.start)

        def setup():
            wizard = expect(port, "GET", "/api/v1/install/wizard", 200)
            require(
                wizard.get("data", {}).get("profile") == "minimal-sqlite",
                "wrong installer profile",
            )
            before = expect(port, "GET", "/api/v1/install/readiness", 200)
            require(
                not before.get("data", {}).get("installationCompleted"),
                "Чистая установка уже завершена",
            )
            denied = expect(
                port,
                "POST",
                "/api/v1/install/bootstrap-admin",
                403,
                {"email": email, "password": password},
            )
            require(isinstance(denied, dict), "Недопустимый ответ отказа для неаутентифицированного запроса")
            created = expect(
                port,
                "POST",
                "/api/v1/install/bootstrap-admin",
                201,
                {"email": email, "displayName": "E2E operator", "password": password},
                {"X-Launcher-Bootstrap-Token": token},
            )
            require(
                created.get("data", {}).get("bootstrapTokenConsumed") is True,
                "bootstrap not consumed",
            )
            expect(
                port,
                "POST",
                "/api/v1/install/bootstrap-admin",
                403,
                {"email": email, "password": password},
                {"X-Launcher-Bootstrap-Token": token},
            )
            login = expect(
                port,
                "POST",
                "/api/v1/auth/login",
                200,
                {"email": email, "password": password},
            )
            tokens = login.get("data", {}).get("tokens", {})
            require(
                tokens.get("accessToken") and tokens.get("refreshToken"),
                "login did not issue tokens",
            )
            finished = expect(
                port,
                "POST",
                "/api/v1/install/first-project",
                201,
                {
                    "projectId": project,
                    "profileId": "vanilla",
                    "channel": "stable",
                    "version": "0.1.0",
                },
                {"Authorization": "Bearer " + tokens["accessToken"]},
            )
            require(
                finished.get("data", {}).get("installationCompleted") is True,
                "install did not complete",
            )
            readiness = expect(port, "GET", "/api/v1/install/readiness", 200)
            require(
                readiness.get("data", {}).get("installationCompleted") is True,
                "install status not persisted",
            )
            verify_project(port, project, tokens["accessToken"])
            # Черновик никогда не должен незаметно выдаваться как опубликованный стабильный манифест.
            expect(
                port,
                "GET",
                "/api/v1/projects/" + project + "/profiles/vanilla/manifest",
                404,
            )
            return tokens

        tokens = step(report, "bootstrap_login_draft_and_stable_denial", setup)
        admin_record = step(report, 'real_owner_admin_crud_0523',
                            lambda: owner_admin_crud_0523(port, email, password))

        def reject_online_backup():
            p = subprocess.run(
                [sys.executable, str(INSTALLER), "backup", "--root", str(root)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            require(
                p.returncode != 0, "online backup incorrectly accepted a running API"
            )

        step(report, "active_writer_fencing_backup", reject_online_backup)

        def reject_second_writer():
            contender = RealAPI(binary, envfile, port, work, expected_version)
            try:
                contender.start(expect_failure=True)
                verify_project(port, project)
            finally:
                contender.cleanup()

        step(report, "second_instance_rejected", reject_second_writer)
        step(report, "sigterm_shutdown", api.stop)
        step(report, "graceful_restart", api.start)
        step(report, "graceful_state_verified", lambda: verify_project(port, project))
        step(report, 'owner_admin_state_after_sigterm_restart_0523',
             lambda: verify_admin_0523(port, email, password, *admin_record))

        def durable_refresh():
            response = expect(
                port,
                "POST",
                "/api/v1/auth/refresh",
                200,
                {"refreshToken": tokens["refreshToken"]},
            )
            new = response.get("data", {}).get("tokens", {})
            require(
                new.get("refreshToken")
                and new["refreshToken"] != tokens["refreshToken"],
                "refresh did not rotate",
            )
            tokens.update(new)
            # Текущий токен доступа должен работать после перезапуска.
            verify_project(port, project, tokens["accessToken"])

        step(report, "session_refresh_after_restart", durable_refresh)
        step(report, "sigkill_crash", lambda: api.stop(crash=True))
        step(report, "crash_recovery_start", api.start)

        def verify_crash():
            verify_project(port, project)
            response = expect(
                port,
                "POST",
                "/api/v1/auth/refresh",
                200,
                {"refreshToken": tokens["refreshToken"]},
            )
            require(
                response.get("data", {}).get("tokens", {}).get("refreshToken"),
                "refresh token acknowledged before SIGKILL was lost",
            )

        step(report, "durable_ack_survives_sigkill", verify_crash)
        step(report, 'owner_admin_state_after_sigkill_0523',
             lambda: verify_admin_0523(port, email, password, *admin_record))
        step(report, "stop_before_backup", api.stop)
        blob = root / "storage" / "e2e" / "blobs" / "survives.dat"
        blob.parent.mkdir(parents=True, mode=0o700)
        blob.write_bytes(os.urandom(128 * 1024))
        os.chmod(blob, 0o600)
        expected_blob_hash = hashlib.sha256(blob.read_bytes()).hexdigest()

        def create_backup():
            output = command(sys.executable, INSTALLER, "backup", "--root", root)
            bundle = Path(json.loads(output)["bundle"])
            verify = json.loads(
                command(sys.executable, INSTALLER, "backup-verify", "--bundle", bundle)
            )
            require(verify.get("operation") == "verify", "Резервная копия не прошла проверку")
            return bundle

        bundle = step(report, "offline_consistent_backup_verify", create_backup)

        def restore():
            command(
                sys.executable,
                INSTALLER,
                "restore",
                "--bundle",
                bundle,
                "--target-root",
                restored,
            )
            require(
                (restored / "db/http.sqlite").is_file()
                and (restored / "db/coordinator.sqlite").is_file(),
                "restored SQLite files absent",
            )
            new_env = (restored / "config/backend.env").read_text()
            require(
                str(restored / "db/http.sqlite") in new_env,
                "restored DB path not relocated",
            )
            restored_blob = restored / "storage" / "e2e" / "blobs" / "survives.dat"
            require(
                restored_blob.is_file()
                and hashlib.sha256(restored_blob.read_bytes()).hexdigest()
                == expected_blob_hash,
                "project file changed across backup/restore",
            )

        step(report, "verify_and_restore_clean_host", restore)
        step(report, "restored_api_start", rest.start)

        def verify_restored():
            verify_project(port, project)
            readiness = expect(port, "GET", "/api/v1/install/readiness", 200)
            require(
                readiness.get("data", {}).get("installationCompleted"),
                "completion status lost during restore",
            )
            expect(
                port,
                "POST",
                "/api/v1/install/bootstrap-admin",
                403,
                {"email": email, "password": password},
                {"X-Launcher-Bootstrap-Token": token},
            )
            login = expect(
                port,
                "POST",
                "/api/v1/auth/login",
                200,
                {"email": email, "password": password},
            )
            require(
                login.get("data", {}).get("tokens", {}).get("accessToken"),
                "password verifier lost on restore",
            )

        step(report, "restored_auth_project_and_one_time_token", verify_restored)
        step(report, 'owner_admin_state_after_backup_restore_0523',
             lambda: verify_admin_0523(port, email, password, *admin_record))
        step(report, "restored_api_shutdown", rest.stop)

        # 0.45.2: переносимый аутентифицированный снимок должен запускать НАСТОЯЩИЙ Go Backend во
        # втором независимом корне установки с сохранением долговечной идентичности и
        # использованного bootstrap-токена. Никаких имитаций HTTP-серверов.
        portable_path = work / "offhost-backup.nmb"
        portable_secret = work / "transfer-passphrase"
        fd = os.open(portable_secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(48))
        alternate = work / "offhost-recovered"
        portable_api = RealAPI(binary, alternate / "config/backend.env", port, work, expected_version)
        try:
            def offhost_export_and_restore():
                command(sys.executable, INSTALLER, "export-portable", "--bundle", bundle,
                        "--output", portable_path, "--passphrase-file", portable_secret)
                require(portable_path.read_bytes().startswith(b"NEVER-MINIMAL-PORTABLE-1\n"),
                        "Отсутствует аутентифицированная оболочка передачи данных")
                command(sys.executable, INSTALLER, "verify-portable", "--input", portable_path,
                        "--passphrase-file", portable_secret)
                command(sys.executable, INSTALLER, "restore-portable", "--input", portable_path,
                        "--target-root", alternate, "--passphrase-file", portable_secret)
                require((alternate / "storage/e2e/blobs/survives.dat").is_file(),
                        "off-host blob not recovered")
                require(hashlib.sha256((alternate / "storage/e2e/blobs/survives.dat").read_bytes()).hexdigest()
                        == expected_blob_hash, "off-host blob digest differs")
                require(str(alternate / "db/http.sqlite") in (alternate / "config/backend.env").read_text(),
                        "off-host paths were not relocated")
                command(sys.executable, INSTALLER, "check", "--env-file", alternate / "config/backend.env",
                        "--binary", binary)
            step(report, "authenticated_offhost_transfer_and_deployment_check", offhost_export_and_restore)
            step(report, "offhost_recovered_backend_start", portable_api.start)
            def prove_offhost_identity():
                verify_project(port, project)
                login = expect(port, "POST", "/api/v1/auth/login", 200,
                               {"email": email, "password": password})
                require(login.get("data", {}).get("tokens", {}).get("accessToken"),
                        "off-host password verifier not recovered")
                expect(port, "POST", "/api/v1/install/bootstrap-admin", 403,
                       {"email": email, "password": password},
                       {"X-Launcher-Bootstrap-Token": token})
            step(report, "offhost_recovered_owner_project_bootstrap", prove_offhost_identity)
            step(report, "offhost_recovered_backend_shutdown", portable_api.stop)
            def tamper_transfer():
                tampered = work / "offhost-tampered.nmb"
                shutil.copyfile(portable_path, tampered)
                with tampered.open("r+b") as stream:
                    stream.seek(60)
                    first = stream.read(1)
                    require(bool(first), "Переносимый тестовый архив неожиданно мал")
                    stream.seek(60)
                    stream.write(bytes([first[0] ^ 1]))
                denied = work / "tampered-restore-refused"
                proc = subprocess.run([sys.executable, str(INSTALLER), "restore-portable",
                                       "--input", str(tampered), "--target-root", str(denied),
                                       "--passphrase-file", str(portable_secret)],
                                      capture_output=True, timeout=90)
                require(proc.returncode != 0 and not denied.exists(),
                        "tampered portable snapshot was published")
            step(report, "authenticated_transfer_tampering_refused", tamper_transfer)
        finally:
            portable_api.cleanup()

        def corrupt_repository():
            corrupt_root = work / "corrupt-repository"
            command(
                sys.executable,
                INSTALLER,
                "restore",
                "--bundle",
                bundle,
                "--target-root",
                corrupt_root,
            )
            db = corrupt_root / "db/http.sqlite"
            with sqlite3.connect(db) as conn:
                conn.execute(
                    "UPDATE http_repository_state_0372 SET sha256=? WHERE singleton=1",
                    ("0" * 64,),
                )
                require(conn.total_changes == 1, "Отсутствует строка состояния HTTP SQLite")
                conn.commit()
            bad = RealAPI(
                binary,
                corrupt_root / "config/backend.env",
                port,
                work,
                expected_version,
            )
            try:
                bad.start(expect_failure=True)
            finally:
                bad.cleanup()
            require(
                not (corrupt_root / "backups").is_symlink(),
                "Недопустимое состояние теста повреждения данных",
            )

        step(report, "corrupt_repository_prevents_api_start", corrupt_repository)

        def corrupted_bundle():
            with (bundle / "payload/db/http.sqlite").open("r+b") as f:
                f.seek(0)
                f.write(b"corrupted-header!")
            p = subprocess.run(
                [
                    sys.executable,
                    str(INSTALLER),
                    "backup-verify",
                    "--bundle",
                    str(bundle),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            require(p.returncode != 0, "Изменённая резервная копия ошибочно прошла проверку")
            target = work / "should-not-restore"
            p = subprocess.run(
                [
                    sys.executable,
                    str(INSTALLER),
                    "restore",
                    "--bundle",
                    str(bundle),
                    "--target-root",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            require(
                p.returncode != 0 and not target.exists(),
                "tampered backup modified target",
            )

        step(report, "corruption_fail_closed", corrupted_bundle)
    finally:
        rest.cleanup()
        api.cleanup()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--guard-policy", type=Path, required=True)
    parser.add_argument("--bridge-policy", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-version", default=PRODUCT_VERSION)
    args = parser.parse_args(argv)
    report = {
        "schemaVersion": 1,
        "productVersion": args.expected_version,
        "status": "blocked",
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "checks": [],
    }
    code = 1
    try:
        require(
            args.expected_version == PRODUCT_VERSION,
            "E2E version differs from checked-out VERSION",
        )
        run_acceptance(
            args.binary.resolve(),
            args.guard_policy.resolve(),
            args.bridge_policy.resolve(),
            args.work_root.absolute(),
            report,
            args.expected_version,
        )
        require(len(report["checks"]) >= 20, "Недостаточно фактических доказательств E2E")
        report["status"] = "passed"
        code = 0
    except (
        AcceptanceFailure,
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
        KeyError,
        sqlite3.DatabaseError,
    ) as exc:
        # Не включайте ответы, переменные окружения, токены и тела запросов в отчёты.
        report["failureType"] = type(exc).__name__
        report["failure"] = str(exc)[:300]
        print("BLOCKED: " + str(exc)[:300], file=sys.stderr)
    finally:
        report["finishedAt"] = datetime.now(timezone.utc).isoformat()
        encode_report(args.report.absolute(), report)
    return code


if __name__ == "__main__":
    sys.exit(main())
