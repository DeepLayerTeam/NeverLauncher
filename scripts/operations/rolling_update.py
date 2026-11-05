#!/usr/bin/env python3
"""Выполнить поэтапное многохостовое обновление API/worker 0.51.6 -> 0.51.7.

Установить скрипт у доверенного оператора И на каждом Docker-хосте. Поместить файл 0600
.env.rolling-target-0517 на каждом хосте, изменив только LAUNCHER_API_IMAGE на независимо
проверенный образ 0.51.7 с закреплённым дайджестом.

Весь процесс оператор удерживает advisory lock сеанса PostgreSQL. Для каждого хоста: проверить
здорового соседа, загрузить целевой образ до нарушения работы, корректно остановить worker/API,
атомарно сменить локальное окружение, пересоздать только локальные worker/API, проверить реальные
версии процессов/Bridge и живой PostgreSQL, затем перейти к следующему хосту. Ingress/Admin данного
хоста не пересоздаются.

Нет миграций, остановки всего кластера, переносов миров/JVM, слепых повторов команд или изменений
общих секретов. Откат возвращает только прежние образы API/worker, но никогда — прежние данные
PostgreSQL.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time

import ha_inventory_0511 as inventory
import multi_host_0512 as multi
import nn1_compat_0516 as nn

SOURCE = "0.51.6"
TARGET = "0.51.7"
PAIR = frozenset((SOURCE, TARGET))
SCHEMA = "neverlauncher.rolling-update.0.51.7"
STAGE = ".env.rolling-target-0517"
BACKUP = ".env.rolling-previous-0517"
STATE = ".rolling-state-0517.json"
LOCK = ".rolling-lock-0517"
MAX_BYTES = 1_000_000

class RollingError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise RollingError(reason)


def secure(path):
    """Только закрытые обычные файлы с одной жёсткой ссылкой; никакие символьные ссылки или устройства."""
    try:
        st = path.lstat()
    except OSError as exc:
        raise RollingError("Отсутствует обязательный закрытый файл: " + path.name) from exc
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
            (stat.S_IMODE(st.st_mode) & 0o077) == 0 and
            0 < st.st_size <= MAX_BYTES,
            "Обязательный файл небезопасен: " + path.name)
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, content):
    """Атомарная замена файла с защитой от сбоев; содержимое никогда не выводится и не передаётся через argv."""
    require(path.parent.is_dir() and not path.parent.is_symlink(), "Недопустимый каталог развёртывания")
    fd, tmp = tempfile.mkstemp(prefix=".rolling-tmp-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        if path.exists() or path.is_symlink():
            secure(path)
        os.replace(tmp, path)
        sync_directory(path.parent)
    finally:
        Path(tmp).unlink(missing_ok=True)


def exclusive_write(path, content):
    require(not path.exists() and not path.is_symlink(), "Резервная копия или состояние переключения требуют проверки оператором")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        sync_directory(path.parent)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def journal(directory, payload):
    atomic_write(directory / STATE, (json.dumps(payload, sort_keys=True) + "\n").encode())


def read_journal(directory):
    path = directory / STATE
    if not path.exists() and not path.is_symlink():
        return None
    try:
        data = json.loads(secure(path))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RollingError("Некорректное значение: «local recovery journal»") from exc
    require(isinstance(data, dict) and data.get("schema") == SCHEMA,
            "Недопустимая схема локального журнала восстановления")
    return data


@contextmanager
def host_lock(directory):
    path = directory / LOCK
    # Стабильный inode файла блокировки; никогда не заменяйте его. Символьные и
    # жёсткие ссылки запрещены.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not (st.st_mode & 0o077),
                "unsafe rolling host lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RollingError("На данном узле уже выполняется последовательная операция") from exc
        yield
    finally:
        os.close(fd)


def rendered(directory, project, env):
    raw = multi.run(multi.compose_command(directory, project, "config", "--format", "json",
                                          env_file=env), cwd=directory, timeout=25)
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise RollingError("Некорректное значение: «rendered Compose JSON»") from exc
    require(isinstance(data, dict) and isinstance(data.get("services"), dict),
            "Недопустимый состав служб Compose")
    return data


def validate_stage(directory, project):
    current_file, target_file = directory / ".env", directory / STAGE
    current = secure(current_file)
    target = secure(target_file)
    st_dir = directory.stat()
    require(not directory.is_symlink() and not (stat.S_IMODE(st_dir.st_mode) & 0o022),
            "Каталог развёртывания не должен быть доступен для записи группе и другим пользователям")
    require(current_file.stat().st_uid == target_file.stat().st_uid,
            "Исходная и подготовленная конфигурации должны иметь одного владельца")
    require(sha(current) != sha(target), "Подготовленный этап совпадает с текущим развёртыванием")
    before = multi.resolved_compose(directory, project)
    after = multi.resolved_compose(directory, project, env_file=target_file)
    require(before["nodeId"] == after["nodeId"] and
            before["machineIdentity"] == after["machineIdentity"] and
            before["sharedEndpoints"] == after["sharedEndpoints"],
            "staged deployment changes node identity or shared dependencies")
    refs_a, refs_b = before["imageDigestRefs"], after["imageDigestRefs"]
    require(refs_a["api"] != refs_b["api"] and refs_a["api"] == refs_a["worker"] and
            refs_b["api"] == refs_b["worker"] and
            all(refs_a[x] == refs_b[x] for x in ("admin", "ingress", "volume-init")),
            "only the API/worker image digest may change")
    a, b = rendered(directory, project, current_file), rendered(directory, project, target_file)
    # Предотвращайте ротацию секретов, обновление других служб и изменение томов,
    # окружения, входного шлюза, проверок здоровья или точек подключения
    # зависимостей.
    changed = []
    for svc in ("api", "worker"):
        if a["services"][svc]["image"] != b["services"][svc]["image"]:
            changed.append(svc)
        b["services"][svc]["image"] = a["services"][svc]["image"]
    require(changed == ["api", "worker"] and a == b,
            "staged Compose config differs beyond the pinned API/worker image")
    return {"nodeId": before["nodeId"], "sourceImage": refs_a["api"],
            "targetImage": refs_b["api"], "sourceHash": sha(current),
            "targetHash": sha(target)}


def live_local(directory, project, version):
    report = multi.local_compat_observe_0516(directory, project)
    require(report["ready"] and report["compatibility0516"]["liveVersion"] == version,
            "Фактическая версия процесса API/обработчика не совпадает с ожидаемой " + version)
    return report


def compose(directory, project, *args, timeout=240, env_file=None):
    return multi.run(multi.compose_command(directory, project, *args, env_file=env_file),
                     cwd=directory, timeout=timeout)


def apply_host(directory, project):
    with host_lock(directory):
        require(read_journal(directory) is None,
                "rolling journal exists; inspect/rollback before another apply")
        plan = validate_stage(directory, project)
        live_local(directory, project, SOURCE)
        previous = secure(directory / ".env")
        target = secure(directory / STAGE)
        # Скачивайте и проверяйте цель по неизменяемой ссылке ДО остановки исходной
        # версии. Никогда не загружайте плавающий тег в промышленной среде.
        compose(directory, project, "pull", "--policy", "always", "api", "worker",
                timeout=420, env_file=directory / STAGE)
        for image in (plan["sourceImage"], plan["targetImage"]):
            multi.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], timeout=25)
        exclusive_write(directory / BACKUP, previous)
        state = {"schema": SCHEMA, **plan, "phase": "prepared"}
        journal(directory, state)
        try:
            state["phase"] = "stopping"
            journal(directory, state)
            compose(directory, project, "stop", "-t", "45", "worker", "api", timeout=120)
            state["phase"] = "switching"
            journal(directory, state)
            require(sha(secure(directory / ".env")) == plan["sourceHash"],
                    "source deployment changed during rollout")
            atomic_write(directory / ".env", target)
            compose(directory, project, "up", "-d", "--no-build", "--no-deps",
                    "--force-recreate", "--wait", "--wait-timeout", "180", "api", "worker", timeout=240)
            live_local(directory, project, TARGET)
            state["phase"] = "applied"
            journal(directory, state)
            return {"schema": SCHEMA, "project": project, "nodeId": plan["nodeId"],
                    "from": SOURCE, "to": TARGET, "ready": True, "phase": "applied",
                    "sourceImage": plan["sourceImage"], "targetImage": plan["targetImage"]}
        except BaseException as error:
            try:
                rollback_host_locked(directory, project, expected=plan)
            except Exception as recovery:
                state["phase"] = "manual-recovery-required"
                journal(directory, state)
                raise RollingError("Не удалось обновить узел и подтвердить прежний процесс; проверьте остановленный узел") from recovery
            raise RollingError("Обновление узла не удалось; прежний образ API/worker восстановлен и проверен") from error


def rollback_host_locked(directory, project, *, expected=None):
    state = read_journal(directory)
    require(state is not None and state.get("phase") in
            ("prepared", "stopping", "switching", "applied", "rolling-back"),
            "Нет подходящего журнала поэтапного обновления для восстановления")
    if expected is not None:
        require(state["sourceHash"] == expected["sourceHash"] and
                state["targetHash"] == expected["targetHash"], "recovery journal changed")
    previous = secure(directory / BACKUP)
    require(sha(previous) == state["sourceHash"], "Предыдущая резервная копия окружения изменилась")
    current = secure(directory / ".env")
    require(sha(current) in (state["sourceHash"], state["targetHash"]),
            "current deployment differs from the pinned rollback images")
    state["phase"] = "rolling-back"
    journal(directory, state)
    compose(directory, project, "stop", "-t", "45", "worker", "api", timeout=120)
    atomic_write(directory / ".env", previous)
    compose(directory, project, "up", "-d", "--no-build", "--no-deps",
            "--force-recreate", "--wait", "--wait-timeout", "180", "api", "worker", timeout=240)
    live_local(directory, project, SOURCE)
    state["phase"] = "rolled-back"
    journal(directory, state)
    return {"schema": SCHEMA, "project": project, "nodeId": state["nodeId"],
            "from": TARGET, "to": SOURCE, "phase": "rolled-back", "ready": True}


def rollback_host(directory, project):
    with host_lock(directory):
        return rollback_host_locked(directory, project)


def host_plan(directory, project):
    with host_lock(directory):
        require(read_journal(directory) is None, "Существующий журнал поэтапного обновления требует проверки оператором")
        result = validate_stage(directory, project)
        live_local(directory, project, SOURCE)
        return {"schema": SCHEMA, "project": project, "nodeId": result["nodeId"],
                "from": SOURCE, "to": TARGET, "phase": "planned", "ready": True,
                "sourceImage": result["sourceImage"], "targetImage": result["targetImage"]}


def remote(target, script, directory, project, operation, *, timeout=540):
    require(multi.HOST_REGEX.fullmatch(target) and not target.startswith("-"), "Недопустимый целевой узел SSH")
    require(script.startswith("/") and directory.startswith("/") and
            all("\n" not in p and "\r" not in p for p in (script, directory)),
            "Недопустимый удалённый скрипт или путь")
    cmd_args = ["python3", script, operation, "--directory", directory,
                "--project", project, "--output", "-"]
    if operation in ("local-apply", "local-rollback"):
        cmd_args.append("--allow-update")
    cmd = shlex.join(cmd_args)
    raw = multi.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                     "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=0",
                     target, cmd], timeout=timeout)
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RollingError("Удалённый агент сформировал некорректный JSON") from exc
    require(result.get("schema") == SCHEMA and result.get("project") == project and
            result.get("ready") is True, "remote update operation did not report successful readiness")
    return result


class PGAdvisoryLock:
    """Одна PostgreSQL advisory lock на время сеанса для всех операций SSH."""
    def __init__(self, dsn_file):
        self.dsn_file = dsn_file
        self.process = None

    def _query(self, sql):
        require(self.process and self.process.poll() is None, "Завершился сеанс блокировки PostgreSQL для поэтапного обновления")
        try:
            self.process.stdin.write(sql + "\n")
            self.process.stdin.flush()
            ready, _, _ = select.select([self.process.stdout], [], [], 10)
            require(bool(ready), "Истекло время ожидания соединения для блокировки PostgreSQL")
            return self.process.stdout.readline().strip()
        except (OSError, ValueError, BrokenPipeError) as exc:
            raise RollingError("Ошибка: «PostgreSQL rolling lock connection»") from exc

    def __enter__(self):
        env = nn.dsn_environment(self.dsn_file)
        try:
            self.process = subprocess.Popen(
                ["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1"],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1)
            require(self._query("SELECT CASE WHEN pg_try_advisory_lock(1717, 51517) "
                                "THEN 'LOCKED' ELSE 'BUSY' END;") == "LOCKED",
                    "another rolling update holds the PostgreSQL cluster lock")
            self.ping()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def ping(self):
        require(self._query("SELECT 'ALIVE';") == "ALIVE",
                "Ошибка подтверждения активности блокировки поэтапного обновления кластера PostgreSQL")

    def __exit__(self, *_):
        if self.process:
            try:
                if self.process.poll() is None:
                    self.process.stdin.close()
                    self.process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=3)


class EdgeMonitor:
    """Во время переключения локального хоста наблюдать внешний TLS-эндпоинт /ready."""
    def __init__(self, url):
        self.url = url
        self.stop = threading.Event()
        self.samples = 0
        self.failures = 0
        self.worker = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                good, _ = multi.edge_ready(self.url, count=1)
            except Exception:
                good = False
            self.samples += 1
            if not good:
                self.failures += 1
            self.stop.wait(1)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.worker.join(timeout=10)

    def assert_continuity(self):
        require(self.samples >= 2 and self.failures == 0,
                "Во время переключения узла публичный HTTPS-шлюз был недоступен или недостаточно проверен")


def observe(nodes, script, directory, project):
    reports = {label: multi.remote_call(target, script, directory, project,
                                        "local-compat-observe", timeout=200)
               for label, target in nodes.items()}
    versions = nn.validate_live_nodes(reports, pair=PAIR)
    return reports, versions


def assert_image_cohorts(reports, versions):
    # Дайджест backend может различаться у старого и целевого выпуска, но каждая
    # группа должна использовать ОДИН неизменяемый образ; службы, отличные от
    # backend, остаются одинаковыми.
    for svc in ("admin", "ingress", "volume-init"):
        require(len({r["imageDigestRefs"].get(svc) for r in reports.values()}) == 1,
                "hosts do not agree on pinned " + svc + " image")
    for version in PAIR:
        images = {reports[node]["imageDigestRefs"]["api"] for node in versions
                  if versions[node] == version}
        require(len(images) <= 1, "different backend digests claimed to be the same version")


def verify_cluster(nodes, script, directory, project, edge_url, catalog):
    reports, versions = observe(nodes, script, directory, project)
    assert_image_cohorts(reports, versions)
    nn.validate_schema(nn.live_pg_migrations(catalog["dsn"]), catalog["versions"])
    ready, _ = multi.edge_ready(edge_url)
    require(ready, "Публичный HTTPS-балансировщик нагрузки не прошёл проверку готовности")
    return reports, versions


def rollout(args):
    nodes = multi.parse_nodes(args.node)
    multi.validate_edge_url(args.edge_url)
    catalog_versions, sha256 = nn.migration_catalog()
    catalog = {"versions": catalog_versions, "dsn": args.pg_dsn_file}
    event = {"schema": SCHEMA, "from": SOURCE, "to": TARGET, "project": args.project,
             "migrationCatalogSHA256": sha256, "steps": [], "verified": False}
    with PGAdvisoryLock(args.pg_dsn_file) as lock:
        reports, versions = verify_cluster(nodes, args.remote_script, args.directory,
                                           args.project, args.edge_url, catalog)
        event["initialVersions"] = versions.copy()
        require(set(versions.values()) <= PAIR, "Неподдерживаемая исходная версия кластера")
        # До изменения первого хоста выполните предварительную проверку КАЖДОЙ
        # подготовленной цели. Несовпадающий дайджест или неподготовленный узел
        # нельзя обнаруживать уже после изменения первой ноды.
        expected_targets = set()
        initial_plans = {}
        for label, target in nodes.items():
            if versions[label] == TARGET:
                expected_targets.add(reports[label]["imageDigestRefs"]["api"])
                continue
            plan = remote(target, args.rolling_script, args.directory, args.project,
                          "local-plan", timeout=240)
            require(plan["nodeId"] == reports[label]["nodeId"] and
                    plan["sourceImage"] == reports[label]["imageDigestRefs"]["api"] and
                    plan["to"] == TARGET and multi.DIGEST_REGEX.fullmatch(plan["targetImage"]),
                    "unverified staged target image on " + label)
            expected_targets.add(plan["targetImage"])
            initial_plans[label] = plan
        require(len(expected_targets) == 1, "Узлы не согласовали единую целевую контрольную сумму OCI")
        for label, target in nodes.items():
            if versions[label] == TARGET:
                continue   # безопасное повторное выполнение после ранее частично завершённого развёртывания
            lock.ping()
            require(all(reports[n]["ready"] for n in nodes if n != label),
                    "Не осталось независимого исправного узла")
            planned = remote(target, args.rolling_script, args.directory, args.project,
                             "local-plan", timeout=240)
            require(planned == initial_plans[label] and
                    planned["nodeId"] == reports[label]["nodeId"] and
                    planned["sourceImage"] == reports[label]["imageDigestRefs"]["api"] and
                    planned["to"] == TARGET, "node stage changed since cluster-wide preflight")
            with EdgeMonitor(args.edge_url) as monitor:
                try:
                    result = remote(target, args.rolling_script, args.directory, args.project,
                                    "local-apply", timeout=600)
                except Exception as error:
                    # Локальный агент пытается выполнить откат при сбое. Прерванная SSH-сессия
                    # может оставить журнал, требующий явного восстановления.
                    raise RollingError("Развёртывание узла не завершено; проверьте локальный журнал") from error
            try:
                require(result["nodeId"] == planned["nodeId"] and
                        result["targetImage"] == planned["targetImage"] and
                        result["from"] == SOURCE and result["to"] == TARGET,
                        "Узел вернул неожиданную квитанцию развёртывания")
                monitor.assert_continuity()
                reports, versions = verify_cluster(nodes, args.remote_script, args.directory,
                                                   args.project, args.edge_url, catalog)
                require(versions[label] == TARGET and all(v in PAIR for v in versions.values()),
                        "Несовпадение версий после переключения")
            except Exception as error:
                try:
                    lock.ping()
                    rolled = remote(target, args.rolling_script, args.directory, args.project,
                                    "local-rollback", timeout=600)
                    require(rolled["phase"] == "rolled-back", "Откат не подтверждён")
                    reports, versions = verify_cluster(nodes, args.remote_script,
                                                       args.directory, args.project, args.edge_url, catalog)
                    require(versions[label] == SOURCE, "Фактическая версия после отката не совпадает с ожидаемой")
                except Exception as recovery:
                    raise RollingError("Проверка после переключения не пройдена, успешность отката не подтверждена") from recovery
                raise RollingError("Проверка после переключения не пройдена; затронутый узел восстановлен") from error
            event["steps"].append({"nodeId": result["nodeId"], "from": SOURCE,
                                   "to": TARGET, "edgeSamples": monitor.samples,
                                   "edgeFailures": monitor.failures, "verified": True})
        lock.ping()
        _, final_versions = verify_cluster(nodes, args.remote_script, args.directory,
                                           args.project, args.edge_url, catalog)
        require(set(final_versions.values()) == {TARGET}, "После поэтапного обновления остались активными старые исполняемые файлы")
        event["finalVersions"] = final_versions
        event["verified"] = True
    return event


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=("local-plan", "local-apply", "local-rollback", "cluster-roll"))
    ap.add_argument("--directory", default="/opt/launcher/deploy/production")
    ap.add_argument("--project", default="launcher")
    ap.add_argument("--node", action="append", default=[])
    ap.add_argument("--remote-script", default="/opt/launcher/scripts/operations/multi_host_0512.py")
    ap.add_argument("--rolling-script", default="/opt/launcher/scripts/operations/rolling_update_0517.py")
    ap.add_argument("--pg-dsn-file", type=Path)
    ap.add_argument("--edge-url")
    ap.add_argument("--allow-update", action="store_true")
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)
    try:
        require(Path(args.directory).is_absolute() and multi.PROJECT_REGEX.fullmatch(args.project),
                "Недопустимый абсолютный путь развёртывания или проект")
        if args.action == "cluster-roll":
            require(args.allow_update and args.pg_dsn_file and args.edge_url,
                    "cluster-roll requires --allow-update --pg-dsn-file --edge-url")
            result = rollout(args)
        else:
            directory = Path(args.directory)
            require(directory.is_dir() and not directory.is_symlink(), "Каталог развёртывания отсутствует")
            if args.action == "local-plan":
                result = host_plan(directory, args.project)
            elif args.action == "local-apply":
                require(args.allow_update, "Для local-apply требуется --allow-update")
                result = apply_host(directory, args.project)
            else:
                require(args.allow_update, "Для local-rollback требуется --allow-update")
                result = rollback_host(directory, args.project)
        inventory.write_report(args.output, result)
        return 0
    except (RollingError, multi.DeploymentError, nn.CompatibilityError,
            inventory.InventoryError, OSError, ValueError) as exc:
        print("Последовательное обновление ЗАБЛОКИРОВАНО: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
