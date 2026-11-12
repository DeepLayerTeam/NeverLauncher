#!/usr/bin/env python3
"""Реальная инъекция сбоев на Docker для изолированных лабораторий Launcher Network-HA.

Используются работающие PostgreSQL и S3, фиксируются подтверждённые устойчивые canary, прерываются
настоящие зависимости и сеть одного worker, затем проверяется восстановление. Производственный SLA
не выводится из синтетических canary. Не запускается в неизолированном проекте Compose или на
непроверенном S3-эндпоинте.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import dr as dr

SERVICES = ("postgres", "redis", "s3", "api", "api-b", "worker-a", "worker-b", "nginx")
REPLICA = ("api", "api-b", "worker-a", "worker-b")
KEY_PREFIX = "launcher-chaos-0456/"


def monotonic() -> float:
    return time.monotonic()


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_scope(project: str, confirm: str, env_file: Path, ready_url: str, s3_url: str, bucket: str) -> None:
    dr.ensure_isolated(project, confirm)
    if not env_file.is_file() or env_file.is_symlink():
        raise dr.DrillError("Требуется обычный файл окружения Compose")
    if (env_file.stat().st_mode & 0o077) != 0:
        raise dr.DrillError("Файл окружения Compose должен иметь права 0600 или более строгие")
    if not re.fullmatch(r"nl-dr-[a-z0-9][a-z0-9-]{0,50}", bucket):
        raise dr.DrillError("Для S3 требуется изолированный бакет с именем nl-dr-*")
    parsed = urlsplit(s3_url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise dr.DrillError("Тестовый адрес S3 должен явно содержать порт HTTP на IPv4 loopback")
    dr.validate_ready_url(ready_url)
    # Публичная HTTPS-точка может быть не loopback. Не принимайте производственный DNS как
    # доказательство: локальный вход лаборатории должен явно привязываться к loopback.
    rp = urlsplit(ready_url)
    if rp.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise dr.DrillError("Публичная проверка готовности в chaos-тесте должна использовать loopback")
    if rp.scheme != "https":
        raise dr.DrillError("Для проверки готовности HA требуется HTTPS с доверенным сертификатом")
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        raise dr.DrillError("Для изолированного S3 задайте AWS_ACCESS_KEY_ID и AWS_SECRET_ACCESS_KEY")
    if dotenv_value(env_file, "LAUNCHER_STORAGE_S3_BUCKET") != bucket:
        raise dr.DrillError("Корзина S3 должна совпадать с конфигурацией изолированного Compose")
    if (dotenv_value(env_file, "LAUNCHER_STORAGE_S3_ACCESS_KEY") != os.environ.get("AWS_ACCESS_KEY_ID")
            or dotenv_value(env_file, "LAUNCHER_STORAGE_S3_SECRET_KEY") != os.environ.get("AWS_SECRET_ACCESS_KEY")):
        raise dr.DrillError("Учётные данные AWS CLI должны соответствовать секретам изолированного тестового MinIO")


def dotenv_value(path: Path, key: str) -> str | None:
    value = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, raw = line.split("=", 1)
        if name.strip() == key:
            if value is not None:
                raise dr.DrillError("Повторяется обязательная переменная тестового окружения:" + key)
            value = raw.strip().strip("\"").strip("'")
    return value


def configure_compose() -> None:
    dr.COMPOSE_FILES[:] = [dr.COMPOSE, dr.ROOT / "deploy/production/docker-compose.network-ha.yml",
                          dr.ROOT / "deploy/production/docker-compose.chaos.yml"]
    dr.COMPOSE_PROFILES[:] = ["network-ha"]


def check_lab_endpoint(project: str, env_file: Path, endpoint: str) -> None:
    # Избегайте постороннего локального туннеля S3 или production оператора: проверяйте, что
    # порт действительно принадлежит s3-контейнеру Compose этого стенда.
    s3_id = container_id(project, env_file, "s3")
    raw = dr.run(["docker", "port", s3_id, "9000/tcp"], timeout=20).stdout.decode().strip()
    actual = {line.strip() for line in raw.splitlines()}
    expected = "127.0.0.1:" + str(urlsplit(endpoint).port)
    if actual != {expected}:
        raise dr.DrillError("Эндпоинт S3 не использует локальный порт изолированного Compose S3")


def check_services(project: str, env_file: Path) -> None:
    states = dr.compose_states(project, env_file)
    for service in SERVICES:
        if states.get(service) != "running":
            raise dr.DrillError(f"Не запущена обязательная изолированная лабораторная служба: {service}")
    for service in REPLICA:
        dr.check_restored_backend(project, env_file, version=None, storage="s3", service=service,
                                  timeout=5) if service.startswith("api") else dr.check_restored_worker_0455(project, env_file, service, timeout=5)


def pg_sql(project: str, env_file: Path, statement: str) -> str:
    # SQL постоянен кроме canary-значений, генерируемых внутри; значения
    # ограничены строчным hex, не SQL и shell от оператора.
    result = dr.compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec",
        'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -X -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        stdin=io.BytesIO(statement.encode("ascii")), timeout=35)
    return result.stdout.decode("utf-8", errors="strict").strip()


def pg_write(project: str, env_file: Path, token: str, payload_hash: str) -> None:
    if not (re.fullmatch(r"[0-9a-f]{32}", token) and re.fullmatch(r"[0-9a-f]{64}", payload_hash)):
        raise dr.DrillError("Некорректный внутренний контрольный маркер PostgreSQL")
    sql = ("CREATE TABLE IF NOT EXISTS launcher_chaos_canaries_0456 "
           "(token text PRIMARY KEY, payload_sha256 text NOT NULL, acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp());\n"
           f"INSERT INTO launcher_chaos_canaries_0456(token,payload_sha256) VALUES ('{token}','{payload_hash}');\n")
    pg_sql(project, env_file, sql)
    pg_verify(project, env_file, token, payload_hash)


def pg_verify(project: str, env_file: Path, token: str, payload_hash: str) -> None:
    result = pg_sql(project, env_file,
                    f"SELECT payload_sha256 FROM launcher_chaos_canaries_0456 WHERE token='{token}';\n")
    if result != payload_hash:
        raise dr.DrillError("Подтверждённый контрольный маркер PostgreSQL отсутствует или был изменён")


def s3_call(endpoint: str, *args: str, timeout: int = 20) -> bytes:
    return dr.run(["aws", "--endpoint-url", endpoint, "--no-cli-pager", "s3api", *args],
                  timeout=timeout).stdout


def s3_prepare(endpoint: str, bucket: str, key: str, data: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="nl-chaos-payload-") as folder:
        src = Path(folder) / "payload"
        src.write_bytes(data)
        s3_call(endpoint, "put-object", "--bucket", bucket, "--key", key, "--body", str(src), timeout=30)
    return s3_verify(endpoint, bucket, key, hashlib.sha256(data).hexdigest())


def s3_verify(endpoint: str, bucket: str, key: str, expected_hash: str) -> str:
    with tempfile.TemporaryDirectory(prefix="nl-chaos-recovered-") as folder:
        dest = Path(folder) / "data"
        s3_call(endpoint, "get-object", "--bucket", bucket, "--key", key, str(dest), timeout=30)
        received = dr.sha256_file(dest)
        if received != expected_hash:
            raise dr.DrillError("Подтверждённый объект S3 отсутствует или был изменён")
        return received


def s3_delete(endpoint: str, bucket: str, key: str) -> None:
    s3_call(endpoint, "delete-object", "--bucket", bucket, "--key", key)


def poll(check, expected: bool, limit: float, name: str) -> float:
    start = monotonic()
    while monotonic() - start < limit:
        try:
            if bool(check()) == expected:
                return round(monotonic() - start, 3)
        except (dr.DrillError, OSError, subprocess.TimeoutExpired):
            if not expected:
                return round(monotonic() - start, 3)
        time.sleep(0.5)
    raise dr.DrillError(f"{name} не достиг состояния {'работоспособен' if expected else 'сбой'} за {limit} с")


def public_ready(url: str) -> bool:
    return dr.ready(url, expected_storage="s3")


def direct_ready(project: str, env_file: Path, service: str) -> bool:
    try:
        raw = dr.compose(project, env_file, "exec", "-T", service, "wget", "-qO-",
                         "http://127.0.0.1:8080/ready", timeout=10).stdout
        payload = json.loads(raw)
        return payload.get("status") == "ready" and payload.get("repository") == "postgres" and payload.get("storage") == "s3"
    except (dr.DrillError, ValueError, OSError, subprocess.TimeoutExpired):
        return False


def container_id(project: str, env_file: Path, service: str) -> str:
    ident = dr.compose(project, env_file, "ps", "-q", service, timeout=20).stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", ident):
        raise dr.DrillError("Не удалось определить изолированный контейнер " + service)
    return ident


def lab_network(project: str, ident: str) -> str:
    raw = dr.run(["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", ident], timeout=20).stdout
    networks = json.loads(raw)
    matched = [name for name in networks if name == project + "_launcher"]
    if len(matched) != 1:
        raise dr.DrillError("Рабочий процесс не подключён к ожидаемой изолированной сети Compose")
    return matched[0]


def dependency_fault(project: str, env_file: Path, service: str, url: str, endpoint: str,
                     bucket: str, key: str, digest: str, token: str, pg_digest: str,
                     limit: float) -> dict:
    # Используйте настоящий отказ службы, а не имитации endpoints. Успешный /ready при сбое
    # зависимости означает нарушение защитной политики готовности.
    start = monotonic()
    event_started = stamp()
    fault_detected = None
    try:
        dr.compose(project, env_file, "stop", "-t", "3", service, timeout=45)
        if service == "s3":
            # Одной проверки health недостаточно для доказательства отказа S3.
            fault_detected = poll(lambda: s3_verify(endpoint, bucket, key, digest) == digest,
                                  False, limit, "Ошибка чтения объекта S3")
        else:
            fault_detected = poll(lambda: public_ready(url), False, limit, "запрет готовности при ошибке")
    finally:
        dr.compose(project, env_file, "up", "-d", service, timeout=90)
    recovered_s = poll(lambda: public_ready(url), True, limit, "Восстановление готовности публичного сервиса")
    poll(lambda: pg_verify(project, env_file, token, pg_digest) is None,
         True, limit, "Проверочный запрос PostgreSQL после восстановления")
    poll(lambda: s3_verify(endpoint, bucket, key, digest) == digest,
         True, limit, "Проверочный запрос S3 после восстановления")
    total = monotonic() - start
    return {"fault": service + "-stopped", "startedUtc": event_started, "restoredUtc": stamp(), "failureObservedSeconds": fault_detected,
            "readinessRecoverySeconds": recovered_s, "endToEndRecoverySeconds": round(total, 3),
            "rtoSeconds": round(total, 3), "rpoSecondsObservedCanaries": 0,
            "acknowledgedPostgresPreserved": True, "acknowledgedS3Preserved": True}


def api_failover(project: str, env_file: Path, url: str, limit: float) -> dict:
    started = monotonic()
    event_started = stamp()
    try:
        dr.compose(project, env_file, "stop", "-t", "3", "api", timeout=45)
        poll(lambda: direct_ready(project, env_file, "api-b"), True, limit, "оставшийся доступным API")
        poll(lambda: public_ready(url), True, limit, "Переключение API через Nginx")
        failover = monotonic() - started
    finally:
        dr.compose(project, env_file, "up", "-d", "api", timeout=90)
    poll(lambda: direct_ready(project, env_file, "api"), True, limit, "перезапущенный API")
    return {"fault": "api-stopped", "startedUtc": event_started, "restoredUtc": stamp(), "failoverSeconds": round(failover, 3),
            "rtoSeconds": round(failover, 3), "serviceSurvived": True}


def network_fault(project: str, env_file: Path, url: str, limit: float) -> dict:
    ident = container_id(project, env_file, "worker-a")
    network = lab_network(project, ident)
    started = monotonic()
    event_started = stamp()
    disconnected = False
    try:
        dr.run(["docker", "network", "disconnect", "--force", network, ident], timeout=30)
        disconnected = True
        failure_time = poll(lambda: direct_ready(project, env_file, "worker-a"), False,
                            limit, "Готовность изолированного обработчика")
        poll(lambda: direct_ready(project, env_file, "worker-b"), True,
             limit, "Готовность оставшегося обработчика")
        poll(lambda: public_ready(url), True, limit, "Доступность оставшегося API")
    finally:
        if disconnected:
            dr.run(["docker", "network", "connect", network, ident], timeout=30)
    poll(lambda: direct_ready(project, env_file, "worker-a"), True, limit, "Готовность повторно подключённого обработчика")
    return {"fault": "worker-a-network-partition", "startedUtc": event_started, "restoredUtc": stamp(), "failureObservedSeconds": failure_time,
            "rtoSeconds": round(monotonic() - started, 3), "survivingWorkerReady": True}


def run_experiment(project: str, env_file: Path, ready_url: str, s3_url: str, bucket: str,
                   limit: float, report: Path) -> dict:
    if report.exists() or report.is_symlink():
        raise dr.DrillError("Файл отчёта уже существует; перезапись запрещена")
    if not report.parent.is_dir() or report.parent.is_symlink():
        raise dr.DrillError("Родительский каталог отчёта должен существовать и не быть символической ссылкой")
    check_services(project, env_file)
    check_lab_endpoint(project, env_file, s3_url)
    poll(lambda: public_ready(ready_url), True, limit, "Первоначальная готовность высокой доступности")
    token = secrets.token_hex(16)
    payload = secrets.token_bytes(64)
    digest = hashlib.sha256(payload).hexdigest()
    key = KEY_PREFIX + token
    outcomes = []
    wrote_s3 = False
    start = monotonic()
    try:
        pg_write(project, env_file, token, digest)
        wrote_s3 = True  # после успешного PUT и неудачного чтения результата всё равно требуется очистка
        s3_prepare(s3_url, bucket, key, payload)
        for service in ("postgres", "redis", "s3"):
            outcomes.append(dependency_fault(project, env_file, service, ready_url, s3_url, bucket,
                                             key, digest, token, digest, limit))
        outcomes.append(api_failover(project, env_file, ready_url, limit))
        outcomes.append(network_fault(project, env_file, ready_url, limit))
        # Повторно считывайте подтверждённые данные после ВСЕХ сбоев, а не только после каждого по отдельности.
        pg_verify(project, env_file, token, digest)
        s3_verify(s3_url, bucket, key, digest)
        result = {"schema": 1, "release": (dr.ROOT / "VERSION").read_text().strip(),
                  "status": "passed", "runId": token, "recordedUtc": stamp(),
                  "mode": "isolated-network-ha", "project": project,
                  "scope": "Подтверждены тестовая строка PostgreSQL и объект S3; это не гарантирует промышленный RPO/SLA",
                  "observedRpoSeconds": 0, "rtoSecondsMax": max(e["rtoSeconds"] for e in outcomes),
                  "durationSeconds": round(monotonic() - start, 3), "events": outcomes,
                  "limits": ["Лабораторное окружение на одном узле Docker; потеря узла не проверялась", "Нет подтверждения для реальных сеансов Minecraft или блокировки заданий",
                             "RPO оценён только по проверочным запросам; неподтверждённые изменения не измерялись"]}
        # Атомарная публикация. Не сообщайте об успехе, если запись или любая
        # операция внедрения отказа завершилась ошибкой.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=report.parent,
                                         prefix=".chaos-0456-", suffix=".tmp", delete=False) as handle:
            staging = Path(handle.name)
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        try:
            if report.exists() or report.is_symlink():
                raise dr.DrillError("Путь отчёта появился во время эксперимента")
            staging.rename(report)
        finally:
            if staging.exists(): staging.unlink()
        return result
    finally:
        if wrote_s3:
            try:
                s3_delete(s3_url, bucket, key)
            except (dr.DrillError, OSError, subprocess.TimeoutExpired):
                # Не скрывайте основную ошибку; оставьте точный ключ для очистки оператором.
                print("Предупреждение: не удалось удалить тестовый объект S3; ключ: " + key, file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--ready-url", required=True,
                        help="Доверенный HTTPS URL готовности на loopback изолированного ingress")
    parser.add_argument("--s3-endpoint", required=True, help="Лабораторный S3-эндпоинт loopback, например http://127.0.0.1:19000")
    parser.add_argument("--s3-bucket", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        check_scope(args.project, args.confirm, args.env_file, args.ready_url, args.s3_endpoint, args.s3_bucket)
        if not 20 <= args.timeout <= 300:
            raise dr.DrillError("Тайм-аут должен составлять от 20 до 300 секунд")
        configure_compose()
        result = run_experiment(args.project, args.env_file, args.ready_url, args.s3_endpoint,
                                args.s3_bucket, args.timeout, args.report)
        print(json.dumps({"status": "passed", "report": str(args.report), "rpoCanaries": result["observedRpoSeconds"],
                          "maxRtoSeconds": result["rtoSecondsMax"]}))
        return 0
    except (dr.DrillError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)[:240]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
