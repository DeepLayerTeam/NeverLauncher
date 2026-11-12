#!/usr/bin/env python3
"""Launcher 0.51.1: инвентаризация *живого* HA и аудит доменов отказа только для чтения.

Требуется Docker на каждом проверяемом хосте и необязательно SSH для удалённых. Контейнеры, БД,
аренды и файлы установки никогда не меняются. Для диагностики масштабирования используются настоящие
проверки advisory lock PG, аренды Redis и обратной записи S3 (создаются и удаляются уникальные
временные объекты). Секреты, блоки окружения Docker, исходные журналы и учётные данные URL не
экспортируются.

Это базовый *детектор*, а не сертификат физического HA или безопасности разделения сети.
Неопределённые свидетельства явно UNVERIFIED, но не PASS.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request

VERSION = "0.51.1"
COMPONENTS = ("api", "worker", "admin", "nginx", "postgres", "redis")
CRITICAL_ROLES = ("api", "worker")
MAX_OUTPUT = 4 * 1024 * 1024
PROJECT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
LABEL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
SSH_RE = re.compile(r"^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*@)?[a-zA-Z0-9][a-zA-Z0-9.\-]*$")
TARGETS = (
    "/var/lib/launcher/storage", "/var/lib/launcher/backups",
    "/var/lib/launcher/factory", "/var/lib/launcher/coordinator",
    "/var/lib/launcher/extensions", "/app/extensions",
)
# Только имена. Значения никогда не записываются ни в отчёт, ни в исключение.
VISIBLE_ENV = frozenset((
    "LAUNCHER_DEPLOYMENT_MODE", "LAUNCHER_PROCESS_ROLE", "LAUNCHER_REPLICA_ID",
    "LAUNCHER_REPOSITORY_DRIVER", "LAUNCHER_SQL_DRIVER",
    "LAUNCHER_DATABASE_AUTO_MIGRATE", "LAUNCHER_STORAGE_DRIVER",
    "LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "LAUNCHER_RATE_LIMIT_ENABLED",
    "LAUNCHER_RATE_LIMIT_FAIL_CLOSED", "LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH",
))
ENDPOINT_ENV = ("LAUNCHER_DATABASE_DSN", "LAUNCHER_REDIS_URL", "LAUNCHER_STORAGE_S3_ENDPOINT")
SENSITIVE_ENV = re.compile(r"(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|CLIENT_SECRET|API_KEY|CREDENTIAL|AUTH_KEY)")


class InventoryError(Exception):
    pass


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def execute(argv, timeout=12, allowed_codes=(0,)):
    """Все аргументы argv задаются явно; не использовать оболочку подпроцесса и не включать stdout/stderr в ошибки."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("Команда недоступна или истекло время ожидания: " + str(argv[0])) from exc
    if proc.returncode not in allowed_codes:
        raise InventoryError("Команда завершилась ошибкой: " + str(argv[0]) + " (exit " + str(proc.returncode) + ")")
    if len(proc.stdout) > MAX_OUTPUT:
        raise InventoryError("Вывод команды превышает установленный лимит инвентаризации")
    return proc.stdout.decode("utf-8", errors="replace")


def fingerprint(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:20]


def machine_identity():
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(candidate).read_text(encoding="ascii").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", value) and value != "0" * 32:
                return "machine:" + fingerprint(value)
        except OSError:
            pass
    return None


def hostname_from_endpoint(raw):
    # Возвращается только хост; userinfo, путь, имя БД, запрос и секрет не
    # выходят из функции. DSN libpq в формате ключей также не раскрываются.
    try:
        parsed = urlsplit(raw.strip())
        if parsed.scheme and parsed.hostname:
            return parsed.hostname.lower()
    except ValueError:
        pass
    if raw.strip().startswith("host="):
        match = re.search(r"(?:^|\s)host=([a-zA-Z0-9_.-]+)(?:\s|$)", raw)
        if match:
            return match.group(1).lower()
    return None


def safe_environment(entries):
    env = {}
    for entry in entries or []:
        key, sep, value = str(entry).partition("=")
        if sep and key not in env:
            env[key] = value
    result = {key: env[key] for key in VISIBLE_ENV if key in env}
    for key in ENDPOINT_ENV:
        if env.get(key):
            result[key + "_HOST"] = hostname_from_endpoint(env[key]) or "unparseable"
    return result, sorted(k for k, v in env.items() if SENSITIVE_ENV.search(k) and bool(v))


def docker_ids(project):
    raw = execute(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=" + project,
                   "--format", "{{.ID}}"])
    ids = [x.strip() for x in raw.splitlines() if re.fullmatch(r"[0-9a-f]{12,64}", x.strip())]
    if len(ids) > 100:
        raise InventoryError("Слишком много контейнеров; укажите более узкий Docker-проект")
    return ids


def docker_inspect(ids):
    if not ids:
        return []
    try:
        data = json.loads(execute(["docker", "inspect", *ids], timeout=20))
    except (ValueError, TypeError) as exc:
        raise InventoryError("Команда Docker inspect вернула некорректный JSON") from exc
    if not isinstance(data, list) or len(data) != len(ids):
        raise InventoryError("Ответ Docker inspect не соответствует запрошенным контейнерам")
    return data


def classify_container(raw, project):
    cfg = raw.get("Config") or {}
    labels = cfg.get("Labels") or {}
    if labels.get("com.docker.compose.project") != project:
        raise InventoryError("Проект в ответе Docker inspect не совпадает с ожидаемым")
    service = labels.get("com.docker.compose.service") or "unknown"
    env, exposed_names = safe_environment(cfg.get("Env") or [])
    state = raw.get("State") or {}
    mounts = []
    for mount in raw.get("Mounts") or []:
        target = str(mount.get("Destination") or "")
        if any(target == p or target.startswith(p + "/") for p in TARGETS):
            mounts.append({"destination": target, "type": mount.get("Type"),
                           "volume": mount.get("Name") if mount.get("Type") == "volume" else None,
                           "writable": bool(mount.get("RW"))})
    health = (state.get("Health") or {}).get("Status") or "not-configured"
    return {"service": service, "containerId": str(raw.get("Id") or "")[:12],
            "imageId": str(raw.get("Image") or ""),
            "running": state.get("Running") is True,
            "health": health, "networkMode": (raw.get("HostConfig") or {}).get("NetworkMode"),
            "environment": env, "secretsPresentInDockerEnvironment": exposed_names,
            "writableDataMounts": mounts}


def docker_ready(container_id, count):
    """Проверять настоящую готовность HTTP с сохранением версии бинарного файла для допусков смешанных выпусков.

    Старые формы ответа остаются наблюдаемыми, но не подходят для совместимости N/N-1. Версия должна
    поступать от работающего процесса, а не из тегов образа, окружения Compose, локального
    VERSION-файла или проверки только статуса.
    """
    durations = []
    failures = 0
    versions = []
    for _ in range(count):
        start = time.monotonic_ns()
        try:
            raw = execute(["docker", "exec", container_id, "wget", "-qO-", "-T", "5",
                           "http://127.0.0.1:8080/ready"], timeout=8)
            # Надёжной версией программы считается только JSON backend вида
            # {status:"ready",version:"..."}. Никогда не определяйте её по предположению.
            try:
                body = json.loads(raw)
            except (ValueError, TypeError):
                body = None
            if isinstance(body, dict) and body.get("status") == "ready" and isinstance(body.get("version"), str):
                versions.append(body["version"])
            durations.append((time.monotonic_ns() - start) / 1_000_000)
        except InventoryError:
            failures += 1
    stable = bool(versions) and len(versions) == len(durations) and len(set(versions)) == 1
    return {"sampled": count, "success": len(durations), "failures": failures,
            "version": versions[0] if stable else None,
            "versionVerified": stable and failures == 0,
            "p50Ms": round(statistics.median(durations), 3) if durations else None,
            "p95Ms": round(sorted(durations)[math.ceil(len(durations) * .95) - 1], 3) if durations else None}


def docker_growth(container_id):
    try:
        result = json.loads(execute(["docker", "exec", container_id, "launcher-api",
                                     "diagnose", "growth"], timeout=50))
        if not isinstance(result, dict):
            return {"verified": False, "failure": "growth_probe_invalid_reply"}
        checks = result.get("checks") or {}
        if not isinstance(checks, dict):
            return {"verified": False, "failure": "growth_probe_invalid_checks"}
        if not result.get("verified"):
            return {"verified": False, "failure": "growth_probe_rejected"}
        return {"verified": True, "postgresql": checks.get("postgresql") is True,
                "redisLease": checks.get("redisLease") is True,
                "s3RoundTrip": checks.get("s3RoundTrip") is True}
    except (ValueError, InventoryError, TypeError):
        return {"verified": False, "failure": "growth_probe_unavailable_or_failed"}


PG_QUERY = ("SELECT json_build_object("
            "'inRecovery',pg_is_in_recovery(),"
            "'synchronousStandbyConfigured',btrim(current_setting('synchronous_standby_names')) <> '',"
            "'synchronousCommit',current_setting('synchronous_commit'),"
            "'replicationPeers',(SELECT count(*) FROM pg_stat_replication),"
            "'synchronousPeers',(SELECT count(*) FROM pg_stat_replication "
            "WHERE sync_state IN ('sync','quorum')))")


def probe_postgres(container_id):
    command = ("PGPASSWORD=\"${POSTGRES_PASSWORD:-}\" exec psql -X -A -t "
               "-U \"${POSTGRES_USER:-postgres}\" -d \"${POSTGRES_DB:-postgres}\" "
               "-c " + shlex.quote(PG_QUERY))
    try:
        data = json.loads(execute(["docker", "exec", container_id, "sh", "-ec", command], timeout=12).strip())
        if not isinstance(data, dict) or not isinstance(data.get("inRecovery"), bool):
            raise ValueError("Неожиданное значение: состояние PostgreSQL")
        return {"observed": True, **data}
    except (InventoryError, ValueError, TypeError):
        return {"observed": False}


def probe_redis(container_id):
    command = ('exec redis-cli -a "${REDIS_PASSWORD:-}" --no-auth-warning INFO replication')
    try:
        raw = execute(["docker", "exec", container_id, "sh", "-ec", command], timeout=12)
        status = {}
        for line in raw.splitlines():
            key, sep, value = line.rstrip("\r").partition(":")
            if sep and key in ("role", "connected_slaves", "master_link_status"):
                status[key] = value.strip()
        if status.get("role") not in ("master", "slave"):
            return {"observed": False}
        return {"observed": True, "role": status["role"],
                "connectedReplicas": int(status.get("connected_slaves", "0") or 0),
                "masterLinkUp": status.get("master_link_status") == "up"}
    except (InventoryError, ValueError):
        return {"observed": False}


def source_state_inventory(root):
    """Перечень рисков с прослеживаемыми источниками; не утверждать, что состояние Runtime общее."""
    files = {
        "runtime": root / "services/api/internal/httpapi/runtime_state.go",
        "persistence": root / "services/api/internal/httpapi/persistence.go",
        "roles": root / "services/api/cmd/launcher-api/process_role_0455.go",
        "leases": root / "services/api/internal/deployment/growth.go",
    }
    try:
        contents = {k: v.read_text(encoding="utf-8") for k, v in files.items()}
    except (OSError, UnicodeError):
        return {"observed": False, "reason": "source_tree_unavailable"}
    fields = ("AuthSessions", "Security", "Passkeys", "ServerBridge", "Maintenance",
              "PackageMutation", "BackendLifecycle0289")
    local_state = [f for f in fields if re.search(r"\b" + re.escape(f) + r"\b", contents["runtime"])]
    return {
        "observed": True,
        "sourceSha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in contents.items()},
        "replicaLocalStateToVerify": local_state,
        "snapshotRestoredAtBoot": "loadLatest(ctx, \"all\")" in contents["persistence"],
        "separateAPIRole": 'case "api":' in contents["roles"],
        "separateWorkerRole": 'case "worker":' in contents["roles"],
        "realDependencyRoundTripPresent": all(token in contents["leases"] for token in
                                               ("verifyPostgresGrowth", "verifyRedisGrowth", "verifyS3Growth")),
    }


def node_inventory(project, samples, growth=True, source_root=None):
    ids = docker_ids(project)
    inspected = docker_inspect(ids)
    items = [classify_container(c, project) for c in inspected]
    node_id = machine_identity()
    try:
        engine_id = execute(["docker", "info", "--format", "{{.ID}}"], timeout=8).strip()
        engine_id = "docker:" + fingerprint(engine_id) if engine_id else None
    except InventoryError:
        engine_id = None
    problems = []
    if not node_id:
        problems.append("Не удалось определить ОС узла: невозможно различить домены отказа")
    if not engine_id:
        problems.append("Не удалось определить идентификатор демона Docker")
    if not items:
        problems.append("Не найдены запущенные или остановленные контейнеры проекта")
    for item in items:
        service = item["service"]
        if service in ("api", "api-b", "worker", "worker-a", "worker-b"):
            item["readiness"] = docker_ready(item["containerId"], samples) if item["running"] else {
                "sampled": 0, "success": 0, "failures": 0, "p50Ms": None, "p95Ms": None}
            if item["readiness"]["success"] != samples:
                problems.append("%s: не пройдены все реальные проверки готовности" % service)
            if item["health"] not in ("healthy", "not-configured"):
                problems.append("Состояние Docker для %s: %s" % (service, item["health"]))
            env = item["environment"]
            wanted_role = "api" if service in ("api", "api-b") else "worker"
            if env.get("LAUNCHER_PROCESS_ROLE") != wanted_role:
                problems.append("%s: выделенная роль %s не запущена" % (service, wanted_role))
            for key, target in (("LAUNCHER_REPOSITORY_DRIVER", "postgres"),
                                ("LAUNCHER_STORAGE_DRIVER", "s3"),
                                ("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "true"),
                                ("LAUNCHER_DATABASE_AUTO_MIGRATE", "false"),
                                ("LAUNCHER_RATE_LIMIT_ENABLED", "true"),
                                ("LAUNCHER_RATE_LIMIT_FAIL_CLOSED", "true")):
                if env.get(key, "").lower() != target:
                    problems.append("%s unsafe %s" % (service, key))
            if env.get("LAUNCHER_DEPLOYMENT_MODE") != "network-ha":
                problems.append("%s: не настроена сетевая высокая доступность" % service)
            if not env.get("LAUNCHER_REPLICA_ID", "").strip():
                problems.append("%s: отсутствует постоянный LAUNCHER_REPLICA_ID" % service)
            if env.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", ""):
                problems.append("%s: по-прежнему используется координатор SQLite" % service)
            if growth and service in ("api", "api-b") and item["running"]:
                item["dependencyRoundTrip"] = docker_growth(item["containerId"])
                if not item["dependencyRoundTrip"]["verified"]:
                    problems.append("%s: не пройдена реальная проверка расширения PostgreSQL/Redis/S3" % service)
        elif service == "postgres" and item["running"]:
            item["postgresState"] = probe_postgres(item["containerId"])
        elif service == "redis" and item["running"]:
            item["redisState"] = probe_redis(item["containerId"])
    # Совпадение идентификаторов на одном хосте небезопасно даже при разных ID
    # контейнеров Docker: маршрутизация ServerBridge привязана к ID реплики.
    replica_ids = [i["environment"].get("LAUNCHER_REPLICA_ID") for i in items
                   if i["service"] in ("api", "api-b", "worker", "worker-a", "worker-b")]
    nonempty = [x for x in replica_ids if x]
    if len(nonempty) != len(set(nonempty)):
        problems.append("Повторяющийся LAUNCHER_REPLICA_ID на узле Docker")
    source = source_state_inventory(source_root or Path(__file__).resolve().parents[2])
    state_inventory = []
    for item in items:
        for mount in item["writableDataMounts"]:
            destination = mount["destination"]
            if "/factory" in destination:
                classification = "reconstructible_or_project_specific_unverified"
            elif "/backups" in destination:
                classification = "local_recovery_copy_not_offhost_proven"
            elif "/coordinator" in destination:
                classification = "local_coordination_must_not_be_authoritative_in_HA"
            else:
                classification = "node_local_state_role_unverified"
            state_inventory.append({"service": item["service"], "surface": destination,
                                    "classification": classification,
                                    "mountType": mount["type"], "writable": mount["writable"]})
    for name, classification in (("Доменное хранилище PostgreSQL", "authoritative_metadata"),
                                 ("Объекты релиза в S3", "authoritative_objects"),
                                 ("Аренды Redis и ограничения частоты запросов", "reconstructible_coordination_not_durable_authority"),
                                 ("Карты состояния Auth/MFA/ServerBridge в Runtime", "replica_local_state_cross_replica_consistency_unverified"),
                                 ("Игровые миры ServerBridge", "external_game_host_state_not_inspected")):
        state_inventory.append({"surface": name, "classification": classification})
    return {"schema": "launcher.ha-inventory.0.51.1", "version": VERSION,
            "collectedUtc": utc_now(), "project": project, "nodeIdentity": node_id,
            "dockerEngineIdentity": engine_id, "containers": items,
            "stateInventory": state_inventory, "sourceState": source,
            "observations": sorted(set(problems)),
            "nodeStatus": "RISK" if problems else "OBSERVED"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def probe_public_edge(url, samples):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise InventoryError("Некорректный HTTPS-адрес внешней точки входа") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise InventoryError("Для внешней точки входа требуется HTTPS-адрес без встроенных учётных данных и фрагмента")
    if parsed.path not in ("", "/", "/ready") or parsed.query:
        raise InventoryError("Для внешней точки входа укажите адрес сервера или /ready без параметров запроса")
    target = url.rstrip("/") + ("/ready" if parsed.path in ("", "/") else "")
    opener = urllib.request.build_opener(NoRedirect())
    durations = []
    failures = 0
    for _ in range(samples):
        started = time.monotonic_ns()
        try:
            request = urllib.request.Request(target, headers={"User-Agent": "Launcher-HA-Inventory/0.51.1"})
            with opener.open(request, timeout=6) as response:
                if response.status != 200:
                    raise InventoryError("Публичный пограничный узел не готов: HTTP-ответ отличается от 200")
                response.read(65536)
            durations.append((time.monotonic_ns() - started) / 1_000_000)
        except (urllib.error.URLError, OSError, InventoryError, ValueError):
            failures += 1
    return {"sampled": samples, "success": len(durations), "failures": failures,
            "p50Ms": round(statistics.median(durations), 3) if durations else None,
            "p95Ms": round(sorted(durations)[math.ceil(len(durations) * .95) - 1], 3) if durations else None}


def assess_cluster(nodes, edge=None):
    issues = []
    findings = []
    containers = [(name, node.get("nodeIdentity"), i) for name, node in nodes.items()
                  for i in node.get("containers", [])]
    def record(name, status, evidence, required=True):
        findings.append({"component": name, "status": status, "evidence": evidence,
                         "requiresIndependentFaultTest": required})
        if status == "RISK":
            issues.append(name + ": " + evidence)

    host_ids = [n.get("nodeIdentity") for n in nodes.values()]
    host_ids_valid = all(host_ids) and len(host_ids) == len(set(host_ids))
    record("failure_domains", "OBSERVED" if host_ids_valid and len(host_ids) >= 2 else "RISK",
           "Разные идентификаторы ОС на %d доступных оператору узлах Docker; физическая изоляция или изоляция гипервизоров не проверена" % len(set(host_ids))
           if host_ids_valid else "Идентификаторы ОС повторяются или отсутствуют либо доступно менее двух узлов")
    for role, aliases in (("api", ("api", "api-b")), ("worker", ("worker", "worker-a", "worker-b")),
                          ("admin", ("admin",)), ("ingress", ("nginx", "ingress"))):
        matched = [(h, i) for _, h, i in containers if i["service"] in aliases and i["running"]]
        ready = [(h, i) for h, i in matched if (i.get("readiness", {}).get("success", 0) > 0
                                              if role in CRITICAL_ROLES else i["health"] == "healthy")]
        domains = {h for h, _ in ready if h}
        status = "OBSERVED" if len(domains) >= 2 and len(ready) >= 2 else "RISK"
        record(role, status, "Запущено %d; готовы к работе %d на %d идентификаторах ОС" %
               (len(matched), len(ready), len(domains)))
    replicas = [(name, i) for name, _, i in containers if i["service"] in
                ("api", "api-b", "worker", "worker-a", "worker-b") and i["running"]]
    ids = [i["environment"].get("LAUNCHER_REPLICA_ID") for _, i in replicas]
    role_safe = len(replicas) >= 4 and all(ids) and len(ids) == len(set(ids))
    if role_safe:
        role_safe = all(i.get("readiness", {}).get("success") == i.get("readiness", {}).get("sampled")
                        for _, i in replicas)
    if role_safe:
        role_safe = all(not n.get("observations") for n in nodes.values())
    record("replica_roles_and_identity", "OBSERVED" if role_safe else "RISK",
           "Идентификаторы реплик уникальны; роли, готовность и настройки Runtime проверены" if role_safe
           else "Идентификаторы отсутствуют или повторяются, роль или конфигурация некорректны либо проверки узлов не пройдены")
    pg = [(h, i) for _, h, i in containers if i["service"] == "postgres" and i["running"]]
    if len(pg) == 1:
        record("postgresql", "RISK", "На проверенных узлах найден только один контейнер PostgreSQL; внешнее переключение при отказе не подтверждено")
    elif not pg:
        record("postgresql", "UNVERIFIED", "Топология внешнего PostgreSQL или управляемого кластера не определяется по проверенным проектам Docker")
    else:
        all_pg = all(i.get("postgresState", {}).get("observed") for _, i in pg)
        sync_pg = any(i.get("postgresState", {}).get("synchronousPeers", 0) >= 1 for _, i in pg)
        distinct_pg = len({h for h, _ in pg if h}) >= 2
        record("postgresql", "UNVERIFIED" if all_pg and sync_pg and distinct_pg else "RISK",
               "Подтверждена реальная репликация PostgreSQL; переключение при отказе и изоляция узлов не проверены" if all_pg and sync_pg and distinct_pg
               else "Синхронная репликация PostgreSQL, роли или домены отказа не подтверждены")
    redis = [(h, i) for _, h, i in containers if i["service"] == "redis" and i["running"]]
    if len(redis) == 1:
        record("redis", "RISK", "Только один контейнер Redis; аренды не подтверждают высокую доступность Redis")
    elif not redis:
        record("redis", "UNVERIFIED", "Невозможно наблюдать внешнее переключение Redis, Sentinel или управляемого сервиса")
    else:
        record("redis", "UNVERIFIED", "Обнаружено несколько процессов Redis; эпоха, кворум и переключение при отказе не проверены")
    live = [i.get("dependencyRoundTrip") for _, i in replicas if i["service"] in ("api", "api-b")]
    if live and all(x and x.get("verified") and x.get("postgresql") and x.get("redisLease") and x.get("s3RoundTrip") for x in live):
        record("s3_objects", "UNVERIFIED", "Реальные запись, чтение, проверка хеша и удаление в S3 из разных клиентов работают; отказоустойчивость провайдера и переключение при сбое не проверялись")
        record("durable_lease", "UNVERIFIED", "Транзакционная изоляция PostgreSQL и аренда Redis работают; безопасность при разделении сети не подтверждена")
    else:
        record("s3_objects", "UNVERIFIED", "Отсутствует подтверждение успешных операций записи, чтения, хеширования и удаления в работающем S3")
        record("durable_lease", "UNVERIFIED", "Отсутствует реальное свидетельство изоляции или аренды PostgreSQL и Redis")
    if edge:
        record("public_tls_edge", "OBSERVED" if edge.get("success") == edge.get("sampled") else "RISK",
               "Публичный HTTPS /ready пройден %d/%d (переключение входного узла при отказе не проверяется)" %
               (edge["success"], edge["sampled"]), required=True)
    else:
        record("public_tls_edge", "UNVERIFIED", "Не предоставлена проверка публичного HTTPS-шлюза")
    source_reports = [node.get("sourceState") for node in nodes.values() if node.get("sourceState", {}).get("observed")]
    if source_reports and any(s.get("replicaLocalStateToVerify") for s in source_reports):
        record("replica_local_runtime_state", "UNVERIFIED",
               "Согласованность внутрипроцессного состояния авторизации, безопасности и Bridge между работающими репликами не проверена; код подтверждает наличие локальных полей процесса")
    else:
        record("replica_local_runtime_state", "UNVERIFIED",
               "Исходный код недоступен или состояние безопасности отдельных процессов не учтено")
    for kind, why in (
        ("secret_authority", "Распределение секретов и ключей, согласованность и независимое восстановление не проверены"),
        ("external_auth", "Переключение внешних зависимостей авторизации OIDC/Microsoft не проверено"),
        ("dns", "Авторитетные DNS-серверы, TTL и сетевое переключение при отказе не проверены"),
        ("serverbridge", "Эпохи Runtime игрового узла или Bridge и маршрутизация между узлами не проверены"),
        ("game_worlds", "Миры с единственным записывающим процессом, снимки и удалённое восстановление не проверены"),
        ("backups", "Восстановление на момент времени (PITR) вне узла и его проверка не выполнялись"),
        ("extension_state", "Процессы расширений, состояние файловой системы и совместимость реплик не проверены"),
    ):
        record(kind, "UNVERIFIED", why)
    operations = [
        {"operation": "Публикация и откат, а также надёжные фоновые задания", "authority": "Транзакционная аренда PostgreSQL и исходящая очередь",
         "partitionRule": "Нет полномочий PostgreSQL — операция запрещается; устаревший исполнитель не может зафиксировать изменения",
         "evidence": "Проверена только изоляция; реальное разделение сети не подтверждено"},
        {"operation": "Команда управления ServerBridge", "authority": "Журнал команд PostgreSQL и аренда канала Redis",
         "partitionRule": "Устаревшая эпоха или токен не могут выполнить внешнее действие; слепое повторение запрещено",
         "evidence": "Инвентаризацией не подтверждено; требуются версии 0.51.4/0.51.5"},
        {"operation": "Изменение профиля, авторизации, MFA или ключа доступа", "authority": "PostgreSQL и устаревшие снимки Runtime отдельных процессов",
         "partitionRule": "Независимые реплики должны согласовываться сразу после фиксации изменений",
         "evidence": "Чтение и запись между репликами не подтверждены; требуется отдельный тест"},
        {"operation": "Сохранение и восстановление мира Minecraft", "authority": "Единственный активный процесс JVM с правом записи в игровой мир",
         "partitionRule": "Единственный писатель с кворумом и изоляцией либо остановка записи до восстановления",
         "evidence": "Инвентаризацией не подтверждено; требуется тест игрового узла"},
    ]
    return {"status": "RISK" if issues else "UNVERIFIED", "issues": issues,
            "spof": findings, "criticalOperations": operations,
            "multiHostFailoverCertified": False,
            "reason": "Инвентаризация и проверка готовности не подтверждают реальные потери хостов, сетевую изоляцию, поэтапные обновления или восстановление миров"}


def remote_node(target, remote_script, project, samples, growth):
    if not SSH_RE.fullmatch(target) or target.startswith("-"):
        raise InventoryError("Некорректный SSH-адрес узла")
    if not remote_script.startswith("/") or "\n" in remote_script:
        raise InventoryError("Для удалённого скрипта требуется абсолютный путь установки")
    command = ["python3", remote_script, "node", "--project", project,
               "--samples", str(samples), "--output", "-"]
    if not growth:
        command.append("--skip-growth")
    # Один аргумент удалённой команды, заключённый в кавычки; никаких подстановок
    # ввода в оболочку.
    raw = execute(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "ConnectTimeout=7", "-o", "NumberOfPasswordPrompts=0",
                   target, shlex.join(command)], timeout=max(45, 55 + 8 * samples), allowed_codes=(0, 3))
    try:
        result = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise InventoryError("Удалённый узел вернул некорректный JSON") from exc
    validate_node(result, project)
    return result


def validate_node(node, project):
    if not isinstance(node, dict) or node.get("schema") != "launcher.ha-inventory.0.51.1" or node.get("project") != project:
        raise InventoryError("Схема или проект списка узлов не совпадает")
    if not isinstance(node.get("containers"), list) or not isinstance(node.get("observations"), list):
        raise InventoryError("Инвентаризация узла не завершена")
    if len(node["containers"]) > 100:
        raise InventoryError("Список узлов превышает допустимый размер")


def write_report(path, payload):
    content = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if path == "-":
        sys.stdout.buffer.write(content)
        return
    destination = Path(path)
    if destination.is_symlink() or destination.exists():
        raise InventoryError("Отчёт уже существует; перезапись существующих подтверждений запрещена")
    if not destination.parent.is_dir():
        raise InventoryError("Отсутствует каталог отчётов")
    fd, temp = tempfile.mkstemp(prefix=".ha-inventory-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temp, destination)  # атомарная публикация с эксклюзивным доступом (без перезаписи)
        dirfd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        Path(temp).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    local = subs.add_parser("node", help="Проверить настоящие процессы Docker на этом хосте")
    local.add_argument("--project", required=True)
    local.add_argument("--samples", type=int, default=3)
    local.add_argument("--skip-growth", action="store_true", help="Отметить проверку зависимостей как неподтверждённую")
    local.add_argument("--source-root", type=Path, help="Включить инвентаризацию локального состояния реплик с прослеживаемым источником")
    local.add_argument("--output", required=True)
    cluster = subs.add_parser("cluster", help="Собрать инвентаризацию узлов через SSH и найти реальные единые точки отказа (SPOF)")
    cluster.add_argument("--project", required=True)
    cluster.add_argument("--node", action="append", required=True,
                         help="name=local или name=trusted-ssh-user@host (повторять на разных хостах)")
    cluster.add_argument("--remote-script", default="/opt/launcher/scripts/operations/ha_inventory_0511.py")
    cluster.add_argument("--samples", type=int, default=3)
    cluster.add_argument("--skip-growth", action="store_true")
    cluster.add_argument("--edge-url", help="Настоящий публичный HTTPS-адрес или /ready")
    cluster.add_argument("--source-root", type=Path)
    cluster.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if not PROJECT_RE.fullmatch(args.project):
            raise InventoryError("Некорректное имя проекта Docker Compose")
        if not 1 <= args.samples <= 20:
            raise InventoryError("Число образцов должно быть от 1 до 20")
        if args.mode == "node":
            result = node_inventory(args.project, args.samples, not args.skip_growth, args.source_root)
            write_report(args.output, result)
            return 3 if result["nodeStatus"] == "RISK" else 0
        nodes = {}
        for spec in args.node:
            name, sep, target = spec.partition("=")
            if not sep or not LABEL_RE.fullmatch(name) or not target or name in nodes:
                raise InventoryError("Каждый --node должен содержать уникальное значение name=SSH-адрес или name=local")
            if target == "local":
                nodes[name] = node_inventory(args.project, args.samples, not args.skip_growth, args.source_root)
            else:
                nodes[name] = remote_node(target, args.remote_script, args.project, args.samples, not args.skip_growth)
        edge = probe_public_edge(args.edge_url, args.samples) if args.edge_url else None
        assessment = assess_cluster(nodes, edge)
        result = {"schema": "launcher.ha-cluster-inventory.0.51.1", "version": VERSION,
                  "collectedUtc": utc_now(), "project": args.project, "nodes": nodes,
                  "edgeReadiness": edge, "assessment": assessment}
        write_report(args.output, result)
        return 3 if assessment["status"] == "RISK" else 0
    except InventoryError as exc:
        # Ошибка никогда не содержит вывод команды, учётные данные или окружение.
        print("Инвентаризация высокой доступности недоступна: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
