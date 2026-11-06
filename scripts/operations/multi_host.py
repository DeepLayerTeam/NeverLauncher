#!/usr/bin/env python3
"""NeverLauncher 0.51.2: выполнить и проверить настоящее развёртывание на нескольких Docker-хостах.

На каждом хосте собственные API, worker, Admin и HTTPS ingress с общими внешними PostgreSQL, Redis и
S3. Программа не развёртывает эти внешние службы и не путает два контейнера одного хоста с двумя
доменами отказа.

Режимы local-check/local-up/local-observe запускаются *на каждом хосте*; cluster-check, cluster-up и
cluster-drill — с доверенной операторской машины через закреплённые SSH-ключи хостов. Кластерная
репетиция нарушает работу контейнеров продукта одного хоста и восстанавливает их даже при ошибке
проверки. Исходная конфигурация Docker и секреты не печатаются и не сохраняются в отчётах.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

import ha_inventory_0511 as inventory

VERSION = "0.51.2"
SCHEMA = "neverlauncher.multi-host.0.51.2"
HOST_REGEX = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9.-]*$")
LABEL_REGEX = re.compile(r"^[a-z][a-z0-9-]{0,40}$")
PROJECT_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
DIGEST_REGEX = re.compile(r"^[a-zA-Z0-9_./:-]+@sha256:[0-9a-f]{64}$")
SERVICES = ("api", "worker", "admin", "ingress")
ALL_SERVICES = ("api", "worker", "admin", "ingress", "volume-init")

class DeploymentError(Exception):
    pass


def run(argv, *, cwd=None, timeout=30, codes=(0,)):
    """При ошибках никогда не раскрывать stderr, stdout, окружение или команды."""
    try:
        p = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError("Команда недоступна или истекло время ожидания: " + argv[0]) from exc
    if p.returncode not in codes:
        raise DeploymentError("Команда завершилась ошибкой: " + argv[0] + " (exit " + str(p.returncode) + ")")
    if len(p.stdout) > 4_000_000:
        raise DeploymentError("Команда вернула слишком большой объём вывода")
    return p.stdout.decode("utf-8", errors="replace")


def compose_command(directory, project, *rest, env_file=None):
    command = ["docker", "compose", "--project-name", project,
               "-f", str(directory / "docker-compose.multi-host.yml")]
    if env_file is not None:
        command.extend(("--env-file", str(env_file)))
    return [*command, *rest]


def url_host(value, scheme):
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise DeploymentError("Некорректный URL внешней конечной точки") from exc
    if parsed.scheme not in scheme or not parsed.hostname or parsed.fragment:
        raise DeploymentError("Внешняя зависимость должна использовать требуемую схему URL с TLS")
    if parsed.hostname.lower() in ("localhost", "127.0.0.1", "::1", "postgres", "redis", "minio", "s3"):
        raise DeploymentError("Внешняя зависимость не должна указывать на localhost или встроенную службу Compose")
    return parsed.hostname.lower()


def check_secure_file(path, *, strict=False):
    if not path.is_file() or path.is_symlink():
        raise DeploymentError("Обязательный файл отсутствует либо является символической ссылкой: " + path.name)
    mode = stat.S_IMODE(path.stat().st_mode)
    if strict and (mode & 0o077):
        raise DeploymentError("Файл секрета доступен группе или другим пользователям: " + path.name)


def resolved_compose(directory, project, *, env_file=None):
    if not PROJECT_REGEX.fullmatch(project):
        raise DeploymentError("Некорректное имя проекта Docker Compose")
    check_secure_file(env_file if env_file is not None else directory / ".env", strict=True)
    check_secure_file(directory / "docker-compose.multi-host.yml")
    check_secure_file(directory / "nginx.multi-host-0512.conf")
    raw = run(compose_command(directory, project, "config", "--format", "json", env_file=env_file), cwd=directory, timeout=20)
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise DeploymentError("Конфигурация Docker Compose не является корректным JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise DeploymentError("В конфигурации Docker Compose отсутствуют службы")
    services = data["services"]
    if set(services) != set(ALL_SERVICES):
        raise DeploymentError("Недопустимые службы Compose: встроенная база данных и посторонние процессы запрещены")
    api = services["api"]["environment"]
    worker = services["worker"]["environment"]
    for name, env in (("api", api), ("worker", worker)):
        if env.get("LAUNCHER_PROCESS_ROLE") != name:
            raise DeploymentError("Неверная роль процесса для " + name)
        for key, expected in (("LAUNCHER_DEPLOYMENT_MODE", "network-ha"),
                              ("LAUNCHER_REPOSITORY_DRIVER", "postgres"),
                              ("LAUNCHER_STORAGE_DRIVER", "s3"),
                              ("LAUNCHER_SQL_DRIVER", "pgx"),
                              ("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "true"),
                              ("LAUNCHER_RATE_LIMIT_ENABLED", "true"),
                              ("LAUNCHER_RATE_LIMIT_FAIL_CLOSED", "true"),
                              ("LAUNCHER_DATABASE_AUTO_MIGRATE", "false"),
                              ("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", "")):
            if str(env.get(key, "")).lower() != expected:
                raise DeploymentError(name + " содержит небезопасное значение " + key)
        if env.get("LAUNCHER_STORAGE_S3_BUCKET", "") == "":
            raise DeploymentError("Отсутствует: «корзина S3»")
    ids = (api.get("LAUNCHER_REPLICA_ID"), worker.get("LAUNCHER_REPLICA_ID"))
    if not isinstance(ids[0], str) or not ids[0].endswith("-api") or not LABEL_REGEX.fullmatch(ids[0][:-4]):
        raise DeploymentError("Для LAUNCHER_NODE_ID требуется: «стабильный идентификатор в нижнем регистре, совместимый с именем узла»")
    node_id = ids[0][:-4]
    if ids[1] != node_id + "-worker":
        raise DeploymentError("API и рабочий процесс должны иметь общий префикс узла, но разные идентификаторы реплик")
    pg = url_host(api.get("LAUNCHER_DATABASE_DSN", ""), ("postgres", "postgresql"))
    if parse_qs(urlsplit(api["LAUNCHER_DATABASE_DSN"]).query).get("sslmode") != ["verify-full"]:
        raise DeploymentError("Для PostgreSQL требуется «TLS с sslmode=verify-full в сети из нескольких узлов»")
    redis = url_host(api.get("LAUNCHER_REDIS_URL", ""), ("rediss",))
    s3 = url_host(api.get("LAUNCHER_STORAGE_S3_ENDPOINT", ""), ("https",))
    public = api.get("LAUNCHER_PUBLIC_URL", "")
    public_host = url_host(public, ("https",))
    if urlsplit(public).username or urlsplit(public).password:
        raise DeploymentError("публичный URL: запрещено «содержать учётные данные»")
    for key in ("LAUNCHER_DATABASE_DSN", "LAUNCHER_REDIS_URL", "LAUNCHER_STORAGE_S3_ENDPOINT",
                "LAUNCHER_STORAGE_S3_BUCKET", "LAUNCHER_STORAGE_S3_REGION", "LAUNCHER_PUBLIC_URL"):
        if api.get(key) != worker.get(key):
            raise DeploymentError("Рабочий процесс и API используют разные общие зависимости: " + key)
    refs = {}
    for name in ALL_SERVICES:
        ref = services[name].get("image", "")
        if not DIGEST_REGEX.fullmatch(ref):
            raise DeploymentError("Производственный образ для " + name + " должен иметь неизменяемую контрольную сумму @sha256")
        refs[name] = ref
    if refs["api"] != refs["worker"]:
        raise DeploymentError("API и рабочий процесс должны использовать точно один и тот же исполняемый файл или образ")
    if "ports" in services["api"] or "ports" in services["worker"]:
        raise DeploymentError("«службы API и обработчика заданий»: запрещено «публиковать порты узла»")
    ingress_ports = services["ingress"].get("ports", [])
    if len(ingress_ports) != 1:
        raise DeploymentError("Входящий прокси должен публиковать ровно один ограниченный HTTPS-порт")
    for bind in ingress_ports:
        if bind.get("target") != 443 or bind.get("published") != "443" or bind.get("protocol", "tcp") != "tcp":
            raise DeploymentError("У локального входящего прокси можно публиковать только порт 443")
        host_ip = str(bind.get("host_ip", ""))
        if not host_ip or host_ip in ("0.0.0.0", "::", "127.0.0.1"):
            raise DeploymentError("ingress: требуется «явный доступный IP-адрес ограниченного сетевого интерфейса»")
    for name in ("api", "worker"):
        if not services[name].get("healthcheck"):
            raise DeploymentError("Отсутствует: «проверка готовности для»" + name)
    # Проверяйте ключ и сертификат TLS на хосте по разобранным томам Docker, а не
    # через недоверенную подстановку содержимого env-файла или журналирование
    # конфигурации Docker.
    tls_targets = ("/etc/launcher/tls/fullchain.pem", "/etc/launcher/tls/privkey.pem")
    tls_volumes = [v for v in services["ingress"].get("volumes", []) if v.get("target") in tls_targets]
    if sorted(v["target"] for v in tls_volumes) != sorted(tls_targets):
        raise DeploymentError("Сертификат TLS и закрытый ключ узла должны быть подключены как тома")
    for volume in tls_volumes:
        if volume.get("type") != "bind" or volume.get("read_only") is not True:
            raise DeploymentError("Учётные данные TLS узла должны подключаться как файлы только для чтения")
        check_secure_file(Path(volume["source"]), strict=volume["target"].endswith("privkey.pem"))
    machine = inventory.machine_identity()
    if not machine:
        raise DeploymentError("Отсутствует machine-id ОС: невозможно подтвердить независимость узлов Docker")
    try:
        pgport = urlsplit(api["LAUNCHER_DATABASE_DSN"]).port or 5432
        redisport = urlsplit(api["LAUNCHER_REDIS_URL"]).port or 6379
        s3port = urlsplit(api["LAUNCHER_STORAGE_S3_ENDPOINT"]).port or 443
    except ValueError as exc:
        raise DeploymentError("У внешнего эндпоинта указан некорректный TCP-порт") from exc
    return {"schema": SCHEMA, "version": VERSION, "nodeId": node_id,
            "machineIdentity": machine, "project": project, "roles": list(SERVICES),
            "imageDigestRefs": refs, "sharedEndpoints": {"postgres": pg, "redis": redis,
            "pgPort": pgport,
            "pgDatabase": urlsplit(api["LAUNCHER_DATABASE_DSN"]).path,
            "redisPort": redisport,
            "redisDb": urlsplit(api["LAUNCHER_REDIS_URL"]).path,
            "s3": s3, "s3Port": s3port,
            "s3Path": urlsplit(api["LAUNCHER_STORAGE_S3_ENDPOINT"]).path,
            "bucket": api["LAUNCHER_STORAGE_S3_BUCKET"],
            "region": api["LAUNCHER_STORAGE_S3_REGION"],
            "public": public_host}, "configurationValidated": True}


def live_observe(directory, project, *, growth=True):
    expected = resolved_compose(directory, project)
    # Проверяйте полное исполняемое состояние: контейнеры, фактические роли
    # процессов из окружения, /ready приложения и рабочих процессов, аренду Redis,
    # транзакцию PostgreSQL и круговую запись/чтение объекта S3.
    node = inventory.node_inventory(project, 3, growth=growth, source_root=directory.parents[1])
    actual = {item["service"]: item for item in node["containers"]}
    issues = list(node["observations"])
    if not growth:
        issues.append("Реальная сквозная проверка PostgreSQL/Redis/S3 была намеренно пропущена")
    for name in SERVICES:
        item = actual.get(name)
        if not item or not item["running"] or item["health"] != "healthy":
            issues.append(name + " не является запущенным исправным контейнером")
            continue
        if name in ("api", "worker"):
            if item.get("readiness", {}).get("success") != 3:
                issues.append(name + " не прошёл три реальные проверки /ready")
            if item["environment"].get("LAUNCHER_REPLICA_ID") != expected["nodeId"] + "-" + name:
                issues.append(name + " Фактический идентификатор реплики не совпадает с конфигурацией развёртывания")
    for name in ("postgres", "redis"):
        if name in actual:
            issues.append("embedded " + name + " не должен запускаться в проекте с несколькими узлами")
    # Неизменяемая ссылка на образ контейнера должна соответствовать
    # развёртыванию, а не только его ID образа — это разные сущности в Docker
    # inspect.
    running_refs = {}
    for container in inventory.docker_inspect(inventory.docker_ids(project)):
        cfg = container.get("Config") or {}
        label = (cfg.get("Labels") or {}).get("com.docker.compose.service")
        if label in SERVICES:
            running_refs[label] = cfg.get("Image")
    for name in SERVICES:
        if running_refs.get(name) != expected["imageDigestRefs"][name]:
            issues.append(name + " Контейнер запущен не из требуемого неизменяемого образа")
    return {**expected, "live": node, "issues": sorted(set(issues)),
            "ready": not issues and all(name in actual for name in SERVICES),
            "observedUtc": inventory.utc_now()}


def local_compat_observe_0516(directory, project):
    """Настоящие проверки HTTP API, Bridge и worker внутри закреплённых работающих образов.

    Это намеренно отдельный режим только для чтения. Обычные кластерные проверки по-прежнему
    отклоняют разные дайджесты образов при развёртывании и хаос-тестах.
    """
    import hashlib
    report = live_observe(directory, project, growth=True)
    if not report.get("ready"):
        raise DeploymentError("Нельзя проверить совместимость неисправного узла")
    running = {c.get("service"): c for c in report["live"]["containers"]}
    for role in ("api", "worker"):
        ready = (running.get(role) or {}).get("readiness") or {}
        if not (ready.get("versionVerified") is True and ready.get("version") in ("0.51.5", "0.51.6", "0.51.7")):
            raise DeploymentError("Не поддерживается или не проверена действующая версия /ready для" + role)
    if running["api"]["readiness"]["version"] != running["worker"]["readiness"]["version"]:
        raise DeploymentError("На одном хосте версии работающих API и рабочего процесса не совпадают")
    container = running["api"]["containerId"]
    def get(path):
        raw = inventory.execute(["docker", "exec", container, "wget", "-qO-", "-T", "5",
                                 "http://127.0.0.1:8080" + path], timeout=9)
        if len(raw) > 512_000:
            raise DeploymentError("Превышен допустимый размер: «ответ совместимости HTTP API»")
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise DeploymentError("Некорректное значение: «ответ совместимости HTTP API»") from exc
        if not isinstance(data, dict):
            raise DeploymentError("Ответ проверки совместимости HTTP API должен быть объектом JSON")
        return data
    v = running["api"]["readiness"]["version"]
    status = get("/api/v1/status")
    if status.get("status") != "ok" or status.get("version") != v:
        raise DeploymentError("Статус работающего API не совпадает с версией из проверки готовности")
    loaders = get("/api/v1/loaders")
    if loaders.get("version") != v or not isinstance(loaders.get("items"), list) or not loaders["items"]:
        raise DeploymentError("Контракт работающего API загрузчика несовместим")
    runtime = get("/api/v1/runtime/requirements")
    if runtime.get("version") != v or not isinstance(runtime.get("java"), dict):
        raise DeploymentError("API требований работающего Runtime несовместим")
    bridge = get("/api/v1/server-bridge/capabilities?protocols=3,2")
    data = bridge.get("data")
    if (not isinstance(data, dict) or data.get("toolVersion") != v or
            data.get("negotiatedProtocolVersion") != 3 or
            data.get("supportedProtocolVersions") != [3, 2] or
            data.get("rollingUpgrade") is not True or
            not data.get("activeSigningKeyFingerprint")):
        raise DeploymentError("Согласование подписанных возможностей ServerBridge несовместимо")
    # Сравнивайте настоящие контракты ответов, а не строки, зависящие от версии.
    protocols = {key: data.get(key) for key in (
        "schemaVersion", "preferredProtocolVersion", "minimumProtocolVersion",
        "supportedProtocolVersions", "requiredFeatures", "protocolV3FeatureDigest",
        "legacyProtocolV2Supported", "securityCapabilityDigest", "activeSigningKeyFingerprint")}
    loaders.pop("version", None)
    runtime.pop("version", None)
    def fingerprint(payload):
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report["compatibility0516"] = {"liveVersion": v, "apiStatus": "ok",
                                   "loadersSHA256": fingerprint(loaders),
                                   "runtimeRequirementsSHA256": fingerprint(runtime),
                                   "bridgeContractSHA256": fingerprint(protocols),
                                   "bridgeProtocol": 3}
    return report


def local_up(directory, project):
    expected = resolved_compose(directory, project)
    # Промышленные образы всегда загружаются по дайджесту. Не собирайте их
    # независимо на двух хостах в надежде, что теги будут означать одинаковые
    # исполняемые байты.
    run(compose_command(directory, project, "pull", "--policy", "always"), cwd=directory, timeout=240)
    run(compose_command(directory, project, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180"),
        cwd=directory, timeout=230)
    report = live_observe(directory, project)
    if not report["ready"]:
        raise DeploymentError("Ошибка: «контейнеры запущены, но проверка готовности или взаимодействие с зависимостями не прошли»")
    return report


def remote_call(target, installed_script, directory, project, mode, *, growth=True, timeout=150):
    if not HOST_REGEX.fullmatch(target) or target.startswith("-"):
        raise DeploymentError("Некорректное значение: «целевой узел SSH»")
    if not installed_script.startswith("/") or not directory.startswith("/"):
        raise DeploymentError("Для установленного скрипта и каталога развёртывания требуются абсолютные пути")
    if any("\n" in s or "\r" in s for s in (installed_script, directory)):
        raise DeploymentError("Некорректное значение: «удалённый путь»")
    args = ["python3", installed_script, mode, "--directory", directory, "--project", project,
            "--output", "-"]
    if not growth:
        args.append("--skip-growth")
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=0", target,
           shlex.join(args)]
    raw = run(ssh, timeout=timeout, codes=(0, 3))
    try:
        result = json.loads(raw)
    except ValueError as exc:
        raise DeploymentError("Удалённый узел вернул некорректный отчёт") from exc
    if not isinstance(result, dict) or result.get("schema") != SCHEMA or result.get("project") != project:
        raise DeploymentError("Удалённый узел вернул отчёт с неверной схемой или проектом")
    return result


def remote_stop_start(target, installed_script, directory, project, action):
    if action not in ("stop", "start"):
        raise DeploymentError("Не поддерживается: «действие по имитации отказа»")
    return remote_call(target, installed_script, directory, project, "local-" + action,
                       growth=False, timeout=(260 if action == "start" else 120))


def parse_nodes(specs):
    nodes = {}
    for spec in specs:
        name, sep, host = spec.partition("=")
        if not sep or not LABEL_REGEX.fullmatch(name) or not HOST_REGEX.fullmatch(host) or host.startswith("-") or name in nodes:
            raise DeploymentError("Для каждого --node требуется уникальная запись вида label=trusted-ssh-host")
        if host in nodes.values():
            raise DeploymentError("Одна цель SSH указана несколько раз")
        nodes[name] = host
    if len(nodes) < 2:
        raise DeploymentError("Требуются как минимум два независимых SSH-узла")
    return nodes


def assert_peer_config(reports):
    seen_machine = set()
    seen_node = set()
    first = next(iter(reports.values()))
    for name, report in reports.items():
        if not report.get("configurationValidated"):
            raise DeploymentError(name + " не имеет корректной многоузловой конфигурации")
        machine = report.get("machineIdentity")
        node_id = report.get("nodeId")
        if not machine or machine in seen_machine or not node_id or node_id in seen_node:
            raise DeploymentError("Идентификаторы machine ID или node ID отсутствуют либо повторяются: узлы нельзя считать независимыми")
        seen_machine.add(machine)
        seen_node.add(node_id)
        if report.get("imageDigestRefs") != first.get("imageDigestRefs"):
            raise DeploymentError("На хостах закреплены разные образы; различие версий в кластере не поддерживается в 0.51.2")
        if report.get("sharedEndpoints") != first.get("sharedEndpoints"):
            raise DeploymentError("Хосты используют разные публичные источники или эндпоинты общих зависимостей")


def collect_cluster(nodes, script, directory, project, mode, *, growth=True):
    reports = {name: remote_call(target, script, directory, project, mode, growth=growth)
               for name, target in nodes.items()}
    assert_peer_config(reports)
    return reports


def validate_edge_url(url):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise DeploymentError("Некорректное значение: «URL внешнего балансировщика нагрузки»") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.path not in ("", "/", "/ready"):
        raise DeploymentError("Внешнему балансировщику требуется HTTPS-адрес или /ready без учётных данных")
    return url


def edge_ready(url, count=3):
    # Используйте публичный путь DNS/балансировщика нагрузки, а не точку доступа,
    # привязанную к ещё работающему хосту.
    validate_edge_url(url)
    result = inventory.probe_public_edge(url, count)
    return result["success"] == count, result


def cluster_verify(reports, edge_url):
    assert_peer_config(reports)
    issues = []
    engines = [r.get("live", {}).get("dockerEngineIdentity") for r in reports.values()]
    if not all(engines) or len(set(engines)) != len(engines):
        issues.append("Идентификаторы Docker Engine отсутствуют или повторяются на узлах SSH")
    for name, report in reports.items():
        if report.get("ready") is not True:
            issues.append(name + " Проверка готовности окружения выполнения не пройдена")
    for name, report in reports.items():
        live = report.get("live")
        if not isinstance(live, dict):
            issues.append(name + " не имеет фактического состояния Docker")
            continue
        roles = {i["service"]: i for i in live.get("containers", [])}
        for service in SERVICES:
            item = roles.get(service)
            if not item or not item.get("running"):
                issues.append(name + ": отсутствует запущенный " + service)
    ok, edge = edge_ready(edge_url)
    if not ok:
        issues.append("Внешний балансировщик HTTPS не вернул успешный ответ /ready на всех проверках")
    return {"schema": SCHEMA, "version": VERSION, "observedUtc": inventory.utc_now(),
            "nodes": reports, "publicEdge": edge, "issues": issues,
            "multiHostControlPlaneObserved": not issues,
            "hostFailureTested": False, "dependencyHAUnverified": True}


def outage_drill(nodes, script, directory, project, edge_url, failed_node):
    if failed_node not in nodes:
        raise DeploymentError("Отказавший узел отсутствует в целевом кластере")
    before = collect_cluster(nodes, script, directory, project, "local-observe")
    normal = cluster_verify(before, edge_url)
    if not normal["multiHostControlPlaneObserved"]:
        raise DeploymentError("Нельзя начинать проверку отказоустойчивости при неисправном исходном состоянии")
    survivor_name = next(n for n in nodes if n != failed_node)
    stopped = False
    restore_error = None
    observations = []
    try:
        # Выполняется только после явного --allow-disruption. Удаляет ВСЕ контейнеры
        # входного шлюза, API, рабочих процессов и Admin на выбранном хосте Docker.
        remote_stop_start(nodes[failed_node], script, directory, project, "stop")
        stopped = True
        for attempt in range(15):
            ok, sample = edge_ready(edge_url, 3)
            observations.append({"attempt": attempt + 1, "success": sample["success"],
                                 "sampled": sample["sampled"]})
            if ok:
                break
            time.sleep(3)
        else:
            raise DeploymentError("Внешний балансировщик HTTPS не восстановился после остановки целого узла")
        survivor = remote_call(nodes[survivor_name], script, directory, project, "local-observe")
        if not survivor.get("ready"):
            raise DeploymentError("После имитации отказа хоста API и рабочий процесс уцелевшего узла неработоспособны")
        success = True
    except DeploymentError as exc:
        success = False
        failure = str(exc)
    finally:
        # Пытайтесь восстановить работу, даже если SSH-команда частично завершилась с
        # ошибкой.
        try:
            remote_stop_start(nodes[failed_node], script, directory, project, "start")
        except DeploymentError as exc:
            restore_error = str(exc)
    if stopped and success and restore_error is None:
        try:
            after = collect_cluster(nodes, script, directory, project, "local-observe")
            recovered = cluster_verify(after, edge_url)["multiHostControlPlaneObserved"]
        except DeploymentError:
            recovered = False
    else:
        recovered = False
    report = {"schema": SCHEMA, "version": VERSION, "observedUtc": inventory.utc_now(),
              "failedNode": failed_node, "survivor": survivor_name, "performedStop": stopped,
              "publicEdgeUnderOutage": observations,
              "survivorAvailable": bool(success), "restorationVerified": recovered,
              "testPassed": bool(stopped and success and recovered and restore_error is None),
              "scope": "Остановлен весь стек приложения Compose; это НЕ физическое отключение питания, разделение сети или переключение зависимостей"}
    if restore_error:
        report["restorationFailure"] = restore_error
    if not success:
        report["testFailure"] = failure
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("local-check", "local-up", "local-observe", "local-stop", "local-start",
                                         "cluster-check", "cluster-up", "cluster-verify", "cluster-drill", "local-compat-observe"))
    parser.add_argument("--directory", default="/opt/launcher/deploy/production")
    parser.add_argument("--project", default="launcher")
    parser.add_argument("--node", action="append", default=[], help="label=ssh-user@host (повторяемый параметр)")
    parser.add_argument("--remote-script", default="/opt/launcher/scripts/operations/multi_host_0512.py")
    parser.add_argument("--edge-url", help="Внешний адрес HTTPS-балансировщика или /ready")
    parser.add_argument("--failed-node", help="Метка узла для отключения во время cluster-drill")
    parser.add_argument("--allow-disruption", action="store_true", help="Обязательно для cluster-drill")
    parser.add_argument("--skip-growth", action="store_true")
    parser.add_argument("--output", required=True, help="Новый путь отчёта или - для JSON в stdout")
    args = parser.parse_args(argv)
    try:
        directory = Path(args.directory)
        if not directory.is_absolute() or not PROJECT_REGEX.fullmatch(args.project):
            raise DeploymentError("Некорректный абсолютный путь каталога или проекта")
        if args.mode.startswith("local-"):
            if args.mode == "local-check":
                report = resolved_compose(directory, args.project)
            elif args.mode == "local-up":
                report = local_up(directory, args.project)
            elif args.mode == "local-observe":
                report = live_observe(directory, args.project, growth=not args.skip_growth)
            elif args.mode == "local-compat-observe":
                report = local_compat_observe_0516(directory, args.project)
            elif args.mode in ("local-stop", "local-start"):
                resolved_compose(directory, args.project)
                action = "stop" if args.mode == "local-stop" else "start"
                # В учебном сценарии порядок остановки не даёт рабочим процессам начинать
                # новые операции; up перезапускает всё закреплённое развёртывание.
                if action == "stop":
                    run(compose_command(directory, args.project, "stop", "-t", "15", *SERVICES), cwd=directory, timeout=95)
                else:
                    run(compose_command(directory, args.project, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180"), cwd=directory, timeout=230)
                report = {**resolved_compose(directory, args.project), "action": action, "executed": True}
            inventory.write_report(args.output, report)
            return 3 if report.get("ready") is False else 0
        nodes = parse_nodes(args.node)
        if args.mode == "cluster-check":
            report = {"schema": SCHEMA, "version": VERSION, "nodes": collect_cluster(
                nodes, args.remote_script, args.directory, args.project, "local-check"),
                "configurationValidated": True, "hostFailureTested": False}
        elif args.mode == "cluster-up":
            if not args.edge_url:
                raise DeploymentError("Перед развёртыванием хостов необходимо указать --edge-url")
            validate_edge_url(args.edge_url)
            collect_cluster(nodes, args.remote_script, args.directory, args.project, "local-check")
            for name, target in nodes.items():
                deployed = remote_call(target, args.remote_script, args.directory, args.project,
                                       "local-up", timeout=520)
                if not deployed.get("ready"):
                    raise DeploymentError(name + " не прошёл проверку фактического запуска")
            report = cluster_verify(collect_cluster(nodes, args.remote_script, args.directory, args.project,
                                                     "local-observe"), args.edge_url)
        elif args.mode == "cluster-verify":
            if not args.edge_url:
                raise DeploymentError("Для проверки кластера необходимо указать --edge-url")
            validate_edge_url(args.edge_url)
            report = cluster_verify(collect_cluster(nodes, args.remote_script, args.directory, args.project,
                                                     "local-observe", growth=not args.skip_growth), args.edge_url)
        else:
            if not args.allow_disruption or not args.edge_url or not args.failed_node:
                raise DeploymentError("Для cluster-drill необходимы --allow-disruption, --failed-node и --edge-url")
            validate_edge_url(args.edge_url)
            report = outage_drill(nodes, args.remote_script, args.directory, args.project,
                                  args.edge_url, args.failed_node)
        inventory.write_report(args.output, report)
        return 0 if (report.get("configurationValidated") or report.get("multiHostControlPlaneObserved")
                     or report.get("testPassed")) else 3
    except (DeploymentError, inventory.InventoryError) as exc:
        print("Многоузловая операция недоступна: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
