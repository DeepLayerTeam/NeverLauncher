#!/usr/bin/env python3
"""0.51.6: допуск *живой* смешанной версии API/worker и PostgreSQL с блокировкой при неопределённости.

Поддерживается только проверенная пара 0.51.5 -> 0.51.6. DDL не применяется, контейнеры не
обновляются; контроллер поэтапного обновления относится к следующему выпуску. Запускать с независимо
доверенного хоста с доступом к активному PostgreSQL writer и по SSH к обоим Docker-хостам. Метки
контейнера и VERSION-файл не доказывают версию работающего процесса.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import parse_qs, unquote, urlsplit

import ha_inventory as inventory
import multi_host as multi

PAIR = frozenset(("0.51.5", "0.51.6"))
# Зафиксировано под точный каталог миграций PostgreSQL поставленной версии 0.51.5.
# Изменение даже добавочной миграции требует отдельно проверенного пути N-1:
# проверка миграций 0.51.5 отклонит неизвестную строку при каждом /ready.
CATALOG_SHA256_0515 = "12247e5cb196efb8a77d52c64dd55e4b4956703100a928c65d8be0c978c723ce"
SCHEMA = "launcher.nn1-live-compat.0.51.6"
ROOT = Path(__file__).resolve().parents[2]

class CompatibilityError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise CompatibilityError(reason)


def migration_catalog(folder=ROOT / "services/api/internal/dbmigrate/sql"):
    files = sorted(folder.glob("*.sql"))
    require(len(files) >= 100, "Отсутствует встроенный каталог миграций PostgreSQL")
    digest = hashlib.sha256()
    versions = {}
    for item in files:
        require(re.fullmatch(r"[a-zA-Z0-9_]+\.sql", item.name) and item.is_file() and not item.is_symlink(),
                "Небезопасный элемент каталога миграций")
        content = item.read_bytes()
        checksum = hashlib.sha256(content).hexdigest()
        name = item.stem
        require(name not in versions, "Повторяющееся имя миграции")
        digest.update(item.name.encode("ascii") + b"\0" + checksum.encode("ascii") + b"\n")
        versions[name] = checksum
    # Пока активен хотя бы один экземпляр 0.51.5, новые миграции развёртывать
    # нельзя.
    require(digest.hexdigest() == CATALOG_SHA256_0515, "0.51.5 каталог изменился; безопасность схемы при смешанных версиях не подтверждена")
    return versions, digest.hexdigest()


def dsn_environment(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and
            (stat.S_IMODE(path.stat().st_mode) & 0o077) == 0, "Требуется закрытый файл DSN PostgreSQL с правами 0600")
    content = path.read_text(encoding="utf-8")
    require(len(content) < 8192 and len(content.splitlines()) == 1, "Файл DSN должен содержать ровно один URL PostgreSQL")
    parsed = urlsplit(content.strip())
    require(parsed.scheme in ("postgres", "postgresql") and parsed.hostname and parsed.path not in ("", "/")
            and parsed.username and parsed.password is not None and not parsed.fragment,
            "В URL PostgreSQL должны быть указаны узел, база данных и учётные данные")
    query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
    require(set(query) <= {"sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout"}
            and all(len(v) == 1 for v in query.values()) and query.get("sslmode") == ["verify-full"],
            "URL PostgreSQL должен требовать проверки имени узла через TLS (verify-full)")
    # Явное окружение имеет приоритет над внешней конфигурацией libpq; никогда не
    # записывайте DSN в журнал.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGHOST=parsed.hostname, PGPORT=str(parsed.port or 5432),
               PGUSER=unquote(parsed.username), PGPASSWORD=unquote(parsed.password),
               PGDATABASE=unquote(parsed.path.lstrip("/")), PGSSLMODE="verify-full",
               PGCONNECT_TIMEOUT=query.get("connect_timeout", ["8"])[0])
    for field in ("sslrootcert", "sslcert", "sslkey"):
        if field in query:
            env["PG" + field.upper()] = query[field][0]
    return env


def live_pg_migrations(path):
    env = dsn_environment(path)
    # Записанные миграции сами по себе не обнаруживают ручной DROP COLUMN.
    # Проверяйте реальные столбцы, обеспечивающие разграничение заданий, outbox и
    # управления Bridge.
    expected = (
        ("durable_jobs", "lease_fence"), ("durable_jobs", "lease_token"),
        ("durable_jobs", "lease_expires_at"), ("event_outbox", "lease_fence"),
        ("event_outbox", "lease_token"), ("event_outbox", "lease_expires_at"),
        ("server_bridge_control_commands_v3", "lease_token"),
        ("server_bridge_control_commands_v3", "lease_until"),
        ("server_bridge_control_commands_v3", "delivery_sequence"),
    )
    values = ",".join("('%s','%s')" % pair for pair in expected)
    sql = ("BEGIN TRANSACTION READ ONLY;\n"
           "SELECT CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END;\n"
           "WITH expected(t,c) AS (VALUES " + values + ") "
           "SELECT CASE WHEN EXISTS (SELECT 1 FROM expected e WHERE NOT EXISTS "
           "(SELECT 1 FROM information_schema.columns i WHERE i.table_schema=current_schema() "
           "AND i.table_name=e.t AND i.column_name=e.c)) "
           "THEN 'shape-mismatch' ELSE 'shape-ok' END;\n"
           "SELECT row_to_json(x)::text FROM "
           "(SELECT version,checksum FROM schema_migrations WHERE version IS NOT NULL ORDER BY version) AS x;\n"
           "COMMIT;\n")
    try:
        proc = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1"],
                              input=sql, text=True, capture_output=True, env=env, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CompatibilityError("Не удалось проверить схему работающей PostgreSQL") from exc
    # stderr может содержать строки подключения, учётные данные или внутренние
    # сведения.
    require(proc.returncode == 0 and len(proc.stdout) <= 200_000, "Проверка схемы рабочего PostgreSQL завершилась ошибкой")
    rows = [s.strip() for s in proc.stdout.splitlines() if s.strip()]
    require(rows and rows[0] == "primary", "DSN PostgreSQL не указывает на доступный для записи основной узел")
    require(len(rows) >= 2 and rows[1] == "shape-ok", "Фактические схемы durable/outbox/ServerBridge несовместимы")
    actual = {}
    for row in rows[2:]:
        try:
            data = json.loads(row)
        except (ValueError, TypeError) as exc:
            raise CompatibilityError("PostgreSQL вернул строку миграции, которую невозможно разобрать") from exc
        require(isinstance(data, dict) and isinstance(data.get("version"), str) and
                isinstance(data.get("checksum"), str), "Недопустимая строка отслеживания миграций")
        require(data["version"] not in actual, "Обнаружены повторно применённые миграции")
        actual[data["version"]] = data["checksum"]
    return actual


def validate_schema(actual, catalog):
    pending = sorted(catalog.keys() - actual.keys())
    unknown = sorted(actual.keys() - catalog.keys())
    drift = sorted(k for k in actual.keys() & catalog.keys() if actual[k] != catalog[k])
    require(not pending and not unknown and not drift,
            "Схема PostgreSQL отличается от закреплённого каталога обеих версий (ожидают применения=%d неизвестных=%d расхождений контрольных сумм=%d)" %
            (len(pending), len(unknown), len(drift)))
    return {"checkedMigrations": len(catalog), "pending": 0, "unknown": 0, "checksumDrift": 0}


def validate_live_nodes(reports, *, require_mixed=False, pair=PAIR):
    require(len(reports) >= 2, "Требуются минимум два независимо проверенных узла")
    machines, engines, node_ids = set(), set(), set()
    baseline = None
    versions = {}
    observed_contracts = None
    for label, report in reports.items():
        require(report.get("schema") == multi.SCHEMA and report.get("configurationValidated") is True
                and report.get("ready") is True and not report.get("issues"), "Узел не готов к рабочему режиму: " + label)
        machine = report.get("machineIdentity")
        node_id = report.get("nodeId")
        live = report.get("live") or {}
        engine = live.get("dockerEngineIdentity")
        require(machine and engine and node_id and machine not in machines and engine not in engines
                and node_id not in node_ids, "Дублирующийся или отсутствующий идентификатор узла, движка или реплики")
        machines.add(machine); engines.add(engine); node_ids.add(node_id)
        refs = report.get("imageDigestRefs") or {}
        require(refs.get("api") == refs.get("worker") and multi.DIGEST_REGEX.fullmatch(refs.get("api", "")),
                "API и обработчик должны использовать один и тот же закреплённый образ на каждом узле")
        shared = report.get("sharedEndpoints")
        require(isinstance(shared, dict) and shared and (baseline is None or shared == baseline),
                "Смешанные версии указывают на разные конечные точки зависимостей")
        baseline = shared
        running = {c.get("service"): c for c in live.get("containers", [])}
        actual_versions = []
        for role in ("api", "worker"):
            item = running.get(role) or {}
            readiness = item.get("readiness") or {}
            require(item.get("running") is True and item.get("health") == "healthy"
                    and readiness.get("success") == readiness.get("sampled") == 3
                    and readiness.get("versionVerified") is True
                    and readiness.get("version") in pair,
                    "на узле отсутствует или не поддерживается версия готовности API/обработчика: " + label + "/" + role)
            require(item.get("environment", {}).get("LAUNCHER_REPLICA_ID") == node_id + "-" + role,
                    "неверный идентификатор роли действующей реплики на узле " + label)
            actual_versions.append(readiness["version"])
        require(actual_versions[0] == actual_versions[1], "Версии API и обработчика не совпадают на узле " + label)
        versions[label] = actual_versions[0]
        contracts = report.get("compatibility0516")
        require(isinstance(contracts, dict) and contracts.get("liveVersion") == actual_versions[0]
                and contracts.get("apiStatus") == "ok" and contracts.get("bridgeProtocol") == 3,
                "отсутствуют действующие HTTP-проверки совместимости для " + label)
        fingerprints = tuple(contracts.get(k) for k in (
            "loadersSHA256", "runtimeRequirementsSHA256", "bridgeContractSHA256"))
        require(all(re.fullmatch(r"[0-9a-f]{64}", value or "") for value in fingerprints),
                "Недопустимый отпечаток контракта действующих API/Bridge на " + label)
        require(observed_contracts is None or observed_contracts == fingerprints,
                "Контракты работающих API и Bridge различаются между поддерживаемыми версиями")
        observed_contracts = fingerprints
    require(not require_mixed or set(versions.values()) == pair, "Для запуска со смешанными версиями требуются обе версии: N и N-1")
    return versions


def verify(args):
    catalog, digest = migration_catalog()
    nodes = multi.parse_nodes(args.node)
    multi.validate_edge_url(args.edge_url)
    # Запускайте живые наблюдения SSH на ФАКТИЧЕСКИХ хостах, а не по локально
    # кэшированным манифестам.
    reports = {label: multi.remote_call(target, args.remote_script, args.directory, args.project,
                                        "local-compat-observe", growth=True, timeout=180)
               for label, target in nodes.items()}
    versions = validate_live_nodes(reports, require_mixed=args.require_mixed)
    migrations = validate_schema(live_pg_migrations(args.pg_dsn_file), catalog)
    ready, edge = multi.edge_ready(args.edge_url)
    require(ready, "Внешний HTTPS-шлюз не прошёл реальные проверки готовности")
    return {"schema": SCHEMA, "verified": True, "sourceVersion": "0.51.5", "targetVersion": "0.51.6",
            "liveVersions": versions, "hostCount": len(reports), "catalogSHA256": digest,
            "postgres": migrations, "edge": {"success": edge.get("success"), "sampled": edge.get("sampled")},
            "limit": "Запрещены DDL, горячая перезагрузка расширений/JVM-агентов разных версий и живая миграция игровых процессов"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Допуск смешанных версий API/worker и PostgreSQL 0.51.5/0.51.6 на живой системе")
    ap.add_argument("--node", action="append", required=True, help="label=ssh-user@node (повторяемый параметр)")
    ap.add_argument("--directory", default="/opt/launcher/deploy/production")
    ap.add_argument("--project", default="launcher")
    ap.add_argument("--remote-script", default="/opt/launcher/scripts/operations/multi_host.py")
    ap.add_argument("--edge-url", required=True)
    ap.add_argument("--pg-dsn-file", type=Path, required=True, help="Один закрытый URL postgres:// с правами 0600; не передавать секреты в argv")
    ap.add_argument("--require-mixed", action="store_true")
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)
    try:
        require(os.path.isabs(args.directory) and multi.PROJECT_REGEX.fullmatch(args.project),
                "Недопустимый удалённый каталог или проект")
        report = verify(args)
        inventory.write_report(args.output, report)
        print("Совместимость N/N−1 на работающей системе проверена; каталог миграций не изменён, DDL не выполнялись", file=sys.stderr)
        return 0
    except (CompatibilityError, multi.DeploymentError, inventory.InventoryError, OSError, ValueError) as exc:
        print("ПРОВЕРКА СОВМЕСТИМОСТИ N/N-1 ЗАБЛОКИРОВАНА: " + str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
