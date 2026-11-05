#!/usr/bin/env python3
"""0.51.9: восстановить замороженную группу 0.51.8 на *новых* хостах Docker/игры/PG.

Порядок: prepare -> replay-postgres -> admit. prepare/admit выполняет оператор из закрытой среды,
replay-postgres — системный пользователь PostgreSQL на изолированном новом хосте БД. Утилита не
может изолировать исходную среду: перед продвижением воспроизведения и публичным допуском обязателен
отдельно обеспеченный шлюз отсечения источника.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

import consistent_backup_0518 as cb
import dr_03512 as dr
import multi_host_0512 as multi
import nn1_compat_0516 as nn

SCHEMA = "neverlauncher.cross-host-recovery/0.51.9"
STATE = "recovery-state-0519.json"
RECORD = "recovery-result-0519.json"
MAX_TRANSFER = 1 << 42

class RecoveryError(RuntimeError):
    pass

def require(condition, reason):
    if not condition:
        raise RecoveryError(reason)

def now():
    return datetime.now(timezone.utc)

def absolute_fresh(path: Path):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), "destination must be a fresh absolute path")
    require(path.parent.is_dir() and not path.parent.is_symlink(), "destination parent missing or symlinked")
    require(all(not p.is_symlink() for p in path.parents), "unsafe destination ancestry")

def private_directory(path: Path):
    require(path.is_dir() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0,
            "directory must exist and be private (0700)")

def parse_pairs(values, *, expected=None):
    result = {}
    for item in values:
        label, sep, value = item.partition("=")
        require(sep and cb.NAME.fullmatch(label) and value and label not in result,
                "invalid or duplicated name=value")
        result[label] = value
    if expected is not None:
        require(set(result) == set(expected), "recovery target set differs from checkpoint")
    return result

def verified_source(backup: Path, stanza: str, trust_file: Path):
    cb.validate_backup(backup, stanza=stanza)
    manifest = cb.read_private_json(backup / "manifest.json")
    require(manifest["schema"] == cb.SCHEMA and manifest.get("version") == "0.51.8", "unsupported checkpoint")
    trust = cb.read_private_json(trust_file)
    require(isinstance(trust, dict) and trust and trust == manifest["trustEscrowSha256"],
            "independently escrowed trust roots do not match checkpoint")
    require(manifest["externalAuthPolicy"] == "none" or
            (manifest["externalAuthPolicy"] == "included" and (backup / "external").is_dir()),
            "external identity provider recovery is incomplete")
    return manifest

def fresh_bucket(bucket, endpoint, source_bucket):
    require(bucket != source_bucket, "refusing to restore into source S3 bucket")
    require(cb.s3_version_inventory(bucket, endpoint) == [],
            "destination S3 bucket contains objects, versions or delete markers")

def target_spec(args, manifest):
    original_nodes = {r["label"] for r in manifest["nodes"]}
    nodes = parse_pairs(args.node, expected=original_nodes)
    require(len(nodes) >= 2 and len(set(nodes.values())) == len(nodes), "at least two distinct restore hosts required")
    for host in nodes.values():
        require(bool(multi.HOST_REGEX.fullmatch(host)) and not host.startswith("-"), "unsafe restore SSH target")
    worlds = parse_pairs(args.world_destination, expected={r["name"] for r in manifest["worlds"]})
    # Формат name=ssh-target:/absolute/new/path; команды оболочки или вводимые пользователем
    # команды не исполняются.
    entries = {}
    for name, value in worlds.items():
        host, sep, path = value.partition(":")
        require(sep and multi.HOST_REGEX.fullmatch(host) and path.startswith("/") and ".." not in Path(path).parts,
                "world requires trusted SSH target and absolute fresh destination")
        entries[name] = (host, path)
    require(args.project.startswith("nl-dr-") and bool(dr.PROJECT_PATTERN.fullmatch(args.project)),
            "isolated DR project must start with nl-dr-")
    require(bool(multi.DIGEST_REGEX.fullmatch(args.tar_image)), "unverified tar image (OCI digest required)")
    return nodes, entries

def transfer(host, script, mode, source: Path, *options, timeout=7200):
    require(source.is_file() and not source.is_symlink(), "source archive not available")
    cmd = cb.ssh(host, script, mode, *options)
    try:
        with source.open("rb") as stream:
            cp = subprocess.run(cmd, stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryError("Недоступно: «SSH recovery transfer»") from exc
    require(cp.returncode == 0 and len(cp.stdout) <= 65536, "remote restore refused or failed")
    try:
        return json.loads(cp.stdout)
    except (UnicodeError, ValueError) as exc:
        raise RecoveryError("Некорректное значение: «remote restore response»") from exc

def remote_json(host, script, mode, *options, timeout=180):
    data = cb.execute(cb.ssh(host, script, mode, *options), timeout=timeout)
    try:
        return json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise RecoveryError("Некорректное значение: «remote inventory»") from exc

def stdin_archive(expected_sha):
    require(bool(cb.HEX64.fullmatch(expected_sha)), "invalid transfer checksum")
    fd, filename = tempfile.mkstemp(prefix=".restore-0519-")
    os.fchmod(fd, 0o600)
    path = Path(filename)
    total = 0
    sha = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as output:
            while chunk := sys.stdin.buffer.read(1024 * 1024):
                total += len(chunk)
                require(total <= MAX_TRANSFER, "restore transfer exceeds configured limit")
                sha.update(chunk)
                output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        require(total > 0 and sha.hexdigest() == expected_sha, "transfer checksum mismatch")
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def docker_clean(project):
    require(bool(dr.PROJECT_PATTERN.fullmatch(project)), "invalid recovery project")
    active = cb.execute(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project])
    require(not active.strip(), "recovery project already contains containers")

def local_preflight(args):
    docker_clean(args.project)
    for name in cb.VOLUMES:
        vol = args.project + "_" + name
        cp = subprocess.run(["docker", "volume", "inspect", vol], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=20, check=False)
        require(cp.returncode != 0, "restoration volume already exists")
    identity = multi.inventory.machine_identity()
    require(bool(identity), "missing real machine identity")
    return {"status": "fresh", "machineIdentity": identity}

def restore_volume_local(args):
    docker_clean(args.project)
    require(args.volume in cb.VOLUMES and bool(multi.DIGEST_REGEX.fullmatch(args.tar_image)),
            "unsupported recovery volume/image")
    vol = args.project + "_" + args.volume
    # Проверяйте ДО чтения больших полезных данных, иначе Docker автоматически создаст каталоги
    # назначения.
    probe = subprocess.run(["docker", "volume", "inspect", vol], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, check=False)
    require(probe.returncode != 0, "volume already exists (no overwrite)")
    tarpath = stdin_archive(args.sha256)
    try:
        expected = dr.tar_digests(tarpath)
        cb.execute(["docker", "volume", "create", "--label", "neverlauncher.recovery=0.51.9", vol], timeout=40)
        with tarpath.open("rb") as data:
            cp = subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "-i",
                                 "--mount", f"type=volume,src={vol},dst=/target",
                                 args.tar_image, "tar", "-xzf", "-", "-C", "/target"],
                                stdin=data, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                timeout=7200, check=False)
        require(cp.returncode == 0, "Docker volume extraction failed")
        with tempfile.TemporaryDirectory(prefix=".readback-0519-") as temporary:
            readback = Path(temporary) / "readback.tar.gz"
            dr.stream_to_file(["docker", "run", "--rm", "--network", "none", "--read-only",
                               "--mount", f"type=volume,src={vol},dst=/source,readonly",
                               args.tar_image, "tar", "-czf", "-", "-C", "/source", "."],
                              readback, timeout=7200)
            require(expected == dr.tar_digests(readback), "volume readback differs from original files")
        return {"status": "restored", "volume": args.volume, "files": len(expected)}
    finally:
        tarpath.unlink(missing_ok=True)

def world_stream_archive(source: Path, target: Path):
    cb.require(dr.safe_world_backup(source)["id"] == source.name, "invalid world backup")
    with tarfile.open(target, "w:gz") as archive:
        archive.add(source, arcname=source.name, recursive=True)

def restore_world_local(args):
    dest = Path(args.destination)
    absolute_fresh(dest)
    require(bool(dr.WORLD_BACKUP_ID.fullmatch(args.backup_id)), "invalid world backup ID")
    tarpath = stdin_archive(args.sha256)
    try:
        with tempfile.TemporaryDirectory(prefix=".world-recovery-0519-", dir=dest.parent) as tmp:
            target = Path(tmp) / "unpacked"
            cb.unpack_safe_tar(tarpath, target)
            source = target / args.backup_id
            dr.safe_world_backup(source)
            dr.restore_world_backup(source, dest)
            manifest = dr.safe_world_backup(source)
            dr.safe_world_restored(dest, manifest)
        return {"status": "restored", "backupId": args.backup_id,
                "files": len(manifest["entries"])}
    finally:
        tarpath.unlink(missing_ok=True)

def state_path(work):
    return work / STATE

def persist(work, state):
    path = state_path(work)
    if path.exists():
        cb.atomic_replace(path, (json.dumps(state, sort_keys=True, indent=2) + "\n").encode())
    else:
        cb.save_exclusive(path, (json.dumps(state, sort_keys=True, indent=2) + "\n").encode())

def read_state(work):
    state = cb.read_private_json(state_path(work))
    require(state.get("schema") == SCHEMA, "wrong recovery state")
    return state

def prepare(args):
    backup, work = Path(args.backup), Path(args.work)
    private_directory(work)
    require(not state_path(work).exists(), "existing recovery journal (resume requires inspection)")
    manifest = verified_source(backup, args.stanza, Path(args.trust_file))
    nodes, worlds = target_spec(args, manifest)
    absolute_fresh(Path(args.pgdata))
    require(Path(args.pgdata).resolve() not in (backup.resolve(), work.resolve()) and
            backup.resolve() not in Path(args.pgdata).resolve().parents and
            work.resolve() not in Path(args.pgdata).resolve().parents, "PostgreSQL target overlaps protected backup/workspace")
    require(args.s3_bucket != manifest["s3"]["bucket"], "source bucket cannot be recovery bucket")
    fresh_bucket(args.s3_bucket, args.s3_endpoint, manifest["s3"]["bucket"])
    machine_ids = set()
    for host in nodes.values():
        data = remote_json(host, args.remote_script, "local-preflight", "--project", args.project)
        require(data.get("status") == "fresh" and data.get("machineIdentity") not in machine_ids and
                data["machineIdentity"] not in {r["machineIdentity"] for r in manifest["nodes"]},
                "recovery host must be a new independent machine")
        machine_ids.add(data["machineIdentity"])
    # Записывайте устойчивый журнал ДО любых разрушительных побочных эффектов. Никогда
    # не повторяйте неопределённое восстановление в частично заполненные тома, бакет или
    # PGDATA посредством незаметной перезаписи.
    state = {"schema": SCHEMA, "runId": manifest["runId"], "phase": "preparing",
             "startedUtc": now().isoformat(), "prepared": [], "nodes": nodes,
             "worldTargets": {n: list(v) for n,v in worlds.items()}, "project": args.project,
             "pgdata": args.pgdata, "bucket": args.s3_bucket,
             "cohortLsn": manifest["postgres"]["cohortLsn"],
             "frozenUtc": manifest["frozenUtc"], "backupCompletedUtc": manifest["completedUtc"]}
    persist(work, state)
    pgargs = argparse.Namespace(action="cohort-pg-restore-fresh", backup=str(backup),
                pgdata=args.pgdata, stanza=args.stanza,
                confirm=manifest["postgres"]["backup"]["label"])
    cb.restore_pg_fresh(pgargs)
    state["prepared"].append("postgres-files"); persist(work, state)
    dr.s3_upload_fresh(args.s3_bucket, backup / "s3", args.s3_endpoint, manifest["s3"]["files"])
    uploaded_versions = cb.s3_version_inventory(args.s3_bucket, args.s3_endpoint)
    require(len([v for v in uploaded_versions if v[0] == "Versions" and v[3] is True]) ==
            len(manifest["s3"]["files"]), "restored S3 inventory count mismatch")
    state["prepared"].append("s3-readback"); persist(work, state)
    for label, host in nodes.items():
        for vol in cb.VOLUMES:
            archive = backup / "hosts" / label / (vol + ".tar.gz")
            reply = transfer(host, args.remote_script, "local-restore-volume", archive,
                             "--project", args.project, "--volume", vol,
                             "--tar-image", args.tar_image, "--sha256", dr.sha256_file(archive))
            require(reply.get("status") == "restored" and reply.get("volume") == vol,
                    "recovered host volume not acknowledged")
            state["prepared"].append("volume:" + label + "/" + vol); persist(work, state)
    for row in manifest["worlds"]:
        name, wid = row["name"], row["backupId"]
        host, destination = worlds[name]
        source = backup / "worlds" / name / wid
        dr.safe_world_backup(source)
        with tempfile.TemporaryDirectory(prefix=".world-ship-0519-", dir=work) as tmp:
            archive = Path(tmp) / "world.tar.gz"
            world_stream_archive(source, archive)
            reply = transfer(host, args.remote_script, "local-restore-world", archive,
                             "--destination", destination, "--backup-id", wid,
                             "--sha256", dr.sha256_file(archive))
        require(reply.get("status") == "restored" and reply.get("backupId") == wid,
                "world recovery not acknowledged")
        state["prepared"].append("world:" + name); persist(work, state)
    # Внешние экспорты и секреты требуют отдельного явного восстановления и изоляции
    # прежнего кластера; скрипт не восстанавливает произвольные секреты.
    state["phase"] = "prepared-not-admitted"
    state["preparedUtc"] = now().isoformat()
    persist(work, state)
    return {"status": state["phase"], "runId": state["runId"], "restoredVolumes": len(nodes) * len(cb.VOLUMES),
            "worlds": len(worlds), "postgres": "files-only", "publicTraffic": "blocked"}

def lsn_value(value):
    high, low = value.split("/", 1)
    return (int(high, 16) << 32) | int(low, 16)

def pg_sql(port, query, socket_dir, *, timeout=60):
    cmd = ["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1",
           "-h", str(socket_dir), "-p", str(port), "-d", "postgres", "-c", query]
    return cb.execute(cmd, timeout=timeout).decode().strip()

def replay_postgres(args):
    work = Path(args.work); private_directory(work)
    state = read_state(work)
    require(state["phase"] == "prepared-not-admitted", "cohort not fully prepared")
    target = Path(state["pgdata"])
    require(target.is_dir() and (target / "PG_VERSION").is_file(), "PGDATA not restored")
    require(args.source_fenced, "source infrastructure must be independently fenced first")
    require(1024 < args.pg_port < 65536, "invalid isolated PostgreSQL port")
    require(args.socket_dir, "private PostgreSQL socket directory required")
    socket_dir = Path(args.socket_dir)
    private_directory(socket_dir)
    require(not any(socket_dir.iterdir()), "PostgreSQL recovery socket directory must be empty")
    # До проверки целевой точки WAL привязывайтесь ТОЛЬКО К UNIX-СОКЕТУ, а не к публичному
    # TCP-интерфейсу.
    options = f"-c listen_addresses='' -c unix_socket_directories={socket_dir} -c port={args.pg_port} -c hot_standby=on"
    cb.execute(["pg_ctl", "-D", str(target), "-o", options, "-w", "-t", "120", "start"], timeout=180)
    should_stop = True
    try:
        deadline = time.monotonic() + 180
        observed = ""
        while time.monotonic() < deadline:
            observed = pg_sql(args.pg_port,
                   "SELECT pg_is_in_recovery()::text || '|' || pg_is_wal_replay_paused()::text || '|' || coalesce(pg_last_wal_replay_lsn()::text,'');",
                   socket_dir)
            fields = observed.split("|")
            if len(fields) == 3 and fields[:2] == ["true", "true"]:
                break
            time.sleep(2)
        else:
            raise RecoveryError("PostgreSQL не достиг заданной точки восстановления WAL в режиме паузы")
        actual = fields[2]
        require(re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", actual) and
                lsn_value(actual) >= lsn_value(state["cohortLsn"]),
                "WAL replay did not reach cohort LSN")
        # pg_wal_replay_resume() доводит восстановление до конца при
        # recovery_target_action=pause.
        pg_sql(args.pg_port, "SELECT pg_wal_replay_resume();", socket_dir)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if pg_sql(args.pg_port, "SELECT pg_is_in_recovery();", socket_dir) == "f":
                break
            time.sleep(2)
        else:
            raise RecoveryError("Восстановленный PostgreSQL не перешёл в режим основного узла")
        # Только после этого объявляйте готовность PostgreSQL/Patroni к запуску под
        # управлением оператора.
        state["phase"] = "postgres-promoted-isolated"
        state["replayedLsn"] = actual
        state["promotedUtc"] = now().isoformat()
        persist(work, state)
    finally:
        if should_stop:
            cb.execute(["pg_ctl", "-D", str(target), "-m", "fast", "-w", "-t", "120", "stop"], timeout=180)
    return {"status": "postgres-promoted-isolated", "replayedLsn": actual,
            "next": "start PostgreSQL through the approved HA service manager before admit"}

def audit_recovery(ledger_file, pg_env, incident):
    """Необязательная выборочная оценка RPO на основе *внешнего* неизменяемого реестра подтверждений.

    Реестр источника обязан охватывать реально подтверждённые ID событий аудита. Нельзя считать
    отсутствие потерь аудита доказательством сохранности неаудированных данных S3/миров.
    """
    ledger = cb.read_private_json(Path(ledger_file))
    require(ledger.get("schema") == "neverlauncher.dr-ack-ledger/v1", "unsupported ack ledger")
    rows = ledger.get("entries")
    require(isinstance(rows, list) and rows and len(rows) <= 100000, "empty/oversized audit ledger")
    last = None
    recovered = 0
    missing = []
    seen = set()
    for row in rows:
        event_id = row.get("id")
        require(isinstance(event_id, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", event_id)
                and event_id not in seen, "bad/duplicate audit event ID")
        seen.add(event_id)
        stamp = datetime.fromisoformat(row["ackUtc"].replace("Z", "+00:00"))
        require(stamp.tzinfo is not None and stamp <= incident,
                "audit acknowledgement outside incident window")
        # Переменные psql с кавычками :'-quoted' позволяют не подставлять
        # идентификаторы как SQL-литералы.
        actual = cb.execute(["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1",
                             "-v", "audit_id=" + event_id],
                            input=b"SELECT id FROM audit_events WHERE id = :'audit_id';\n",
                            env=pg_env, timeout=30).decode().strip()
        require(actual in ("", event_id), "unexpected audit readback")
        if actual == event_id:
            last = stamp if last is None or stamp > last else last
            recovered += 1
        else:
            missing.append((event_id, stamp))
    require(last is not None, "no independently acknowledged audit event survived")
    # Более поздний ACK может не восстановиться, хотя более ранний восстановлен.
    # Сохраняйте это предупреждение вместо недостоверного утверждения, что RPO равен
    # возрасту одной контрольной точки.
    nonmonotonic = any(stamp <= last for _, stamp in missing)
    return {"sampledAuditRpoSeconds": None if nonmonotonic else
            round(max(0, (incident - last).total_seconds()), 3),
            "auditEventsRecovered": recovered, "auditEventsMissing": len(missing),
            "nonMonotonicRecovery": nonmonotonic,
            "auditCoverage": "only IDs in external ledger; other writes/worlds/S3 not measured"}

def assert_recovered_runtime(report):
    require(report.get("ready") is True and report.get("configurationValidated") is True,
            "recovery host did not pass live readiness")
    containers = {row.get("service"): row for row in (report.get("live") or {}).get("containers", [])}
    for role in ("api", "worker"):
        row = containers.get(role) or {}
        ready = row.get("readiness") or {}
        require(row.get("running") is True and ready.get("versionVerified") is True and
                ready.get("version") == "0.51.9" and ready.get("success") == ready.get("sampled") == 3,
                "recovered " + role + " is not the running verified 0.51.9 binary")
    return True

def admission(args):
    work = Path(args.work); private_directory(work)
    state = read_state(work)
    require(state["phase"] == "postgres-promoted-isolated", "PostgreSQL recovery not proven")
    require(args.source_fenced and args.external_secrets_restored,
            "old writers must be fenced and secrets/external auth separately restored")
    require(args.project == state["project"], "project mismatch")
    nodes = state["nodes"]
    require(args.ready_url and args.incident_at, "public readiness and incident timestamp required for RTO")
    incident = datetime.fromisoformat(args.incident_at.replace("Z", "+00:00"))
    frozen = datetime.fromisoformat(state["frozenUtc"].replace("Z", "+00:00"))
    require(incident.tzinfo is not None and frozen.tzinfo is not None and frozen <= incident <= now(),
            "incident timestamp invalid or older than checkpoint")
    # Проверьте, что НОВЫЙ PostgreSQL действительно допускает запись через свою
    # защищённую служебную точку подключения.
    from nn1_compat_0516 import dsn_environment
    env = dsn_environment(Path(args.pg_dsn_file))
    result = cb.execute(["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1",
                         "-c", "SELECT NOT pg_is_in_recovery();"], env=env, timeout=45).decode().strip()
    require(result == "t", "managed recovered PostgreSQL is not writable")
    catalog, _ = nn.migration_catalog()
    nn.validate_schema(nn.live_pg_migrations(Path(args.pg_dsn_file)), catalog)
    audit = audit_recovery(args.ack_ledger, env, incident) if args.ack_ledger else None
    state["phase"] = "admitting"
    persist(work, state)
    reports = {}
    for label, host in nodes.items():
        row = remote_json(host, args.multi_host_script, "local-up", "--directory", args.directory,
                          "--project", args.project, "--output", "-", timeout=480)
        assert_recovered_runtime(row)
        reports[label] = row
        state["prepared"].append("api-worker:" + label)
        persist(work, state)
    require(multi.cluster_verify(reports, args.ready_url)["multiHostControlPlaneObserved"] is True,
            "public ingress and recovered multi-host services failed readiness")
    end = now()
    # RTO измеряется от УКАЗАННОГО времени начала инцидента до фактической
    # готовности. RPO невозможно измерить без независимо зарегистрированных
    # подтверждённых записей; прошедшее время даёт лишь консервативную оценку
    # возраста точки восстановления.
    result = {"schema": SCHEMA, "status": "recovery-ready", "runId": state["runId"],
              "readyUtc": end.isoformat(), "incidentUtc": incident.isoformat(),
              "rtoSeconds": round((end - incident).total_seconds(), 3),
              "rtoScope": "control-plane public ingress readiness; not Minecraft world join",
              "recoveryPointAgeSeconds": round((incident - frozen).total_seconds(), 3),
              "rpoMeasured": False, "rpoNote": "requires external last-acknowledged-write ledger and readback",
              "nodesReady": len(reports), "worlds": len(state["worldTargets"]),
              "fencing": "operator independently attested; not machine-verifiable"}
    if audit is not None:
        result["sampledRpo"] = audit
    cb.save_exclusive(work / RECORD, (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    state["phase"] = "recovery-ready"; persist(work, state)
    return result

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "replay-postgres", "admit", "local-preflight", "local-restore-volume", "local-restore-world", "status"))
    p.add_argument("--backup"); p.add_argument("--work"); p.add_argument("--stanza")
    p.add_argument("--pgdata"); p.add_argument("--pg-dsn-file")
    p.add_argument("--trust-file"); p.add_argument("--node", action="append", default=[])
    p.add_argument("--world-destination", action="append", default=[])
    p.add_argument("--project", default="")
    p.add_argument("--remote-script", default="/opt/launcher/scripts/operations/cross_host_recovery_0519.py")
    p.add_argument("--multi-host-script", default="/opt/launcher/scripts/operations/multi_host_0512.py")
    p.add_argument("--directory", default="/opt/launcher/deploy/production")
    p.add_argument("--tar-image"); p.add_argument("--volume"); p.add_argument("--sha256")
    p.add_argument("--destination"); p.add_argument("--backup-id")
    p.add_argument("--s3-bucket"); p.add_argument("--s3-endpoint")
    p.add_argument("--socket-dir"); p.add_argument("--pg-port", type=int, default=55439)
    p.add_argument("--source-fenced", action="store_true")
    p.add_argument("--external-secrets-restored", action="store_true")
    p.add_argument("--ready-url"); p.add_argument("--incident-at"); p.add_argument("--ack-ledger")
    args = p.parse_args(argv)
    try:
        if args.action == "local-preflight":
            result = local_preflight(args)
        elif args.action == "local-restore-volume":
            result = restore_volume_local(args)
        elif args.action == "local-restore-world":
            result = restore_world_local(args)
        elif args.action == "prepare":
            result = prepare(args)
        elif args.action == "replay-postgres":
            result = replay_postgres(args)
        elif args.action == "admit":
            result = admission(args)
        else:
            result = read_state(Path(args.work))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RecoveryError, cb.BackupError, dr.DrillError, multi.DeploymentError,
            nn.CompatibilityError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "failed", "reason": type(exc).__name__}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
