#!/usr/bin/env python3
"""NeverLauncher 0.51.1: read-only, *live* HA inventory and failure-domain audit.

Requires Docker on each inspected host and optional SSH for remote hosts. It
never changes containers, databases, leases or files in the installation.
Growth diagnostics use the existing real PG advisory-lock, Redis lease and S3
round-trip probes (which create and remove uniquely named temporary objects).
No secret, Docker environment block, raw logs or URL credentials are exported.

This is a baseline *detector*, not a certificate of physical HA or partition
safety. Indeterminate evidence is explicitly UNVERIFIED, never PASS.
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
# Names only. Values are never written to a report or to an exception.
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
    """All argv are explicit; no subprocess shell or stdout/stderr in errors."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("command unavailable or timed out: " + str(argv[0])) from exc
    if proc.returncode not in allowed_codes:
        raise InventoryError("command failed: " + str(argv[0]) + " (exit " + str(proc.returncode) + ")")
    if len(proc.stdout) > MAX_OUTPUT:
        raise InventoryError("command output exceeds bounded inventory limit")
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
    # Only the host is returned; userinfo, path, db name, query and secret
    # never leave this function. libpq keyword DSNs are not exposed.
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
        raise InventoryError("too many containers; narrow Docker project")
    return ids


def docker_inspect(ids):
    if not ids:
        return []
    try:
        data = json.loads(execute(["docker", "inspect", *ids], timeout=20))
    except (ValueError, TypeError) as exc:
        raise InventoryError("Docker inspect returned invalid JSON") from exc
    if not isinstance(data, list) or len(data) != len(ids):
        raise InventoryError("Docker inspect response does not match requested containers")
    return data


def classify_container(raw, project):
    cfg = raw.get("Config") or {}
    labels = cfg.get("Labels") or {}
    if labels.get("com.docker.compose.project") != project:
        raise InventoryError("Docker inspect project mismatch")
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
    """Probe actual HTTP readiness, retaining the binary version for mixed-rollout gates.

    Older response shapes remain observable but cannot qualify for N/N-1
    compatibility; the version must come from the running process, never image
    tags, Compose environment, a local VERSION file or a status-only probe.
    """
    durations = []
    failures = 0
    versions = []
    for _ in range(count):
        start = time.monotonic_ns()
        try:
            raw = execute(["docker", "exec", container_id, "wget", "-qO-", "-T", "5",
                           "http://127.0.0.1:8080/ready"], timeout=8)
            # Only a JSON {status:"ready",version:"..."} from the backend
            # is a trustworthy software version. Never silently infer it.
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
            raise ValueError("unexpected PostgreSQL status")
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
    """Source-traced risk inventory; never asserts that runtime state is shared."""
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
        problems.append("host OS identity unavailable; cannot distinguish failure domains")
    if not engine_id:
        problems.append("Docker daemon identity unavailable")
    if not items:
        problems.append("no running or stopped project containers found")
    for item in items:
        service = item["service"]
        if service in ("api", "api-b", "worker", "worker-a", "worker-b"):
            item["readiness"] = docker_ready(item["containerId"], samples) if item["running"] else {
                "sampled": 0, "success": 0, "failures": 0, "p50Ms": None, "p95Ms": None}
            if item["readiness"]["success"] != samples:
                problems.append("%s readiness did not pass all real probes" % service)
            if item["health"] not in ("healthy", "not-configured"):
                problems.append("%s Docker health is %s" % (service, item["health"]))
            env = item["environment"]
            wanted_role = "api" if service in ("api", "api-b") else "worker"
            if env.get("LAUNCHER_PROCESS_ROLE") != wanted_role:
                problems.append("%s is not running dedicated %s role" % (service, wanted_role))
            for key, target in (("LAUNCHER_REPOSITORY_DRIVER", "postgres"),
                                ("LAUNCHER_STORAGE_DRIVER", "s3"),
                                ("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "true"),
                                ("LAUNCHER_DATABASE_AUTO_MIGRATE", "false"),
                                ("LAUNCHER_RATE_LIMIT_ENABLED", "true"),
                                ("LAUNCHER_RATE_LIMIT_FAIL_CLOSED", "true")):
                if env.get(key, "").lower() != target:
                    problems.append("%s unsafe %s" % (service, key))
            if env.get("LAUNCHER_DEPLOYMENT_MODE") != "network-ha":
                problems.append("%s is not configured for network-ha" % service)
            if not env.get("LAUNCHER_REPLICA_ID", "").strip():
                problems.append("%s missing stable LAUNCHER_REPLICA_ID" % service)
            if env.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", ""):
                problems.append("%s still uses SQLite coordinator" % service)
            if growth and service in ("api", "api-b") and item["running"]:
                item["dependencyRoundTrip"] = docker_growth(item["containerId"])
                if not item["dependencyRoundTrip"]["verified"]:
                    problems.append("%s live PostgreSQL/Redis/S3 growth probe failed" % service)
        elif service == "postgres" and item["running"]:
            item["postgresState"] = probe_postgres(item["containerId"])
        elif service == "redis" and item["running"]:
            item["redisState"] = probe_redis(item["containerId"])
    # Collisions in identifiers on the same host are unsafe even if Docker uses
    # different container IDs: ServerBridge routing is keyed by replica ID.
    replica_ids = [i["environment"].get("LAUNCHER_REPLICA_ID") for i in items
                   if i["service"] in ("api", "api-b", "worker", "worker-a", "worker-b")]
    nonempty = [x for x in replica_ids if x]
    if len(nonempty) != len(set(nonempty)):
        problems.append("duplicate LAUNCHER_REPLICA_ID on Docker host")
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
    for name, classification in (("PostgreSQL domain repository", "authoritative_metadata"),
                                 ("S3 release objects", "authoritative_objects"),
                                 ("Redis leases / rate limits", "reconstructible_coordination_not_durable_authority"),
                                 ("Auth/MFA/ServerBridge runtime maps", "replica_local_state_cross_replica_consistency_unverified"),
                                 ("ServerBridge game worlds", "external_game_host_state_not_inspected")):
        state_inventory.append({"surface": name, "classification": classification})
    return {"schema": "neverlauncher.ha-inventory.0.51.1", "version": VERSION,
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
        raise InventoryError("invalid HTTPS edge URL") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise InventoryError("edge URL must be HTTPS without embedded credentials or fragment")
    if parsed.path not in ("", "/", "/ready") or parsed.query:
        raise InventoryError("edge URL must be an origin or /ready (no query)")
    target = url.rstrip("/") + ("/ready" if parsed.path in ("", "/") else "")
    opener = urllib.request.build_opener(NoRedirect())
    durations = []
    failures = 0
    for _ in range(samples):
        started = time.monotonic_ns()
        try:
            request = urllib.request.Request(target, headers={"User-Agent": "NeverLauncher-HA-Inventory/0.51.1"})
            with opener.open(request, timeout=6) as response:
                if response.status != 200:
                    raise InventoryError("public edge readiness is not HTTP 200")
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
           "distinct OS identities on %d operator-reached Docker hosts; physical/hypervisor separation unverified" % len(set(host_ids))
           if host_ids_valid else "duplicate/missing OS identity or fewer than two hosts")
    for role, aliases in (("api", ("api", "api-b")), ("worker", ("worker", "worker-a", "worker-b")),
                          ("admin", ("admin",)), ("ingress", ("nginx", "ingress"))):
        matched = [(h, i) for _, h, i in containers if i["service"] in aliases and i["running"]]
        ready = [(h, i) for h, i in matched if (i.get("readiness", {}).get("success", 0) > 0
                                              if role in CRITICAL_ROLES else i["health"] == "healthy")]
        domains = {h for h, _ in ready if h}
        status = "OBSERVED" if len(domains) >= 2 and len(ready) >= 2 else "RISK"
        record(role, status, "%d running; %d live-ready on %d OS identities" %
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
           "replica IDs unique and runtime role/readiness/configuration checked" if role_safe
           else "missing/duplicate IDs, invalid role/configuration or failed node checks")
    pg = [(h, i) for _, h, i in containers if i["service"] == "postgres" and i["running"]]
    if len(pg) == 1:
        record("postgresql", "RISK", "only one PostgreSQL container on inspected hosts; no proven external failover")
    elif not pg:
        record("postgresql", "UNVERIFIED", "external PostgreSQL/managed cluster topology not observable from inspected Docker projects")
    else:
        all_pg = all(i.get("postgresState", {}).get("observed") for _, i in pg)
        sync_pg = any(i.get("postgresState", {}).get("synchronousPeers", 0) >= 1 for _, i in pg)
        distinct_pg = len({h for h, _ in pg if h}) >= 2
        record("postgresql", "UNVERIFIED" if all_pg and sync_pg and distinct_pg else "RISK",
               "live PostgreSQL replication observed; failover/fencing not exercised" if all_pg and sync_pg and distinct_pg
               else "PostgreSQL synchronous replication, roles or failure domains not proven")
    redis = [(h, i) for _, h, i in containers if i["service"] == "redis" and i["running"]]
    if len(redis) == 1:
        record("redis", "RISK", "single Redis container; leases do not establish Redis HA")
    elif not redis:
        record("redis", "UNVERIFIED", "external Redis/sentinel/managed failover not observable")
    else:
        record("redis", "UNVERIFIED", "multiple Redis processes observed; epoch, quorum and failover not exercised")
    live = [i.get("dependencyRoundTrip") for _, i in replicas if i["service"] in ("api", "api-b")]
    if live and all(x and x.get("verified") and x.get("postgresql") and x.get("redisLease") and x.get("s3RoundTrip") for x in live):
        record("s3_objects", "UNVERIFIED", "actual cross-client S3 write/read/hash/delete works; provider durability and failover not exercised")
        record("durable_lease", "UNVERIFIED", "PostgreSQL transaction fence and Redis lease work; partition safety remains unproven")
    else:
        record("s3_objects", "UNVERIFIED", "missing successful live S3 write/read/hash/delete evidence")
        record("durable_lease", "UNVERIFIED", "missing live PostgreSQL + Redis fencing/lease evidence")
    if edge:
        record("public_tls_edge", "OBSERVED" if edge.get("success") == edge.get("sampled") else "RISK",
               "public HTTPS /ready passed %d/%d (does not test ingress host failover)" %
               (edge["success"], edge["sampled"]), required=True)
    else:
        record("public_tls_edge", "UNVERIFIED", "no public HTTPS edge probe supplied")
    source_reports = [node.get("sourceState") for node in nodes.values() if node.get("sourceState", {}).get("observed")]
    if source_reports and any(s.get("replicaLocalStateToVerify") for s in source_reports):
        record("replica_local_runtime_state", "UNVERIFIED",
               "live-replica agreement for auth/security/Bridge in-process state not tested; source confirms per-process fields")
    else:
        record("replica_local_runtime_state", "UNVERIFIED",
               "source unavailable or per-process security state not inventoried")
    for kind, why in (
        ("secret_authority", "secret/key distribution, consistency and independent recovery not probed"),
        ("external_auth", "OIDC/Microsoft/external auth dependency failover not probed"),
        ("dns", "authoritative DNS and TTL/network failover not probed"),
        ("serverbridge", "game host/Bridge runtime epochs and cross-host routing not probed"),
        ("game_worlds", "single-writer worlds, snapshots and remote restoration not probed"),
        ("backups", "off-host PITR and verified restore not probed"),
        ("extension_state", "extension processes, filesystem state and cross-replica compatibility not probed"),
    ):
        record(kind, "UNVERIFIED", why)
    operations = [
        {"operation": "publish/rollback + durable jobs", "authority": "PostgreSQL transactional lease/outbox",
         "partitionRule": "no PostgreSQL authority -> fail closed; stale worker may not commit",
         "evidence": "fencing probe only, live partition unverified"},
        {"operation": "ServerBridge control command", "authority": "PostgreSQL command journal + Redis channel lease",
         "partitionRule": "stale epoch/token cannot apply external side effect; no blind replay",
         "evidence": "not proven by inventory; requires 0.51.4/0.51.5"},
        {"operation": "profile/auth/MFA/passkey mutation", "authority": "PostgreSQL plus legacy per-process runtime snapshots",
         "partitionRule": "independent replicas must agree immediately after commit",
         "evidence": "cross-replica write/read behavior not proven; needs dedicated test"},
        {"operation": "Minecraft world save/restore", "authority": "single active game JVM/world writer",
         "partitionRule": "quorum/fenced single writer or stop writes until restored",
         "evidence": "not proven by inventory; requires game-host test"},
    ]
    return {"status": "RISK" if issues else "UNVERIFIED", "issues": issues,
            "spof": findings, "criticalOperations": operations,
            "multiHostFailoverCertified": False,
            "reason": "inventory/readiness cannot certify real host loss, network partitions, rolling updates or world restore"}


def remote_node(target, remote_script, project, samples, growth):
    if not SSH_RE.fullmatch(target) or target.startswith("-"):
        raise InventoryError("invalid SSH target")
    if not remote_script.startswith("/") or "\n" in remote_script:
        raise InventoryError("remote script must be an absolute installed path")
    command = ["python3", remote_script, "node", "--project", project,
               "--samples", str(samples), "--output", "-"]
    if not growth:
        command.append("--skip-growth")
    # Single quoted remote command argument, never interpolated shell input.
    raw = execute(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "ConnectTimeout=7", "-o", "NumberOfPasswordPrompts=0",
                   target, shlex.join(command)], timeout=max(45, 55 + 8 * samples), allowed_codes=(0, 3))
    try:
        result = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise InventoryError("remote node returned invalid JSON") from exc
    validate_node(result, project)
    return result


def validate_node(node, project):
    if not isinstance(node, dict) or node.get("schema") != "neverlauncher.ha-inventory.0.51.1" or node.get("project") != project:
        raise InventoryError("node inventory schema/project mismatch")
    if not isinstance(node.get("containers"), list) or not isinstance(node.get("observations"), list):
        raise InventoryError("node inventory incomplete")
    if len(node["containers"]) > 100:
        raise InventoryError("node inventory too large")


def write_report(path, payload):
    content = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if path == "-":
        sys.stdout.buffer.write(content)
        return
    destination = Path(path)
    if destination.is_symlink() or destination.exists():
        raise InventoryError("report already exists; never overwrite existing evidence")
    if not destination.parent.is_dir():
        raise InventoryError("report directory missing")
    fd, temp = tempfile.mkstemp(prefix=".ha-inventory-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temp, destination)  # atomic exclusive publication (no overwrite)
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
    local = subs.add_parser("node", help="inspect actual Docker processes on this host")
    local.add_argument("--project", required=True)
    local.add_argument("--samples", type=int, default=3)
    local.add_argument("--skip-growth", action="store_true", help="mark dependency round-trip unverified")
    local.add_argument("--source-root", type=Path, help="include source-traced replica-local state inventory")
    local.add_argument("--output", required=True)
    cluster = subs.add_parser("cluster", help="collect node inventories over SSH and find live SPOFs")
    cluster.add_argument("--project", required=True)
    cluster.add_argument("--node", action="append", required=True,
                         help="name=local or name=trusted-ssh-user@host (repeat on distinct hosts)")
    cluster.add_argument("--remote-script", default="/opt/launcher/scripts/operations/ha_inventory_0511.py")
    cluster.add_argument("--samples", type=int, default=3)
    cluster.add_argument("--skip-growth", action="store_true")
    cluster.add_argument("--edge-url", help="real public HTTPS origin or /ready")
    cluster.add_argument("--source-root", type=Path)
    cluster.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if not PROJECT_RE.fullmatch(args.project):
            raise InventoryError("invalid Docker Compose project name")
        if not 1 <= args.samples <= 20:
            raise InventoryError("samples must be between 1 and 20")
        if args.mode == "node":
            result = node_inventory(args.project, args.samples, not args.skip_growth, args.source_root)
            write_report(args.output, result)
            return 3 if result["nodeStatus"] == "RISK" else 0
        nodes = {}
        for spec in args.node:
            name, sep, target = spec.partition("=")
            if not sep or not LABEL_RE.fullmatch(name) or not target or name in nodes:
                raise InventoryError("each --node must be a unique name=SSH-target or name=local")
            if target == "local":
                nodes[name] = node_inventory(args.project, args.samples, not args.skip_growth, args.source_root)
            else:
                nodes[name] = remote_node(target, args.remote_script, args.project, args.samples, not args.skip_growth)
        edge = probe_public_edge(args.edge_url, args.samples) if args.edge_url else None
        assessment = assess_cluster(nodes, edge)
        result = {"schema": "neverlauncher.ha-cluster-inventory.0.51.1", "version": VERSION,
                  "collectedUtc": utc_now(), "project": args.project, "nodes": nodes,
                  "edgeReadiness": edge, "assessment": assessment}
        write_report(args.output, result)
        return 3 if assessment["status"] == "RISK" else 0
    except InventoryError as exc:
        # The error never contains command output, credentials or an environment.
        print("HA inventory unavailable: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
