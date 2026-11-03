#!/usr/bin/env python3
"""NeverLauncher 0.51.2: execute and verify a real multi-Docker-host deployment.

Every host runs its own API, worker, Admin and HTTPS ingress against shared
external PostgreSQL, Redis and S3. This program never provisions those external
services or mistakes two containers on one host for two failure domains.

Modes local-check/local-up/local-observe are run *on each host*; cluster-check,
cluster-up and cluster-drill run from a trusted operator machine via pinned SSH
host keys. Cluster drill disrupts one host's product containers and restores
those containers even on verification failure. No raw Docker config or secrets
are printed or persisted in reports.
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
    """Never expose stderr, stdout, environment, or commands in failures."""
    try:
        p = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError("command unavailable or timed out: " + argv[0]) from exc
    if p.returncode not in codes:
        raise DeploymentError("command failed: " + argv[0] + " (exit " + str(p.returncode) + ")")
    if len(p.stdout) > 4_000_000:
        raise DeploymentError("command produced unexpectedly large output")
    return p.stdout.decode("utf-8", errors="replace")


def compose_command(directory, project, *rest):
    return ["docker", "compose", "--project-name", project,
            "-f", str(directory / "docker-compose.multi-host.yml"), *rest]


def url_host(value, scheme):
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise DeploymentError("invalid external endpoint URL") from exc
    if parsed.scheme not in scheme or not parsed.hostname or parsed.fragment:
        raise DeploymentError("external dependency must use the required TLS URL scheme")
    if parsed.hostname.lower() in ("localhost", "127.0.0.1", "::1", "postgres", "redis", "minio", "s3"):
        raise DeploymentError("external dependency cannot resolve to a localhost or embedded Compose service")
    return parsed.hostname.lower()


def check_secure_file(path, *, strict=False):
    if not path.is_file() or path.is_symlink():
        raise DeploymentError("required file is absent or is a symlink: " + path.name)
    mode = stat.S_IMODE(path.stat().st_mode)
    if strict and (mode & 0o077):
        raise DeploymentError("secret file is accessible to group/other: " + path.name)


def resolved_compose(directory, project):
    if not PROJECT_REGEX.fullmatch(project):
        raise DeploymentError("invalid Compose project name")
    check_secure_file(directory / ".env", strict=True)
    check_secure_file(directory / "docker-compose.multi-host.yml")
    check_secure_file(directory / "nginx.multi-host-0512.conf")
    raw = run(compose_command(directory, project, "config", "--format", "json"), cwd=directory, timeout=20)
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise DeploymentError("Docker Compose configuration is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise DeploymentError("Docker Compose configuration missing services")
    services = data["services"]
    if set(services) != set(ALL_SERVICES):
        raise DeploymentError("unexpected Compose services; embedded database or other processes are prohibited")
    api = services["api"]["environment"]
    worker = services["worker"]["environment"]
    for name, env in (("api", api), ("worker", worker)):
        if env.get("LAUNCHER_PROCESS_ROLE") != name:
            raise DeploymentError("incorrect process role for " + name)
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
                raise DeploymentError(name + " has unsafe " + key)
        if env.get("LAUNCHER_STORAGE_S3_BUCKET", "") == "":
            raise DeploymentError("S3 bucket missing")
    ids = (api.get("LAUNCHER_REPLICA_ID"), worker.get("LAUNCHER_REPLICA_ID"))
    if not isinstance(ids[0], str) or not ids[0].endswith("-api") or not LABEL_REGEX.fullmatch(ids[0][:-4]):
        raise DeploymentError("LAUNCHER_NODE_ID must be a stable lowercase hostname-compatible identifier")
    node_id = ids[0][:-4]
    if ids[1] != node_id + "-worker":
        raise DeploymentError("API and worker must share one node prefix but use different replica IDs")
    pg = url_host(api.get("LAUNCHER_DATABASE_DSN", ""), ("postgres", "postgresql"))
    if parse_qs(urlsplit(api["LAUNCHER_DATABASE_DSN"]).query).get("sslmode") != ["verify-full"]:
        raise DeploymentError("PostgreSQL requires TLS sslmode=verify-full on multi-host network")
    redis = url_host(api.get("LAUNCHER_REDIS_URL", ""), ("rediss",))
    s3 = url_host(api.get("LAUNCHER_STORAGE_S3_ENDPOINT", ""), ("https",))
    public = api.get("LAUNCHER_PUBLIC_URL", "")
    public_host = url_host(public, ("https",))
    if urlsplit(public).username or urlsplit(public).password:
        raise DeploymentError("public URL must not contain credentials")
    for key in ("LAUNCHER_DATABASE_DSN", "LAUNCHER_REDIS_URL", "LAUNCHER_STORAGE_S3_ENDPOINT",
                "LAUNCHER_STORAGE_S3_BUCKET", "LAUNCHER_STORAGE_S3_REGION", "LAUNCHER_PUBLIC_URL"):
        if api.get(key) != worker.get(key):
            raise DeploymentError("worker and API target different shared dependency " + key)
    refs = {}
    for name in ALL_SERVICES:
        ref = services[name].get("image", "")
        if not DIGEST_REGEX.fullmatch(ref):
            raise DeploymentError("production image for " + name + " must have immutable @sha256 digest")
        refs[name] = ref
    if refs["api"] != refs["worker"]:
        raise DeploymentError("API and worker must use exactly the same binary/image")
    if "ports" in services["api"] or "ports" in services["worker"]:
        raise DeploymentError("API/worker must not publish host ports")
    ingress_ports = services["ingress"].get("ports", [])
    if len(ingress_ports) != 1:
        raise DeploymentError("ingress must publish exactly one restricted HTTPS port")
    for bind in ingress_ports:
        if bind.get("target") != 443 or bind.get("published") != "443" or bind.get("protocol", "tcp") != "tcp":
            raise DeploymentError("only port 443 of local ingress may be published")
        host_ip = str(bind.get("host_ip", ""))
        if not host_ip or host_ip in ("0.0.0.0", "::", "127.0.0.1"):
            raise DeploymentError("ingress requires an explicit reachable, restricted interface IP")
    for name in ("api", "worker"):
        if not services[name].get("healthcheck"):
            raise DeploymentError("missing readiness healthcheck for " + name)
    # Check the TLS key/cert on the host via parsed Docker volumes, not an
    # untrusted interpolation of env-file contents or a log of Docker config.
    tls_targets = ("/etc/launcher/tls/fullchain.pem", "/etc/launcher/tls/privkey.pem")
    tls_volumes = [v for v in services["ingress"].get("volumes", []) if v.get("target") in tls_targets]
    if sorted(v["target"] for v in tls_volumes) != sorted(tls_targets):
        raise DeploymentError("both host TLS certificate and key must be bind-mounted")
    for volume in tls_volumes:
        if volume.get("type") != "bind" or volume.get("read_only") is not True:
            raise DeploymentError("host TLS credentials must be read-only file binds")
        check_secure_file(Path(volume["source"]), strict=volume["target"].endswith("privkey.pem"))
    machine = inventory.machine_identity()
    if not machine:
        raise DeploymentError("OS machine-id missing; cannot prove independent Docker hosts")
    try:
        pgport = urlsplit(api["LAUNCHER_DATABASE_DSN"]).port or 5432
        redisport = urlsplit(api["LAUNCHER_REDIS_URL"]).port or 6379
        s3port = urlsplit(api["LAUNCHER_STORAGE_S3_ENDPOINT"]).port or 443
    except ValueError as exc:
        raise DeploymentError("external endpoint has an invalid TCP port") from exc
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
    # Full executable state inspection: containers, actual process-role env,
    # app/worker /ready, Redis lease, PG transaction and S3 object round trip.
    node = inventory.node_inventory(project, 3, growth=growth, source_root=directory.parents[1])
    actual = {item["service"]: item for item in node["containers"]}
    issues = list(node["observations"])
    if not growth:
        issues.append("live PostgreSQL/Redis/S3 round-trip was deliberately skipped")
    for name in SERVICES:
        item = actual.get(name)
        if not item or not item["running"] or item["health"] != "healthy":
            issues.append(name + " is not a running healthy container")
            continue
        if name in ("api", "worker"):
            if item.get("readiness", {}).get("success") != 3:
                issues.append(name + " did not pass three real /ready probes")
            if item["environment"].get("LAUNCHER_REPLICA_ID") != expected["nodeId"] + "-" + name:
                issues.append(name + " effective replica identity differs from deployment")
    for name in ("postgres", "redis"):
        if name in actual:
            issues.append("embedded " + name + " must not be running in the multi-host project")
    # A container's immutable image *reference* must match the deployment,
    # not merely its image ID, which is a different object in Docker inspect.
    running_refs = {}
    for container in inventory.docker_inspect(inventory.docker_ids(project)):
        cfg = container.get("Config") or {}
        label = (cfg.get("Labels") or {}).get("com.docker.compose.service")
        if label in SERVICES:
            running_refs[label] = cfg.get("Image")
    for name in SERVICES:
        if running_refs.get(name) != expected["imageDigestRefs"][name]:
            issues.append(name + " container did not start from requested immutable image")
    return {**expected, "live": node, "issues": sorted(set(issues)),
            "ready": not issues and all(name in actual for name in SERVICES),
            "observedUtc": inventory.utc_now()}


def local_compat_observe_0516(directory, project):
    """Real HTTP API, Bridge and worker probes inside pinned running images.

    This is purposefully a separate, read-only mode. Ordinary cluster checks
    continue to reject different image digests during deploy/chaos drills.
    """
    import hashlib
    report = live_observe(directory, project, growth=True)
    if not report.get("ready"):
        raise DeploymentError("cannot inspect compatibility on an unhealthy node")
    running = {c.get("service"): c for c in report["live"]["containers"]}
    for role in ("api", "worker"):
        ready = (running.get(role) or {}).get("readiness") or {}
        if not (ready.get("versionVerified") is True and ready.get("version") in ("0.51.5", "0.51.6")):
            raise DeploymentError("unsupported or unverified live /ready version for " + role)
    if running["api"]["readiness"]["version"] != running["worker"]["readiness"]["version"]:
        raise DeploymentError("API/worker live version mismatch on the same host")
    container = running["api"]["containerId"]
    def get(path):
        raw = inventory.execute(["docker", "exec", container, "wget", "-qO-", "-T", "5",
                                 "http://127.0.0.1:8080" + path], timeout=9)
        if len(raw) > 512_000:
            raise DeploymentError("HTTP API compatibility response too large")
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise DeploymentError("HTTP API compatibility response invalid") from exc
        if not isinstance(data, dict):
            raise DeploymentError("HTTP API compatibility response must be a JSON object")
        return data
    v = running["api"]["readiness"]["version"]
    status = get("/api/v1/status")
    if status.get("status") != "ok" or status.get("version") != v:
        raise DeploymentError("live API status differs from live readiness version")
    loaders = get("/api/v1/loaders")
    if loaders.get("version") != v or not isinstance(loaders.get("items"), list) or not loaders["items"]:
        raise DeploymentError("live loader API contract incompatible")
    runtime = get("/api/v1/runtime/requirements")
    if runtime.get("version") != v or not isinstance(runtime.get("java"), dict):
        raise DeploymentError("live runtime requirements API incompatible")
    bridge = get("/api/v1/server-bridge/capabilities?protocols=3,2")
    data = bridge.get("data")
    if (not isinstance(data, dict) or data.get("toolVersion") != v or
            data.get("negotiatedProtocolVersion") != 3 or
            data.get("supportedProtocolVersions") != [3, 2] or
            data.get("rollingUpgrade") is not True or
            not data.get("activeSigningKeyFingerprint")):
        raise DeploymentError("live signed ServerBridge capability negotiation incompatible")
    # Compare real response contracts, not version-dependent strings.
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
    # Production images are always fetched by digest. Never build independently
    # on two hosts and hope their tags resolve to the same executable bytes.
    run(compose_command(directory, project, "pull", "--policy", "always"), cwd=directory, timeout=240)
    run(compose_command(directory, project, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180"),
        cwd=directory, timeout=230)
    report = live_observe(directory, project)
    if not report["ready"]:
        raise DeploymentError("containers started but live readiness or dependency round trips failed")
    return report


def remote_call(target, installed_script, directory, project, mode, *, growth=True, timeout=150):
    if not HOST_REGEX.fullmatch(target) or target.startswith("-"):
        raise DeploymentError("invalid SSH target")
    if not installed_script.startswith("/") or not directory.startswith("/"):
        raise DeploymentError("installed script and deployment directory must be absolute paths")
    if any("\n" in s or "\r" in s for s in (installed_script, directory)):
        raise DeploymentError("invalid remote path")
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
        raise DeploymentError("remote node returned invalid report") from exc
    if not isinstance(result, dict) or result.get("schema") != SCHEMA or result.get("project") != project:
        raise DeploymentError("remote node returned mismatched report schema/project")
    return result


def remote_stop_start(target, installed_script, directory, project, action):
    if action not in ("stop", "start"):
        raise DeploymentError("unsupported disruption action")
    return remote_call(target, installed_script, directory, project, "local-" + action,
                       growth=False, timeout=100)


def parse_nodes(specs):
    nodes = {}
    for spec in specs:
        name, sep, host = spec.partition("=")
        if not sep or not LABEL_REGEX.fullmatch(name) or not HOST_REGEX.fullmatch(host) or host.startswith("-") or name in nodes:
            raise DeploymentError("each --node must be a unique label=trusted-ssh-host")
        if host in nodes.values():
            raise DeploymentError("same SSH target specified more than once")
        nodes[name] = host
    if len(nodes) < 2:
        raise DeploymentError("at least two independent SSH hosts are required")
    return nodes


def assert_peer_config(reports):
    seen_machine = set()
    seen_node = set()
    first = next(iter(reports.values()))
    for name, report in reports.items():
        if not report.get("configurationValidated"):
            raise DeploymentError(name + " does not have a valid multi-host configuration")
        machine = report.get("machineIdentity")
        node_id = report.get("nodeId")
        if not machine or machine in seen_machine or not node_id or node_id in seen_node:
            raise DeploymentError("duplicate/missing machine ID or node ID; cannot treat as distinct hosts")
        seen_machine.add(machine)
        seen_node.add(node_id)
        if report.get("imageDigestRefs") != first.get("imageDigestRefs"):
            raise DeploymentError("different pinned images on hosts; cluster version skew not supported in 0.51.2")
        if report.get("sharedEndpoints") != first.get("sharedEndpoints"):
            raise DeploymentError("hosts target different public origins or shared dependency endpoints")


def collect_cluster(nodes, script, directory, project, mode, *, growth=True):
    reports = {name: remote_call(target, script, directory, project, mode, growth=growth)
               for name, target in nodes.items()}
    assert_peer_config(reports)
    return reports


def validate_edge_url(url):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise DeploymentError("invalid external load balancer URL") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.path not in ("", "/", "/ready"):
        raise DeploymentError("external load balancer URL must be an HTTPS origin or /ready without credentials")
    return url


def edge_ready(url, count=3):
    # The public DNS/LB path, not an endpoint tied to the still-alive host.
    validate_edge_url(url)
    result = inventory.probe_public_edge(url, count)
    return result["success"] == count, result


def cluster_verify(reports, edge_url):
    assert_peer_config(reports)
    issues = []
    engines = [r.get("live", {}).get("dockerEngineIdentity") for r in reports.values()]
    if not all(engines) or len(set(engines)) != len(engines):
        issues.append("Docker Engine identities missing or duplicated across SSH hosts")
    for name, report in reports.items():
        if report.get("ready") is not True:
            issues.append(name + " runtime readiness failed")
    for name, report in reports.items():
        live = report.get("live")
        if not isinstance(live, dict):
            issues.append(name + " has no actual Docker state")
            continue
        roles = {i["service"]: i for i in live.get("containers", [])}
        for service in SERVICES:
            item = roles.get(service)
            if not item or not item.get("running"):
                issues.append(name + ": missing running " + service)
    ok, edge = edge_ready(edge_url)
    if not ok:
        issues.append("external HTTPS load balancer did not return successful /ready on all probes")
    return {"schema": SCHEMA, "version": VERSION, "observedUtc": inventory.utc_now(),
            "nodes": reports, "publicEdge": edge, "issues": issues,
            "multiHostControlPlaneObserved": not issues,
            "hostFailureTested": False, "dependencyHAUnverified": True}


def outage_drill(nodes, script, directory, project, edge_url, failed_node):
    if failed_node not in nodes:
        raise DeploymentError("failed node not in target cluster")
    before = collect_cluster(nodes, script, directory, project, "local-observe")
    normal = cluster_verify(before, edge_url)
    if not normal["multiHostControlPlaneObserved"]:
        raise DeploymentError("cannot begin outage test when baseline is not healthy")
    survivor_name = next(n for n in nodes if n != failed_node)
    stopped = False
    restore_error = None
    observations = []
    try:
        # Executed only after explicit --allow-disruption. This removes ALL
        # ingress/API/worker/Admin containers on the selected Docker host.
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
            raise DeploymentError("external HTTPS LB did not recover after stopping one full node")
        survivor = remote_call(nodes[survivor_name], script, directory, project, "local-observe")
        if not survivor.get("ready"):
            raise DeploymentError("surviving node does not have healthy API and worker after simulated host loss")
        success = True
    except DeploymentError as exc:
        success = False
        failure = str(exc)
    finally:
        # Attempt restoration even if SSH command failed partway through.
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
              "scope": "stopped complete Compose product stack, NOT physical power-off, network partition or dependency failover"}
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
    parser.add_argument("--node", action="append", default=[], help="label=ssh-user@host (repeat)")
    parser.add_argument("--remote-script", default="/opt/launcher/scripts/operations/multi_host_0512.py")
    parser.add_argument("--edge-url", help="external HTTPS load-balancer origin or /ready")
    parser.add_argument("--failed-node", help="node label to disrupt during cluster-drill")
    parser.add_argument("--allow-disruption", action="store_true", help="required for cluster-drill")
    parser.add_argument("--skip-growth", action="store_true")
    parser.add_argument("--output", required=True, help="new report path or - for JSON stdout")
    args = parser.parse_args(argv)
    try:
        directory = Path(args.directory)
        if not directory.is_absolute() or not PROJECT_REGEX.fullmatch(args.project):
            raise DeploymentError("invalid absolute directory/project")
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
                # In a drill stop order excludes workers from starting new
                # operations; up restarts the complete pinned deployment.
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
                raise DeploymentError("--edge-url required before deploying any hosts")
            validate_edge_url(args.edge_url)
            collect_cluster(nodes, args.remote_script, args.directory, args.project, "local-check")
            for name, target in nodes.items():
                deployed = remote_call(target, args.remote_script, args.directory, args.project,
                                       "local-up", timeout=520)
                if not deployed.get("ready"):
                    raise DeploymentError(name + " did not pass live startup verification")
            report = cluster_verify(collect_cluster(nodes, args.remote_script, args.directory, args.project,
                                                     "local-observe"), args.edge_url)
        elif args.mode == "cluster-verify":
            if not args.edge_url:
                raise DeploymentError("--edge-url required for cluster verification")
            validate_edge_url(args.edge_url)
            report = cluster_verify(collect_cluster(nodes, args.remote_script, args.directory, args.project,
                                                     "local-observe", growth=not args.skip_growth), args.edge_url)
        else:
            if not args.allow_disruption or not args.edge_url or not args.failed_node:
                raise DeploymentError("cluster-drill requires --allow-disruption --failed-node and --edge-url")
            validate_edge_url(args.edge_url)
            report = outage_drill(nodes, args.remote_script, args.directory, args.project,
                                  args.edge_url, args.failed_node)
        inventory.write_report(args.output, report)
        return 0 if (report.get("configurationValidated") or report.get("multiHostControlPlaneObserved")
                     or report.get("testPassed")) else 3
    except (DeploymentError, inventory.InventoryError) as exc:
        print("multi-host operation unavailable: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
