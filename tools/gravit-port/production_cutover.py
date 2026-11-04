#!/usr/bin/env python3
"""Two-phase, fail-closed Gravit production ingress cutover on local HAProxy.

The API (PostgreSQL) remains authoritative for release routing and identity.
HAProxy's admin socket is authoritative for the configured ingress backends.
These two systems do not share a transaction: any ambiguity leaves ingress in
MAINT and requires operator reconciliation, not automatic old-world replay.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

FORMAT = "never/gravit-production-cutover/v1"
HEX = re.compile(r"^[a-f0-9]{64}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
SERVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
ROUTE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
PROBES = ("launch", "login", "join", "skins", "loader", "optional", "admin")


class Blocked(Exception):
    pass


def require(ok: bool, reason: str):
    if not ok:
        raise Blocked(reason)


def strict_file(path: Path, limit: int = 1 << 20) -> bytes:
    require(path.is_absolute(), "absolute file path required")
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= limit and st.st_mode & 0o077 == 0,
            "missing, symlinked, oversized or nonprivate file: " + str(path))
    with path.open("rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "file exceeds size bound")
    return data


def document(path: Path, limit: int = 1 << 20) -> dict:
    value = json.loads(strict_file(path, limit))
    require(isinstance(value, dict), "JSON object expected")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_url(uri: str) -> bool:
    try:
        u = urlsplit(uri)
        return u.scheme == "https" and bool(u.hostname) and not u.username and not u.password and not u.fragment
    except ValueError:
        return False


def validate(config: dict, journal_dir: Path):
    require(config.get("format") == FORMAT, "unsupported config format")
    for name in ("runId", "profileId", "channel", "stageId", "releaseId"):
        value = config.get(name)
        require(isinstance(value, str) and bool(NAME.fullmatch(value) if name in ("profileId", "channel") else ROUTE.fullmatch(value) if name in ("runId", "stageId") else len(value) >= 8), "invalid " + name)
    require(isinstance(config.get("expectedRevision"), int) and config["expectedRevision"] >= 1, "expected route revision required")
    require(isinstance(config.get("inventorySha256"), str) and HEX.fullmatch(config["inventorySha256"]), "inventory digest required")
    require(isinstance(config.get("targetDigest"), str) and HEX.fullmatch(config["targetDigest"]), "exact signed target manifest digest required")
    require(isinstance(config.get("baselineRevision"), int) and config["baselineRevision"] >= 0, "baseline channel revision required")
    require(safe_url(config.get("backend", "")), "Backend must use verified HTTPS")
    require(isinstance(config.get("launcher"), str) and Path(config["launcher"]).is_absolute(), "absolute CLI required")
    launcher = Path(config["launcher"])
    require(launcher.is_file() and not launcher.is_symlink() and os.access(launcher, os.X_OK), "launcher executable unavailable")
    require(isinstance(config.get("launcherSha256"), str) and HEX.fullmatch(config["launcherSha256"]), "CLI digest required")
    with launcher.open("rb") as f:
        require(digest(f.read()) == config["launcherSha256"], "launcher CLI changed")
    require(isinstance(config.get("proxySocket"), str) and Path(config["proxySocket"]).is_absolute(), "HAProxy Unix socket path required")
    sock_stat = Path(config["proxySocket"]).lstat()
    require(stat.S_ISSOCK(sock_stat.st_mode) and sock_stat.st_uid in (0, os.geteuid()),
            "HAProxy admin socket must be real and owned by root or operator")
    require(journal_dir.is_dir() and not journal_dir.is_symlink() and journal_dir.stat().st_mode & 0o077 == 0,
            "journal directory must be existing, private (0700), non-linked")
    routes = config.get("routes")
    require(isinstance(routes, dict) and set(routes) == {"auth", "game"}, "both auth and game ingress backends required")
    pairs = []
    for kind in ("auth", "game"):
        route = routes[kind]
        require(isinstance(route, dict) and set(route) == {"backend", "source", "target"}, "invalid proxy route")
        require(all(isinstance(v, str) and SERVER.fullmatch(v) for v in route.values()), "invalid HAProxy backend/server")
        require(route["source"] != route["target"], "different HAProxy source and target required")
        pairs.extend([(route["backend"], route["source"]), (route["backend"], route["target"])])
    require(len(pairs) == len(set(pairs)) and routes["auth"]["backend"] != routes["game"]["backend"], "auth and game must have distinct dedicated proxy backends")
    require(5 <= config.get("drainSeconds", 0) <= 600, "drainSeconds must be 5..600")
    require(isinstance(config.get("postSwitchStage"), str) and Path(config["postSwitchStage"]).is_absolute(), "post-switch real Minecraft stage required")
    require(isinstance(config.get("gamePublicAddress"), str) and bool(re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", config["gamePublicAddress"])),
            "explicit public Minecraft host:port required")
    live = document(Path(config["postSwitchStage"]) / "live-session.json", 16384)
    require(isinstance(live.get("clientArgs"), list) and any(isinstance(arg, str) and config["gamePublicAddress"] in arg for arg in live["clientArgs"]),
            "post-switch client launch does not reference the configured public Minecraft ingress")
    require(isinstance(config.get("authCanary"), dict), "actual auth canary required")
    p = config["authCanary"]
    require(safe_url(p.get("url", "")) and p.get("method") == "POST" and
            isinstance(p.get("requestBodyFile"), str) and Path(p["requestBodyFile"]).is_absolute() and
            isinstance(p.get("expectedPlayerUuid"), str) and bool(re.fullmatch(r"[a-f0-9-]{36}", p["expectedPlayerUuid"])) and
            p.get("uuidJSONField") in ("uuid", "playerUuid", "id") and safe_url(p.get("frontendUrl", "")), "invalid authenticated canary configuration")
    require(isinstance(p.get("requestSha256"), str) and HEX.fullmatch(p["requestSha256"]), "auth canary request digest required")
    require(digest(strict_file(Path(p["requestBodyFile"]), 8192)) == p["requestSha256"], "auth canary request changed")
    require(os.environ.get("LAUNCHER_TOKEN", "").strip() != "", "LAUNCHER_TOKEN must be set in environment")


class Proxy:
    """Real HAProxy runtime socket. No shell and no network-admin credentials."""
    def __init__(self, path: str):
        self.path = path

    def command(self, command: str) -> str:
        require("\n" not in command and "\r" not in command and len(command) < 256, "unsafe HAProxy command")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect(self.path)
            sock.sendall((command + "\n").encode("ascii"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            size = 0
            while True:
                piece = sock.recv(65536)
                if not piece:
                    break
                size += len(piece)
                require(size <= 4 << 20, "HAProxy response too large")
                chunks.append(piece)
        data = b"".join(chunks).decode("utf-8", "replace")
        require(not data.lstrip().startswith(("Unknown", "Error", "Permission denied", "No such")),
                "HAProxy rejected command")
        return data

    def instance(self) -> str:
        info = {}
        for line in self.command("show info").splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                info[key.strip()] = value.strip()
        pid = info.get("Pid", "")
        require(pid.isdigit() and int(pid) > 0, "HAProxy process identity unavailable")
        return pid

    def stats(self) -> dict[tuple[str, str], dict]:
        lines = self.command("show stat").splitlines()
        headers = None
        result = {}
        for line in lines:
            if line.startswith("# "):
                headers = next(csv.reader([line[2:]]))
                continue
            if line and headers:
                values = next(csv.reader([line]))
                item = dict(zip(headers, values))
                result[(item.get("pxname", ""), item.get("svname", ""))] = item
        require(bool(result), "HAProxy returned no valid server stats")
        return result

    def state(self, backend: str, server: str, state: str):
        require(state in ("ready", "drain", "maint"), "invalid server state")
        self.command(f"set server {backend}/{server} state {state}")
        stats = self.stats()
        row = stats.get((backend, server))
        require(row is not None, "HAProxy server vanished")
        if state == "maint":
            require(row.get("status", "").startswith("MAINT"), "HAProxy did not apply maintenance")
        if state == "drain":
            require(row.get("status", "").startswith("DRAIN"), "HAProxy did not apply drain")
        if state == "ready":
            require(row.get("status") == "UP", "HAProxy target is not healthy/UP")


def inspect_proxy(proxy: Proxy, cfg: dict, phase: str):
    stats = proxy.stats()
    for kind in ("auth", "game"):
        r = cfg["routes"][kind]
        source = stats.get((r["backend"], r["source"]))
        target = stats.get((r["backend"], r["target"]))
        require(source is not None and target is not None, "missing configured ingress server " + kind)
        expected = {r["source"], r["target"]}
        for (backend, server), row in stats.items():
            if backend == r["backend"] and server not in expected and server not in ("FRONTEND", "BACKEND"):
                require(row.get("status", "").startswith("MAINT"), "third active ingress server in " + kind)
        if phase == "prepare":
            require(source.get("status") == "UP" and target.get("status", "").startswith("MAINT"),
                    "expected source UP and target MAINT before drain")
        elif phase == "closed":
            require(source.get("status", "").startswith("MAINT") and target.get("status", "").startswith("MAINT"),
                    "ingress is not fully closed")
        elif phase == "open":
            require(source.get("status", "").startswith("MAINT") and target.get("status") == "UP",
                    "target not UP or source not MAINT")


def close_ingress(proxy: Proxy, cfg: dict):
    errors = []
    for kind in ("auth", "game"):
        r = cfg["routes"][kind]
        for name in ("source", "target"):
            try:
                proxy.state(r["backend"], r[name], "maint")
            except Exception as exc:
                errors.append(kind + ":" + name + ":" + type(exc).__name__)
    if errors:
        raise Blocked("could not prove ingress closed (manual HAProxy maintenance required): " + ", ".join(errors))
    inspect_proxy(proxy, cfg, "closed")


def journal_write(directory: Path, payload: dict, *, new: bool = False):
    path = directory / "cutover-state.json"
    raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
    if new:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    else:
        # Атомарная замена в той же файловой системе. Все журналы остаются закрытыми.
        temp = directory / "cutover-state.json.next"
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_phase(cfg_hash: str, phase: str) -> dict:
    return {"format": FORMAT, "configSha256": cfg_hash, "phase": phase,
            "updatedAtUnix": int(time.time()), "trafficOpen": False,
            "backendRouteActive": False}


def load_phase(directory: Path, cfg_hash: str) -> dict:
    result = document(directory / "cutover-state.json", 16384)
    require(result.get("format") == FORMAT and result.get("configSha256") == cfg_hash, "journal/config mismatch")
    return result


def update_phase(directory: Path, state: dict, phase: str, **extras):
    state.update(extras)
    state["phase"] = phase
    state["updatedAtUnix"] = int(time.time())
    journal_write(directory, state)


def run_cli(cfg: dict, args: list[str], output: Path, timeout=120) -> dict:
    require(not output.exists(), "refusing to overwrite cutover evidence")
    launcher = Path(cfg["launcher"])
    with launcher.open("rb") as f:
        require(digest(f.read()) == cfg["launcherSha256"], "CLI changed during cutover")
    with open(os.devnull, "wb") as sink:
        env = dict(os.environ)
        # Bearer-токен доступен только через окружение, никогда не сохраняется и не передаётся в argv.
        env.pop("LAUNCHER_PASSWORD", None)
        try:
            subprocess.run([str(launcher), "migrate", "gravit", *args, "--output", str(output)],
                           stdin=sink, stdout=sink, stderr=sink, env=env,
                           timeout=timeout, check=True)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise Blocked("NeverLauncher migration CLI command failed: " + args[0]) from exc
    require(output.exists(), "CLI did not create result " + args[0])
    result = document(output, 1 << 20)
    return result.get("data", result)


def route_list(cfg: dict, directory: Path, name: str) -> dict:
    doc = run_cli(cfg, ["cutover-list", "--backend", cfg["backend"], "--run", cfg["runId"]], directory / name)
    require(isinstance(doc, list), "invalid cutover-list result")
    matching = [v for v in doc if isinstance(v, dict) and v.get("profileId") == cfg["profileId"] and v.get("channel") == cfg["channel"]]
    require(len(matching) == 1, "exactly one matching route required")
    return matching[0]


def assert_route(route: dict, cfg: dict, active: bool):
    require(route.get("runId") == cfg["runId"] and route.get("stageId") == cfg["stageId"]
            and route.get("releaseId") == cfg["releaseId"] and
            route.get("targetDigest") == cfg["targetDigest"] and
            route.get("baselineRevision") == cfg["baselineRevision"] and
            route.get("state") == ("active" if active else "staged"), "cutover route differs from approved target")
    want_rev = cfg["expectedRevision"] + (1 if active else 0)
    require(route.get("revision") == want_rev, "cutover route revision changed")
    if active:
        require(route.get("activatedRevision") == cfg["baselineRevision"] + 1, "activated channel head differs from approved baseline")


def receipt_check(cfg: dict) -> None:
    receipt = document(Path(cfg["fenceReceipt"]), 8192)
    require(receipt.get("format") == "never/gravit-source-stop/v1" and
            all(receipt.get(field) == cfg[cfgfield] for field, cfgfield in
                (("runId", "runId"), ("profileId", "profileId"), ("channel", "channel"), ("stageId", "stageId"))) and
            receipt.get("unitState") == "inactive" and receipt.get("unitFileState") in ("masked", "masked-runtime") and
            receipt.get("snapshotSha256") == cfg.get("sourceSnapshotSha256"), "source fence receipt not bound to approved source")
    # Backend/CLI независимо проверяют хеш квитанции и её свежесть.
    from datetime import datetime, timezone
    checked = datetime.fromisoformat(receipt["checkedAt"].replace("Z", "+00:00"))
    stopped = datetime.fromisoformat(receipt["stoppedAt"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    require(0 <= (now - checked).total_seconds() < 600 and
            0 <= (now - stopped).total_seconds() < 900, "source fence receipt expired")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("auth canary redirected")


def auth_canary(cfg: dict, *, public: bool = False):
    canary = cfg["authCanary"]
    body = strict_file(Path(canary["requestBodyFile"]), 8192)
    require(digest(body) == canary["requestSha256"], "auth canary payload changed since preflight")
    req = Request(canary["frontendUrl"] if public else canary["url"], body, method="POST",
                  headers={"Content-Type": "application/json", "Cache-Control": "no-store"})
    # TLS проверяется по доверию ОС; без небезопасного обхода и межхостовых редиректов.
    try:
        with build_opener(HTTPSHandler(), NoRedirect()).open(req, timeout=8) as response:
            require(response.status == 200, "auth canary denied")
            data = response.read(8193)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise Blocked("authenticated target login canary failed") from exc
    require(len(data) <= 8192, "oversized auth canary result")
    result = json.loads(data)
    require(isinstance(result, dict) and result.get(canary["uuidJSONField"]) == canary["expectedPlayerUuid"],
            "auth canary authenticated wrong Minecraft UUID")
    # Намеренно не сохранять cookies сеанса, токен, пароль или тело.


def live_canary(cfg: dict, directory: Path) -> dict:
    report = run_cli(cfg, ["rehearse-local", "--run", cfg["runId"], "--stage", cfg["postSwitchStage"],
                           "--inventory-sha256", cfg["inventorySha256"]], directory / "post-switch-minecraft.json", 1000)
    require(report.get("ready") is False and report.get("cutoverAllowed") is False,
            "local witness must not claim Backend certification")
    live = report.get("liveSession")
    require(isinstance(live, dict) and live.get("joinedAt") and HEX.fullmatch(str(live.get("clientSha256", "")))
            and live.get("playerUuid") == cfg["authCanary"]["expectedPlayerUuid"],
            "post-switch Minecraft join not observed for authenticated UUID")
    probes = report.get("probes")
    require(isinstance(probes, list) and len(probes) == len(PROBES)
            and [p.get("name") for p in probes] == list(PROBES)
            and all(p.get("passed") is True and HEX.fullmatch(str(p.get("evidenceSha256", ""))) for p in probes),
            "post-switch Minecraft probes did not pass")
    return report


def prepare(cfg: dict, directory: Path, config_sha: str, proxy: Proxy):
    require(not (directory / "cutover-state.json").exists(), "existing journal requires manual recovery")
    route = route_list(cfg, directory, "route-before.json")
    assert_route(route, cfg, False)
    proxy_pid = proxy.instance()
    inspect_proxy(proxy, cfg, "prepare")
    state = new_phase(config_sha, "preparing")
    state["haproxyPid"] = proxy_pid
    journal_write(directory, state, new=True)
    try:
        for kind in ("auth", "game"):
            r = cfg["routes"][kind]
            proxy.state(r["backend"], r["source"], "drain")
        deadline = time.monotonic() + cfg["drainSeconds"]
        while True:
            stats = proxy.stats()
            remaining = 0
            for kind in ("auth", "game"):
                r = cfg["routes"][kind]
                scur = stats[(r["backend"], r["source"])].get("scur", "")
                require(scur.isdigit(), "invalid HAProxy session count")
                remaining += int(scur)
            if remaining == 0:
                break
            require(time.monotonic() < deadline, "source game/auth sessions did not drain")
            time.sleep(1)
        close_ingress(proxy, cfg)
        require(proxy.instance() == proxy_pid, "HAProxy restarted during cutover prepare")
        update_phase(directory, state, "traffic_fenced")
    except BaseException:
        try:
            close_ingress(proxy, cfg)
        finally:
            update_phase(directory, state, "blocked")
        raise


def activate(cfg: dict, directory: Path, config_sha: str, proxy: Proxy):
    state = load_phase(directory, config_sha)
    require(state["phase"] == "traffic_fenced", "only prepared, closed ingress may activate")
    inspect_proxy(proxy, cfg, "closed")
    require(proxy.instance() == state.get("haproxyPid"), "HAProxy restarted after ingress was fenced; manual reconciliation required")
    route = route_list(cfg, directory, "route-pre-activate.json")
    assert_route(route, cfg, False)
    receipt_check(cfg)
    # Проверить настоящую целевую авторизацию до смены указателя доставки PostgreSQL.
    auth_canary(cfg)
    update_phase(directory, state, "activating")
    try:
        run_cli(cfg, ["cutover-activate", "--backend", cfg["backend"], "--run", cfg["runId"],
                      "--confirm", cfg["runId"], "--profile-id", cfg["profileId"], "--channel", cfg["channel"],
                      "--expected-revision", str(cfg["expectedRevision"]), "--source-fenced", "true",
                      "--fence-receipt", cfg["fenceReceipt"]], directory / "route-activation.json")
        route = route_list(cfg, directory, "route-after.json")
        assert_route(route, cfg, True)
        update_phase(directory, state, "route_activated", backendRouteActive=True)
        for kind in ("auth", "game"):
            r = cfg["routes"][kind]
            proxy.state(r["backend"], r["target"], "ready")
        inspect_proxy(proxy, cfg, "open")
        update_phase(directory, state, "target_open", trafficOpen=True)
        auth_canary(cfg, public=True)  # Real public HTTPS ingress, not just direct upstream.
        # Тот же UUID должен действительно подключиться к серверу Minecraft после переключения.
        live_canary(cfg, directory)
        route = route_list(cfg, directory, "route-final.json")
        assert_route(route, cfg, True)
        inspect_proxy(proxy, cfg, "open")
        require(proxy.instance() == state["haproxyPid"], "HAProxy restarted before cutover verification")
        update_phase(directory, state, "complete", trafficOpen=True)
    except BaseException as exc:
        state["errorClass"] = type(exc).__name__
        state["trafficOpen"] = False
        try:
            close_ingress(proxy, cfg)
        except Exception:
            state["manualProxyClosureRequired"] = True
        update_phase(directory, state, "blocked")
        raise


def main(argv=None) -> int:
    # Не допускать создания выходных файлов CLI миграции с правом чтения для всех.
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "activate", "status"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--journal-dir", required=True)
    parser.add_argument("--confirm", required=False, default="")
    args = parser.parse_args(argv)
    try:
        config_path = Path(args.config)
        config_raw = strict_file(config_path)
        cfg = json.loads(config_raw)
        directory = Path(args.journal_dir)
        validate(cfg, directory)
        require(args.command == "status" or args.confirm == cfg["runId"], "exact runId confirmation required")
        lock_path = directory / ".cutover.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            cfg_hash = digest(config_raw)
            if args.command == "status":
                state = load_phase(directory, cfg_hash)
                print(json.dumps({"phase": state["phase"], "backendRouteActive": state["backendRouteActive"],
                                  "trafficOpen": state["trafficOpen"], "manualProxyClosureRequired": state.get("manualProxyClosureRequired", False)}, sort_keys=True))
            else:
                proxy = Proxy(cfg["proxySocket"])
                if args.command == "prepare":
                    prepare(cfg, directory, cfg_hash, proxy)
                else:
                    activate(cfg, directory, cfg_hash, proxy)
                print("cutover phase: " + load_phase(directory, cfg_hash)["phase"])
        finally:
            os.close(fd)
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
