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
    require(path.is_absolute(), "Требуется абсолютный путь к файлу")
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= limit and st.st_mode & 0o077 == 0,
            "Файл отсутствует, является символической ссылкой, слишком велик или доступен посторонним: " + str(path))
    with path.open("rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "Размер файла превышает допустимый предел")
    return data


def document(path: Path, limit: int = 1 << 20) -> dict:
    value = json.loads(strict_file(path, limit))
    require(isinstance(value, dict), "Ожидается объект JSON")
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
    require(config.get("format") == FORMAT, "Формат конфигурации не поддерживается")
    for name in ("runId", "profileId", "channel", "stageId", "releaseId"):
        value = config.get(name)
        require(isinstance(value, str) and bool(NAME.fullmatch(value) if name in ("profileId", "channel") else ROUTE.fullmatch(value) if name in ("runId", "stageId") else len(value) >= 8), "invalid " + name)
    require(isinstance(config.get("expectedRevision"), int) and config["expectedRevision"] >= 1, "Требуется ожидаемая редакция маршрута")
    require(isinstance(config.get("inventorySha256"), str) and HEX.fullmatch(config["inventorySha256"]), "Требуется хеш перечня файлов")
    require(isinstance(config.get("targetDigest"), str) and HEX.fullmatch(config["targetDigest"]), "Требуется точный хеш подписанного целевого манифеста")
    require(isinstance(config.get("baselineRevision"), int) and config["baselineRevision"] >= 0, "Требуется исходная редакция канала")
    require(safe_url(config.get("backend", "")), "Backend должен использовать проверенный HTTPS")
    require(isinstance(config.get("launcher"), str) and Path(config["launcher"]).is_absolute(), "Требуется абсолютный путь к CLI")
    launcher = Path(config["launcher"])
    require(launcher.is_file() and not launcher.is_symlink() and os.access(launcher, os.X_OK), "Исполняемый файл лаунчера недоступен")
    require(isinstance(config.get("launcherSha256"), str) and HEX.fullmatch(config["launcherSha256"]), "Требуется хеш исполняемого CLI")
    with launcher.open("rb") as f:
        require(digest(f.read()) == config["launcherSha256"], "Исполняемый CLI лаунчера изменился")
    require(isinstance(config.get("proxySocket"), str) and Path(config["proxySocket"]).is_absolute(), "Требуется путь к Unix-сокету HAProxy")
    sock_stat = Path(config["proxySocket"]).lstat()
    require(stat.S_ISSOCK(sock_stat.st_mode) and sock_stat.st_uid in (0, os.geteuid()),
            "Административный сокет HAProxy должен реально существовать и принадлежать root или оператору")
    require(journal_dir.is_dir() and not journal_dir.is_symlink() and journal_dir.stat().st_mode & 0o077 == 0,
            "Каталог журнала должен существовать, быть закрытым (0700) и не являться ссылкой")
    routes = config.get("routes")
    require(isinstance(routes, dict) and set(routes) == {"auth", "game"}, "Требуются серверные компоненты для входа и игрового трафика")
    pairs = []
    for kind in ("auth", "game"):
        route = routes[kind]
        require(isinstance(route, dict) and set(route) == {"backend", "source", "target"}, "Некорректный маршрут прокси")
        require(all(isinstance(v, str) and SERVER.fullmatch(v) for v in route.values()), "Некорректный Backend или сервер HAProxy")
        require(route["source"] != route["target"], "Источник и цель HAProxy должны различаться")
        pairs.extend([(route["backend"], route["source"]), (route["backend"], route["target"])])
    require(len(pairs) == len(set(pairs)) and routes["auth"]["backend"] != routes["game"]["backend"], "Для входа и игрового трафика нужны разные выделенные серверы прокси")
    require(5 <= config.get("drainSeconds", 0) <= 600, "Параметр drainSeconds должен быть от 5 до 600")
    require(isinstance(config.get("postSwitchStage"), str) and Path(config["postSwitchStage"]).is_absolute(), "После переключения требуется этап фактического запуска Minecraft")
    require(isinstance(config.get("gamePublicAddress"), str) and bool(re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", config["gamePublicAddress"])),
            "Необходимо явно указать публичный адрес Minecraft в формате host:port")
    live = document(Path(config["postSwitchStage"]) / "live-session.json", 16384)
    require(isinstance(live.get("clientArgs"), list) and any(isinstance(arg, str) and config["gamePublicAddress"] in arg for arg in live["clientArgs"]),
            "После переключения клиент запускается без указанной публичной точки входа Minecraft")
    require(isinstance(config.get("authCanary"), dict), "Требуется реальная контрольная проверка авторизации")
    p = config["authCanary"]
    require(safe_url(p.get("url", "")) and p.get("method") == "POST" and
            isinstance(p.get("requestBodyFile"), str) and Path(p["requestBodyFile"]).is_absolute() and
            isinstance(p.get("expectedPlayerUuid"), str) and bool(re.fullmatch(r"[a-f0-9-]{36}", p["expectedPlayerUuid"])) and
            p.get("uuidJSONField") in ("uuid", "playerUuid", "id") and safe_url(p.get("frontendUrl", "")), "invalid authenticated canary configuration")
    require(isinstance(p.get("requestSha256"), str) and HEX.fullmatch(p["requestSha256"]), "Требуется хеш запроса контрольной проверки авторизации")
    require(digest(strict_file(Path(p["requestBodyFile"]), 8192)) == p["requestSha256"], "Запрос контрольной проверки авторизации изменился")
    require(os.environ.get("LAUNCHER_TOKEN", "").strip() != "", "Переменная окружения LAUNCHER_TOKEN должна быть задана")


class Proxy:
    """Реальный сокет Runtime HAProxy. Без командной оболочки и учётных данных сетевого администратора."""
    def __init__(self, path: str):
        self.path = path

    def command(self, command: str) -> str:
        require("\n" not in command and "\r" not in command and len(command) < 256, "Небезопасная команда HAProxy")
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
                require(size <= 4 << 20, "Ответ HAProxy превышает допустимый размер")
                chunks.append(piece)
        data = b"".join(chunks).decode("utf-8", "replace")
        require(not data.lstrip().startswith(("Unknown", "Error", "Permission denied", "No such")),
                "HAProxy отклонил команду")
        return data

    def instance(self) -> str:
        info = {}
        for line in self.command("show info").splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                info[key.strip()] = value.strip()
        pid = info.get("Pid", "")
        require(pid.isdigit() and int(pid) > 0, "Идентификатор процесса HAProxy недоступен")
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
        require(bool(result), "HAProxy не вернул корректные сведения о серверах")
        return result

    def state(self, backend: str, server: str, state: str):
        require(state in ("ready", "drain", "maint"), "Некорректное состояние сервера")
        self.command(f"set server {backend}/{server} state {state}")
        stats = self.stats()
        row = stats.get((backend, server))
        require(row is not None, "Сервер HAProxy исчез")
        if state == "maint":
            require(row.get("status", "").startswith("MAINT"), "HAProxy не применил режим обслуживания")
        if state == "drain":
            require(row.get("status", "").startswith("DRAIN"), "HAProxy не применил режим завершения соединений")
        if state == "ready":
            require(row.get("status") == "UP", "Целевой сервер HAProxy неработоспособен или не находится в состоянии UP")


def inspect_proxy(proxy: Proxy, cfg: dict, phase: str):
    stats = proxy.stats()
    for kind in ("auth", "game"):
        r = cfg["routes"][kind]
        source = stats.get((r["backend"], r["source"]))
        target = stats.get((r["backend"], r["target"]))
        require(source is not None and target is not None, "Отсутствует настроенный сервер входящего трафика " + kind)
        expected = {r["source"], r["target"]}
        for (backend, server), row in stats.items():
            if backend == r["backend"] and server not in expected and server not in ("FRONTEND", "BACKEND"):
                require(row.get("status", "").startswith("MAINT"), "Третий активный сервер входящего трафика в " + kind)
        if phase == "prepare":
            require(source.get("status") == "UP" and target.get("status", "").startswith("MAINT"),
                    "Перед завершением соединений источник должен быть UP, а цель — MAINT")
        elif phase == "closed":
            require(source.get("status", "").startswith("MAINT") and target.get("status", "").startswith("MAINT"),
                    "Входящий трафик перекрыт не полностью")
        elif phase == "open":
            require(source.get("status", "").startswith("MAINT") and target.get("status") == "UP",
                    "Цель не находится в состоянии UP или источник не находится в MAINT")


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
        raise Blocked("Не удалось подтвердить закрытие входящего трафика (требуется ручное обслуживание HAProxy): " + ", ".join(errors))
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
        # Atomic replacement on same filesystem. All journals remain private.
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
    require(result.get("format") == FORMAT and result.get("configSha256") == cfg_hash, "Журнал не соответствует конфигурации")
    return result


def update_phase(directory: Path, state: dict, phase: str, **extras):
    state.update(extras)
    state["phase"] = phase
    state["updatedAtUnix"] = int(time.time())
    journal_write(directory, state)


def run_cli(cfg: dict, args: list[str], output: Path, timeout=120) -> dict:
    require(not output.exists(), "Перезапись доказательств переключения запрещена")
    launcher = Path(cfg["launcher"])
    with launcher.open("rb") as f:
        require(digest(f.read()) == cfg["launcherSha256"], "CLI изменился во время переключения")
    with open(os.devnull, "wb") as sink:
        env = dict(os.environ)
        # The bearer token is environment-only, never stored or placed in argv.
        env.pop("LAUNCHER_PASSWORD", None)
        try:
            subprocess.run([str(launcher), "migrate", "gravit", *args, "--output", str(output)],
                           stdin=sink, stdout=sink, stderr=sink, env=env,
                           timeout=timeout, check=True)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise Blocked("Ошибка команды CLI миграции NeverLauncher: " + args[0]) from exc
    require(output.exists(), "CLI не создал результат " + args[0])
    result = document(output, 1 << 20)
    return result.get("data", result)


def route_list(cfg: dict, directory: Path, name: str) -> dict:
    doc = run_cli(cfg, ["cutover-list", "--backend", cfg["backend"], "--run", cfg["runId"]], directory / name)
    require(isinstance(doc, list), "Некорректный результат списка переключений")
    matching = [v for v in doc if isinstance(v, dict) and v.get("profileId") == cfg["profileId"] and v.get("channel") == cfg["channel"]]
    require(len(matching) == 1, "Требуется ровно один соответствующий маршрут")
    return matching[0]


def assert_route(route: dict, cfg: dict, active: bool):
    require(route.get("runId") == cfg["runId"] and route.get("stageId") == cfg["stageId"]
            and route.get("releaseId") == cfg["releaseId"] and
            route.get("targetDigest") == cfg["targetDigest"] and
            route.get("baselineRevision") == cfg["baselineRevision"] and
            route.get("state") == ("active" if active else "staged"), "cutover route differs from approved target")
    want_rev = cfg["expectedRevision"] + (1 if active else 0)
    require(route.get("revision") == want_rev, "Редакция маршрута переключения изменилась")
    if active:
        require(route.get("activatedRevision") == cfg["baselineRevision"] + 1, "Активированная версия канала не соответствует утверждённой базовой версии")


def receipt_check(cfg: dict) -> None:
    receipt = document(Path(cfg["fenceReceipt"]), 8192)
    require(receipt.get("format") == "never/gravit-source-stop/v1" and
            all(receipt.get(field) == cfg[cfgfield] for field, cfgfield in
                (("runId", "runId"), ("profileId", "profileId"), ("channel", "channel"), ("stageId", "stageId"))) and
            receipt.get("unitState") == "inactive" and receipt.get("unitFileState") in ("masked", "masked-runtime") and
            receipt.get("snapshotSha256") == cfg.get("sourceSnapshotSha256"), "Квитанция блокировки источника не привязана к одобренному источнику")
    # Backend/CLI independently checks the receipt hash and its freshness.
    from datetime import datetime, timezone
    checked = datetime.fromisoformat(receipt["checkedAt"].replace("Z", "+00:00"))
    stopped = datetime.fromisoformat(receipt["stoppedAt"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    require(0 <= (now - checked).total_seconds() < 600 and
            0 <= (now - stopped).total_seconds() < 900, "source fence receipt expired")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("Контрольный запрос авторизации перенаправлен")


def auth_canary(cfg: dict, *, public: bool = False):
    canary = cfg["authCanary"]
    body = strict_file(Path(canary["requestBodyFile"]), 8192)
    require(digest(body) == canary["requestSha256"], "auth canary payload changed since preflight")
    req = Request(canary["frontendUrl"] if public else canary["url"], body, method="POST",
                  headers={"Content-Type": "application/json", "Cache-Control": "no-store"})
    # TLS validation uses OS trust; no insecure override and no cross-host redirects.
    try:
        with build_opener(HTTPSHandler(), NoRedirect()).open(req, timeout=8) as response:
            require(response.status == 200, "Контрольный запрос авторизации отклонён")
            data = response.read(8193)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise Blocked("Ошибка: проверочный вход с аутентификацией в целевую систему") from exc
    require(len(data) <= 8192, "Ответ контрольного запроса авторизации слишком велик")
    result = json.loads(data)
    require(isinstance(result, dict) and result.get(canary["uuidJSONField"]) == canary["expectedPlayerUuid"],
            "Контрольная проверка авторизации подтвердила неверный UUID Minecraft")
    # Intentionally do not persist session cookies, token, password or body.


def live_canary(cfg: dict, directory: Path) -> dict:
    report = run_cli(cfg, ["rehearse-local", "--run", cfg["runId"], "--stage", cfg["postSwitchStage"],
                           "--inventory-sha256", cfg["inventorySha256"]], directory / "post-switch-minecraft.json", 1000)
    require(report.get("ready") is False and report.get("cutoverAllowed") is False,
            "Локальное подтверждение не должно заявлять о сертификации Backend")
    live = report.get("liveSession")
    require(isinstance(live, dict) and live.get("joinedAt") and HEX.fullmatch(str(live.get("clientSha256", "")))
            and live.get("playerUuid") == cfg["authCanary"]["expectedPlayerUuid"],
            "После переключения не обнаружено подключение Minecraft с подтверждённым UUID")
    probes = report.get("probes")
    require(isinstance(probes, list) and len(probes) == len(PROBES)
            and [p.get("name") for p in probes] == list(PROBES)
            and all(p.get("passed") is True and HEX.fullmatch(str(p.get("evidenceSha256", ""))) for p in probes),
            "Проверки Minecraft после переключения не пройдены")
    return report


def prepare(cfg: dict, directory: Path, config_sha: str, proxy: Proxy):
    require(not (directory / "cutover-state.json").exists(), "Существующий журнал требует ручного восстановления")
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
                require(scur.isdigit(), "Некорректное число сессий HAProxy")
                remaining += int(scur)
            if remaining == 0:
                break
            require(time.monotonic() < deadline, "Игровые сеансы и сеансы авторизации источника не завершились")
            time.sleep(1)
        close_ingress(proxy, cfg)
        require(proxy.instance() == proxy_pid, "HAProxy перезапустился во время подготовки переключения")
        update_phase(directory, state, "traffic_fenced")
    except BaseException:
        try:
            close_ingress(proxy, cfg)
        finally:
            update_phase(directory, state, "blocked")
        raise


def activate(cfg: dict, directory: Path, config_sha: str, proxy: Proxy):
    state = load_phase(directory, config_sha)
    require(state["phase"] == "traffic_fenced", "Активировать можно только подготовленную систему с закрытым входящим трафиком")
    inspect_proxy(proxy, cfg, "closed")
    require(proxy.instance() == state.get("haproxyPid"), "HAProxy перезапустился после блокировки входящего трафика; требуется ручная сверка")
    route = route_list(cfg, directory, "route-pre-activate.json")
    assert_route(route, cfg, False)
    receipt_check(cfg)
    # Verify real target auth before changing the PostgreSQL delivery pointer.
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
        # The same UUID must actually join the Minecraft server after switching.
        live_canary(cfg, directory)
        route = route_list(cfg, directory, "route-final.json")
        assert_route(route, cfg, True)
        inspect_proxy(proxy, cfg, "open")
        require(proxy.instance() == state["haproxyPid"], "HAProxy перезапустился до проверки переключения")
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
    # Do not allow migration CLI output files to be created world-readable.
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
        require(args.command == "status" or args.confirm == cfg["runId"], "Требуется точное подтверждение runId")
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
                print("Этап переключения: " + load_phase(directory, cfg_hash)["phase"])
        finally:
            os.close(fd)
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
