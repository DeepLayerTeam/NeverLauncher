#!/usr/bin/env python3
"""Безопасный отказ при эксплуатационном откате Gravit/Never через PostgreSQL и HAProxy.

Это НЕ откатывает файлы действующих миров и НЕ запускает старые процессы записи
Gravit. Перед планированием и подтверждением оператор должен согласовать
данные миров, игроков и БД плагинов, а также доказать остановку обоих независимых
процессов записи. Состояние прокси Runtime не является долговременным.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import production_cutover_04911 as co

FORMAT = "never/gravit-operational-rollback/v1"
UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service$")
PHASES = ("fenced", "planned", "committing", "committed_fenced", "blocked", "uncertain")


def require(condition, message):
    co.require(condition, message)


def sha_file(path: Path, *, limit=8 << 20):
    data = co.strict_file(path, limit)
    return hashlib.sha256(data).hexdigest()


def validate(cfg: dict, cutover: dict):
    require(cfg.get("format") == FORMAT, "Неизвестный формат конфигурации отката")
    require(cfg.get("runId") == cutover["runId"] and cfg.get("profileId") == cutover["profileId"]
            and cfg.get("channel") == cutover["channel"], "Область отката отличается от области переключения")
    require(cfg.get("cutoverConfigSha256") == cutover["_hash"], "Хеш конфигурации переключения не совпадает")
    require(isinstance(cfg.get("units"), dict) and set(cfg["units"]) == {"source", "target"},
            "Необходимо проверить системные службы исходной и целевой систем")
    units = cfg["units"]
    for side in ("source", "target"):
        values = units[side]
        require(isinstance(values, list) and values and all(isinstance(x, str) and UNIT.fullmatch(x) for x in values)
                and len(values) == len(set(values)), "Некорректный список служб systemd: " + side)
    require(not set(units["source"]).intersection(units["target"]), "Одна служба не может одновременно быть источником и целью")
    for name in ("currentSnapshot", "sourceSnapshot"):
        require(isinstance(cfg.get(name), str) and Path(cfg[name]).is_absolute(), "absolute " + name + " required")
    # Конфигурация восстановления запрещает произвольный запуск команд, небезопасный HTTP и секреты.
    permitted = {"format", "runId", "profileId", "channel", "cutoverConfigSha256", "units",
                 "currentSnapshot", "sourceSnapshot", "reconciliationEvidenceSha256"}
    require(set(cfg) <= permitted, "Неизвестные или небезопасные поля конфигурации отката")
    if "reconciliationEvidenceSha256" in cfg:
        require(bool(co.HEX.fullmatch(str(cfg["reconciliationEvidenceSha256"]))), "Некорректные доказательства сверки")


def systemd_state(unit: str) -> dict:
    try:
        out = subprocess.run(["systemctl", "show", unit, "--property=ActiveState,SubState,UnitFileState",
                              "--no-pager"], stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise co.Blocked("Не удалось проверить служба systemd" + unit) from exc
    result = dict(line.split("=", 1) for line in out.stdout.decode("utf-8", "replace").splitlines() if "=" in line)
    require(all(result.get(field) for field in ("ActiveState", "SubState", "UnitFileState")),
            "Неполный ответ systemd для " + unit)
    return result


def check_writers(cfg: dict):
    for side in ("source", "target"):
        for unit in cfg["units"][side]:
            values = systemd_state(unit)
            require(values["ActiveState"] == "inactive" and values["UnitFileState"] in
                    ("masked", "masked-runtime"),
                    "Записывающий процесс не остановлен и не заблокирован через systemd mask: " + unit)


def capture_snapshot(path: Path, after: float | None = None) -> tuple[str, dict]:
    require(path.is_absolute(), "Требуется абсолютный путь к снимку")
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_mode & 0o077 == 0 and st.st_nlink == 1,
            "Снимок должен быть закрытым обычным файлом с одной жёсткой ссылкой")
    if after is not None:
        require(st.st_mtime >= after, "Снимок необходимо экспортировать после блокировки входящего трафика и записывающих процессов")
    raw = co.strict_file(path, 8 << 20)
    decoder = json.loads(raw)
    require(isinstance(decoder, dict) and isinstance(decoder.get("worldSha256"), str)
            and co.HEX.fullmatch(decoder["worldSha256"])
            and isinstance(decoder.get("players"), list), "Некорректная структура снимка Gravit")
    return hashlib.sha256(raw).hexdigest(), decoder


def get_route(cutover: dict, directory: Path, filename: str):
    return co.route_list(cutover, directory, filename)


def verify_active(cutover: dict, route: dict):
    co.assert_route(route, cutover, True)


def verify_rolled_back(cutover: dict, route: dict):
    require(route.get("runId") == cutover["runId"] and route.get("profileId") == cutover["profileId"]
            and route.get("channel") == cutover["channel"] and route.get("stageId") == cutover["stageId"]
            and route.get("releaseId") == cutover["releaseId"] and route.get("targetDigest") == cutover["targetDigest"]
            and route.get("state") == "rolled_back" and route.get("revision") == cutover["expectedRevision"] + 2,
            "Не подтверждено восстановление прежнего маршрута Backend")


def journal_path(directory: Path):
    return directory / "rollback-state.json"


def write_journal(directory: Path, doc: dict, new=False):
    path = journal_path(directory)
    raw = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) < 16384, "Журнал отката слишком велик")
    if new:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    else:
        require(path.exists() and not path.is_symlink(), "Журнал отката отсутствует")
        tmp = directory / "rollback-state.json.next"
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def state_load(directory: Path, cfg_hash: str, cut_hash: str):
    state = co.document(journal_path(directory), 16384)
    require(state.get("format") == FORMAT and state.get("configSha256") == cfg_hash
            and state.get("cutoverConfigSha256") == cut_hash and state.get("phase") in PHASES,
            "Журнал отката не соответствует ожидаемому")
    return state


def change(directory: Path, state: dict, phase: str, **props):
    state.update(props)
    state["phase"] = phase
    state["updatedAtUnix"] = int(time.time())
    write_journal(directory, state)


def assert_proxy(proxy: co.Proxy, cutover: dict, state: dict):
    require(proxy.instance() == state["haproxyPid"],
            "HAProxy перезапущен: перезагрузка могла возобновить трафик к исходной системе")
    co.inspect_proxy(proxy, cutover, "closed")


def fence(cfg, cut, directory, cfg_hash, proxy):
    require(not journal_path(directory).exists(), "Журнал отката уже существует: проверьте состояние и выполните сверку; не повторяйте запуск вслепую")
    cutstate = co.load_phase(directory, cut["_hash"])
    require(cutstate["phase"] in ("complete", "blocked", "route_activated", "target_open"),
            "Переключение не находится в состоянии после активации")
    route = get_route(cut, directory, "rollback-before.json")
    verify_active(cut, route)
    pid = proxy.instance()
    # Сначала закройте внешний входящий трафик, затем извне остановите/заблокируйте ВСЕ известные независимые процессы записи.
    # При неуспешном закрытии нельзя создавать ложный журнал готовности.
    co.close_ingress(proxy, cut)
    require(proxy.instance() == pid, "HAProxy перезапущен во время закрытия входящего трафика")
    state = {"format": FORMAT, "configSha256": cfg_hash, "cutoverConfigSha256": cut["_hash"],
             "phase": "fenced", "haproxyPid": pid, "routeRevision": route["revision"],
             "fencedAtUnix": int(time.time()), "updatedAtUnix": int(time.time()), "trafficOpen": False}
    write_journal(directory, state, new=True)
    return state


def typed_digest(snapshot: dict) -> str:
    """Соблюдайте порядок полей Go gravitrehearsal.SnapshotDigest и кодирование JSON."""
    required = ("worldSha256", "loader", "optionalPresetSha256", "players")
    pfields = ("sourceId", "uuid", "inventorySha256", "permissionsSha256", "economy", "skinSha256", "admin")
    require(set(snapshot) == set(required) and isinstance(snapshot["players"], list), "Неожиданные поля снимка")
    players = []
    for p in snapshot["players"]:
        require(isinstance(p, dict) and set(p) == set(pfields) and isinstance(p["admin"], bool)
                and all(isinstance(p[x], str) for x in pfields if x != "admin"), "Некорректная запись игрока в снимке")
        players.append({k: p[k] for k in pfields})
    require(all(isinstance(snapshot[k], str) for k in required if k != "players"), "Некорректная строка в снимке")
    canonical = {k: players if k == "players" else snapshot[k] for k in required}
    return co.digest(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def validate_source_against_target(current: dict, source: dict, has_reconciliation: bool, baseline: str):
    # Если Never создал новые игровые данные, потребуйте от оператора сначала согласовать их
    # с ИЗОЛИРОВАННЫМ источником, затем независимо повторно выгрузить ОБА набора.
    # Backend выполняет дополнительные предметные проверки содержимого.
    if has_reconciliation:
        require(current == source, "Исходная система не приведена в точное соответствие с текущим состоянием миров и игроков Never")
    else:
        require(typed_digest(source) == baseline, "Снимок Gravit больше не совпадает с базовым состоянием MIG10; сначала выполните сверку")


def snapshots(cfg, state, cut, *, fresh=None):
    current = Path(fresh or cfg["currentSnapshot"])
    current_sha, current_obj = capture_snapshot(current, state["fencedAtUnix"])
    source_sha, source_obj = capture_snapshot(Path(cfg["sourceSnapshot"]), state["fencedAtUnix"])
    validate_source_against_target(current_obj, source_obj, bool(cfg.get("reconciliationEvidenceSha256")), cut["sourceSnapshotSha256"])
    return current, current_sha, source_sha


def plan(cfg, cut, directory, state, proxy):
    require(state["phase"] == "fenced", "Откат уже запланирован или предпринималась попытка отката")
    assert_proxy(proxy, cut, state)
    check_writers(cfg)
    verify_active(cut, get_route(cut, directory, "rollback-route-plan.json"))
    current, sha, source_sha = snapshots(cfg, state, cut)
    args = ["rollback-plan", "--backend", cut["backend"], "--run", cut["runId"],
            "--confirm", cut["runId"], "--profile-id", cut["profileId"], "--channel", cut["channel"],
            "--expected-revision", str(state["routeRevision"]), "--writer-fenced", "true",
            "--snapshot", str(current)]
    if cfg.get("reconciliationEvidenceSha256"):
        args += ["--reconciled-source-snapshot", cfg["sourceSnapshot"],
                 "--reconciliation-evidence-sha256", cfg["reconciliationEvidenceSha256"]]
    report = co.run_cli(cut, args, directory / "rollback-plan-result.json")
    require(report.get("format") == "never/gravit-rollback/v1" and report.get("runId") == cut["runId"]
            and report.get("profileId") == cut["profileId"] and report.get("channel") == cut["channel"]
            and report.get("state") == "planned" and report.get("ready") is True
            and report.get("blockers") in ([], None) and report.get("routeRevision") == state["routeRevision"]
            and bool(co.HEX.fullmatch(str(report.get("planSha256", ""))))
            and report.get("evidenceSha256") == sha
            and report.get("mode") == ("reconciled" if cfg.get("reconciliationEvidenceSha256") else "unchanged"),
            "Backend не одобрил конкретный план отката")
    change(directory, state, "planned", planSha256=report["planSha256"],
           snapshotSha256=sha, sourceSnapshotFileSha256=source_sha, plannedAtUnix=int(time.time()))
    return state


def verify_completed(cut, directory, state):
    suffix = next((f"-{n:03d}" for n in range(1, 1000)
                   if not (directory / f"rollback-status-final-{n:03d}.json").exists()
                   and not (directory / f"rollback-route-after-{n:03d}.json").exists()), None)
    require(suffix is not None, "Исчерпаны доказательства сверки отката")
    status = co.run_cli(cut, ["rollback-status", "--backend", cut["backend"], "--run", cut["runId"],
                              "--profile-id", cut["profileId"], "--channel", cut["channel"]],
                        directory / ("rollback-status-final" + suffix + ".json"))
    require(status.get("state") == "completed" and status.get("ready") is True
            and status.get("planSha256") == state["planSha256"]
            and status.get("routeRevision") == state["routeRevision"],
            "Backend не подтвердил завершение отката по этому плану")
    verify_rolled_back(cut, get_route(cut, directory, "rollback-route-after" + suffix + ".json"))


def commit(cfg, cut, directory, state, proxy, fresh: Path):
    require(state["phase"] == "planned", "Применять разрешено только одобренный откат")
    require(time.time() - state["plannedAtUnix"] < 540, "Срок действия плана отката истёк; не используйте старый план повторно")
    assert_proxy(proxy, cut, state)
    check_writers(cfg)
    verify_active(cut, get_route(cut, directory, "rollback-route-precommit.json"))
    current, sha, source_sha = snapshots(cfg, state, cut, fresh=fresh)
    require(current != Path(cfg["currentSnapshot"]), "Свежий снимок должен быть отдельным экспортом, выполненным после составления плана")
    require(current.stat().st_mtime >= state["plannedAtUnix"], "Снимок Never создан раньше плана отката")
    require(sha == state["snapshotSha256"] and source_sha == state["sourceSnapshotFileSha256"],
            "Состояние миров или игроков изменилось после одобрения; требуется новый план")
    args = ["rollback-commit", "--backend", cut["backend"], "--run", cut["runId"],
            "--confirm", cut["runId"], "--profile-id", cut["profileId"], "--channel", cut["channel"],
            "--expected-revision", str(state["routeRevision"]), "--writer-fenced", "true",
            "--source-writer-fenced", "true", "--plan-sha256", state["planSha256"],
            "--snapshot", str(current), "--current-evidence-sha256", sha]
    if cfg.get("reconciliationEvidenceSha256"):
        args += ["--reconciled-source-snapshot", cfg["sourceSnapshot"],
                 "--reconciliation-evidence-sha256", cfg["reconciliationEvidenceSha256"]]
    change(directory, state, "committing")
    try:
        report = co.run_cli(cut, args, directory / "rollback-commit-result.json")
        require(report.get("state") == "completed" and report.get("planSha256") == state["planSha256"],
                "Backend не подтвердил применение отката")
        verify_completed(cut, directory, state)
        assert_proxy(proxy, cut, state)
        change(directory, state, "committed_fenced", trafficOpen=False)
    except BaseException as exc:
        try:
            co.close_ingress(proxy, cut)
        except Exception:
            state["manualProxyClosureRequired"] = True
        change(directory, state, "uncertain", failureClass=type(exc).__name__)
        raise


def reconcile(cut, directory, state, proxy):
    require(state["phase"] in ("committing", "uncertain", "committed_fenced"),
            "Сверять можно только фактически предпринятую попытку применения")
    assert_proxy(proxy, cut, state)
    # НЕ повторяйте COMMIT после тайм-аута. Сначала считайте достоверное состояние PostgreSQL.
    verify_completed(cut, directory, state)
    change(directory, state, "committed_fenced", trafficOpen=False)


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fence", "plan", "commit", "reconcile", "status"))
    parser.add_argument("--cutover-config", required=True)
    parser.add_argument("--rollback-config", required=True)
    parser.add_argument("--journal-dir", required=True)
    parser.add_argument("--confirm", default="")
    parser.add_argument("--fresh-snapshot", default="")
    args = parser.parse_args(argv)
    try:
        cutraw = co.strict_file(Path(args.cutover_config))
        cut = json.loads(cutraw)
        directory = Path(args.journal_dir)
        co.validate(cut, directory)
        cut["_hash"] = co.digest(cutraw)
        cfgraw = co.strict_file(Path(args.rollback_config))
        cfg = json.loads(cfgraw)
        validate(cfg, cut)
        cfg_hash = co.digest(cfgraw)
        require(args.command == "status" or args.confirm == cut["runId"], "Требуется точное подтверждение идентификатора запуска")
        require(args.command == "commit" or not args.fresh_snapshot, "Параметр --fresh-snapshot разрешён только при применении")
        if args.command == "commit":
            require(args.fresh_snapshot and Path(args.fresh_snapshot).is_absolute(), "Требуется независимый свежий снимок")
        lock = os.open(directory / ".cutover.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == "status":
                state = state_load(directory, cfg_hash, cut["_hash"])
                print(json.dumps({"phase": state["phase"], "trafficOpen": state["trafficOpen"],
                                  "manualProxyClosureRequired": state.get("manualProxyClosureRequired", False)}, sort_keys=True))
            else:
                proxy = co.Proxy(cut["proxySocket"])
                if args.command == "fence":
                    state = fence(cfg, cut, directory, cfg_hash, proxy)
                else:
                    state = state_load(directory, cfg_hash, cut["_hash"])
                    if args.command == "plan":
                        plan(cfg, cut, directory, state, proxy)
                    elif args.command == "commit":
                        commit(cfg, cut, directory, state, proxy, Path(args.fresh_snapshot))
                    else:
                        reconcile(cut, directory, state, proxy)
                print("Этап отката: " + state_load(directory, cfg_hash, cut["_hash"])["phase"])
        finally:
            os.close(lock)
        return 0
    except (co.Blocked, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
