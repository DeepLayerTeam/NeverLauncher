#!/usr/bin/env python3
"""Run a three-project Gravit import, *real* Minecraft rehearsal and signed client update.

Only existing NeverLauncher CLI runtime paths are used. Rehearsal after update
is an intentionally LOCAL witness: the MIG10 Backend receipt is immutable.
This tool cannot sign GA, forge receipts, or perform production cutover.
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
import time
import zipfile
from urllib.parse import urlsplit

CLASSES = ("fileauth-single", "sql-modded", "proxy-network")
PROBES = ("launch", "login", "join", "skins", "loader", "optional", "admin")
HEX = re.compile(r"^[a-f0-9]{64}$")
RUN = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")
FORMAT = "never/gravit-three-project-rehearsal/v1"


class Blocked(Exception):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise Blocked(message)


def json_file(path: Path, limit: int = 1024 * 1024) -> dict:
    data = regular_bytes(path, limit)
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise Blocked("invalid JSON file: " + str(path)) from exc
    require(isinstance(value, dict), "expected JSON object: " + str(path))
    return value


def _checked_open(path: Path, limit: int):
    """Pin source files to an inode; a replaced or linked source must block cutover."""
    try:
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
                "missing, linked, hardlinked or oversized file: " + str(path))
        require(not any(parent.is_symlink() for parent in path.parents),
                "symlinked parent in migration path: " + str(path))
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        stream = os.fdopen(fd, "rb")
        opened = os.fstat(fd)
        try:
            require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns),
                    "file changed before reading: " + str(path))
        except BaseException:
            stream.close()
            raise
        return stream, st
    except OSError as exc:
        raise Blocked("cannot open checked migration file: " + str(path)) from exc


def _checked_finish(path: Path, stream, st) -> None:
    end = os.fstat(stream.fileno())
    require((end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns)
            == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns),
            "migration file changed during read: " + str(path))


def regular_bytes(path: Path, limit: int) -> bytes:
    stream, st = _checked_open(path, limit)
    with stream:
        data = stream.read(limit + 1)
        require(len(data) == st.st_size and len(data) <= limit,
                "migration file changed or exceeds limit: " + str(path))
        _checked_finish(path, stream, st)
    return data


def sha(path: Path) -> str:
    stream, st = _checked_open(path, 8 << 30)
    h = hashlib.sha256()
    with stream:
        for buf in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(buf)
        _checked_finish(path, stream, st)
    return h.hexdigest()


def checked_file(name: object, digest: object, limit: int = 1024 * 1024 * 1024) -> Path:
    require(isinstance(name, str) and name.startswith("/") and isinstance(digest, str)
            and bool(HEX.fullmatch(digest)), "absolute file and expected SHA-256 required")
    path = Path(name)
    # Хешировать поток с закреплённым inode; завершать с ошибкой, если вход изменён или связан ссылкой.
    stream, st = _checked_open(path, limit)
    with stream:
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
        _checked_finish(path, stream, st)
    require(h.hexdigest() == digest, "file SHA-256 differs from approved bytes: " + name)
    return path


def real_dir(name: object) -> Path:
    require(isinstance(name, str) and name.startswith("/"), "absolute directory required")
    path = Path(name)
    require(path.is_dir() and not path.is_symlink() and path.resolve() == path,
            "missing or linked directory: " + name)
    return path


def within(root: Path, child: object) -> Path:
    require(isinstance(child, str) and child and not child.startswith("/")
            and "\\" not in child and all(t not in ("", ".", "..") for t in child.split("/")),
            "invalid relative installed component")
    path = root / child
    require(path.resolve().is_relative_to(root) and not path.is_symlink(),
            "component escapes installed root")
    return path


def preflight(config: dict, output: Path) -> list[dict]:
    require(config.get("format") == FORMAT, "wrong cohort format")
    backend = config.get("backend")
    require(isinstance(backend, str), "HTTPS Backend origin required")
    origin = urlsplit(backend)
    require(origin.scheme == "https" and bool(origin.hostname) and origin.username is None
            and origin.password is None and origin.path in ("", "/")
            and not origin.query and not origin.fragment and backend.rstrip("/") == backend,
            "rehearsal requires a clean HTTPS Backend origin")
    checked_file(config.get("launcher"), config.get("launcherSha256"), 256 << 20)
    require(os.access(config["launcher"], os.X_OK), "launcher CLI not executable")
    require(isinstance(config.get("projects"), list) and len(config["projects"]) == 3,
            "exactly three real Gravit projects are required")
    output = real_dir(str(output))
    require(output.stat().st_mode & 0o077 == 0, "private output directory must be chmod 0700")
    require(bool(os.environ.get("LAUNCHER_TOKEN", "").strip()), "LAUNCHER_TOKEN required in environment")
    used: dict[str, set] = {name: set() for name in ("class", "run", "project", "source", "stage", "root")}
    result = []
    for p in config["projects"]:
        require(isinstance(p, dict), "project must be an object")
        cls, run, project = p.get("referenceClass"), p.get("runId"), p.get("projectId")
        require(cls in CLASSES and isinstance(run, str) and bool(RUN.fullmatch(run))
                and isinstance(project, str) and bool(RUN.fullmatch(project)),
                "missing class, valid run ID or project ID")
        source = checked_file(p.get("sourceZip"), p.get("sourceSha256"), 512 << 20)
        require(zipfile.is_zipfile(source), "source is not a ZIP: " + str(source))
        checked_file(p.get("mapping"), p.get("mappingSha256"), 12288)
        checked_file(p.get("dryRunReport"), p.get("dryRunReportSha256"), 16 << 20)
        report = json_file(Path(p["dryRunReport"]), 16 << 20)
        body = report.get("data", report)
        require(isinstance(body, dict) and body.get("runId") == run
                and body.get("sourceSha256") == p["sourceSha256"]
                and body.get("inventorySha256") == p.get("inventorySha256")
                and body.get("status") == "manual" and body.get("blockers") == [],
                "approved multi-profile plan missing, stale or blocked")
        stage, root = real_dir(p.get("stage")), real_dir(p.get("installRoot"))
        marker = json_file(stage / ".migration-stage.json", 8192)
        require(marker.get("format") == "never/migration-stage/v1" and marker.get("runId") == run
                and marker.get("isolated") is True, "not a marked isolated stage")
        live = json_file(stage / "live-session.json", 16384)
        require(isinstance(live.get("rconAddress"), str) and
                (live["rconAddress"].startswith("127.") or live["rconAddress"].startswith("[::1]:")),
                "RCON must be bound to loopback")
        for file in ("source-snapshot.json", "target-snapshot.json", "rcon-password"):
            regular_bytes(stage / file, 4 << 20)
        require(stage.joinpath("rcon-password").stat().st_mode & 0o077 == 0,
                "RCON password must be owner-only")
        for name in PROBES:
            probe = stage / "probes" / name
            regular_bytes(probe, 1 << 20)
            require(os.access(probe, os.X_OK), "missing executable staging probe " + name)
        pkg = checked_file(p.get("updatePackage"), p.get("updateSha256"), 8 << 30)
        delivery = checked_file(p.get("deliveryManifest"), p.get("deliverySha256"), 16 << 20)
        require(pkg != source and delivery != source, "source and update package must differ")
        component = within(root, p.get("installedComponent"))
        regular_bytes(component, 256 << 20)
        # Привязать оба свидетельства запуска Minecraft к *реально обновлённому исполняемому файлу*.
        # Иначе стабильная обёртка могла бы запустить старый клиент, пока другой
        # файл Runtime успешно обновлён, создавая ложное свидетельство обновления.
        require(root.is_relative_to(stage) and isinstance(live.get("clientPath"), str),
                "the real client install must be inside its isolated stage")
        require(within(stage, live["clientPath"]) == component,
                "live-session client must be the exact signed component being updated")
        require(isinstance(p.get("expectedUpdatedVersion"), str)
                and bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}(?:[-+][A-Za-z0-9.-]+)?", p["expectedUpdatedVersion"])),
                "expected updated product version required")
        for name, value in (("class", cls), ("run", run), ("project", project),
                            ("source", p["sourceSha256"]), ("stage", str(stage)), ("root", str(root))):
            require(value not in used[name], "two projects share " + name)
            used[name].add(value)
        project_out = output / cls
        require(not project_out.exists() and not project_out.is_symlink(),
                "existing project output: no partial replay without an operator review")
        require(not Path(config["launcher"]).is_relative_to(root), "runner CLI may not be replaced by its own update")
        result.append(dict(p))
    require(used["class"] == set(CLASSES), "all three distinct reference classes required")
    return result


def cli(launcher: str, args: list[str], timeout: int = 1800) -> None:
    # Никогда не помещать bearer-токен оператора в аргументы процесса или отчёт.
    env = dict(os.environ)
    with open(os.devnull, "wb") as sink:
        try:
            subprocess.run([launcher, *args], env=env, stdin=sink, stdout=sink,
                           stderr=sink, check=True, timeout=timeout)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise Blocked("NeverLauncher command failed at " + " ".join(args[:3])) from exc


def verify_rehearsal(path: Path, p: dict, *, authoritative: bool) -> dict:
    doc = json_file(path, 8 << 20)
    r = doc.get("data", doc)
    require(isinstance(r, dict) and r.get("runId") == p["runId"]
            and r.get("sourceInventorySha256") == p["inventorySha256"]
            and r.get("cutoverAllowed") is False,
            "rehearsal report not bound to this run or attempts cutover")
    live = r.get("liveSession")
    require(isinstance(live, dict) and bool(HEX.fullmatch(str(live.get("clientSha256", ""))))
            and bool(live.get("joinedAt")) and live.get("playerUuid"),
            "missing actual observed Minecraft join")
    probes = r.get("probes")
    require(isinstance(probes, list) and [x.get("name") for x in probes if isinstance(x, dict)] == list(PROBES)
            and all(x.get("passed") is True and HEX.fullmatch(str(x.get("evidenceSha256", ""))) for x in probes),
            "missing required executable staging checks")
    require(r.get("ready") is authoritative,
            "Backend did not certify pre-update run or local witness claimed authoritative status")
    if authoritative:
        require(r.get("blockers") == [], "Backend rehearsal reported blockers")
    else:
        require(r.get("blockers") != [], "local-only witness must not be reported as certified")
    return r


def save_private(path: Path, value: dict) -> None:
    content = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def execute_project(launcher: str, backend: str, p: dict, root: Path, launcher_sha: str | None = None) -> dict:
    run = p["runId"]
    out = root / p["referenceClass"]
    out.mkdir(mode=0o700)
    base = ["migrate", "gravit"]
    common = ["--backend", backend, "--run", run]
    common_stage = ["--run", run, "--stage", p["stage"], "--inventory-sha256", p["inventorySha256"]]
    def execute(name: str, command: list[str], limit: int = 1800) -> Path:
        target = out / (name + ".json")
        if launcher_sha is not None:
            require(sha(Path(launcher)) == launcher_sha, "CLI executable changed during migration")
        cli(launcher, command + ["--output", str(target)], limit)
        require(target.is_file() and target.stat().st_size > 0, "missing result of " + name)
        return target
    execute("verify-before-import", base + ["verify-dry-run-all", *common, "--source", p["sourceZip"],
             "--mapping", p["mapping"], "--report", p["dryRunReport"]])
    execute("content-import", base + ["import-content-all", *common, "--confirm", run,
             "--source", p["sourceZip"], "--mapping", p["mapping"], "--report", p["dryRunReport"]], 3600)
    certified_path = execute("pre-update-live", base + ["rehearse", *common_stage,
                                                     "--backend", backend], 1200)
    certified = verify_rehearsal(certified_path, p, authoritative=True)
    old_hash = sha(within(Path(p["installRoot"]), p["installedComponent"]))
    require(certified["liveSession"]["clientSha256"] == old_hash,
            "pre-update live Minecraft did not use the installed client executable")
    update_path = execute("signed-update", ["update", "components", "--package", p["updatePackage"],
             "--expected-sha256", p["updateSha256"], "--delivery-manifest", p["deliveryManifest"],
             "--root", p["installRoot"]], 1800)
    update = json_file(update_path, 16 << 20)
    require(update.get("status") == "committed" and
            update.get("toVersion") == p["expectedUpdatedVersion"] and
            update.get("packageSha256") == p["updateSha256"], "signed component update was not committed")
    new_hash = sha(within(Path(p["installRoot"]), p["installedComponent"]))
    require(old_hash != new_hash, "expected installed runtime component did not change")
    post_path = execute("post-update-live", base + ["rehearse-local", *common_stage], 1200)
    after = verify_rehearsal(post_path, p, authoritative=False)
    require(after["liveSession"]["clientSha256"] == new_hash,
            "post-update live Minecraft did not use the upgraded executable")
    require(after["liveSession"]["playerUuid"] == certified["liveSession"]["playerUuid"],
            "Minecraft UUID changed after client update")
    require(after.get("sourceSnapshotSha256") == certified.get("sourceSnapshotSha256") and
            after.get("targetSnapshotSha256") == certified.get("targetSnapshotSha256"),
            "world, inventory or permissions changed during update")
    return {"referenceClass": p["referenceClass"], "runId": run, "projectId": p["projectId"],
            "sourceSha256": p["sourceSha256"], "updatePackageSha256": p["updateSha256"],
            "installedBeforeSha256": old_hash, "installedAfterSha256": new_hash,
            "preUpdateWitnessSha256": sha(certified_path), "postUpdateWitnessSha256": sha(post_path),
            "status": "isolated-stage-import-launch-update-join-passed"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--preflight-only", action="store_true")
    args = ap.parse_args(argv)
    try:
        cfg = json_file(args.config, 256 << 10)
        cases = preflight(cfg, args.output_dir)
        if args.preflight_only:
            print("PREFLIGHT: 3 distinct sources, stages, hashes and signed update packages present (not E2E)")
            return 0
        report = {"format": FORMAT, "version": "0.49.10", "status": "BLOCKED",
                  "cases": [], "productionGA": False}
        for case in cases:
            report["cases"].append(execute_project(cfg["launcher"], cfg["backend"], case, args.output_dir, cfg["launcherSha256"]))
        report["status"] = "isolated-stage-pass-not-production-GA"
        save_private(args.output_dir / "cohort-04910.json", report)
        print("PASS: 3 isolated real-project import + Minecraft join + signed update + post-update join runs; GA NOT certified")
        return 0
    except (Blocked, OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
