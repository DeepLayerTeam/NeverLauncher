#!/usr/bin/env python3
"""Real signed-release lifecycle fault testing using the production CLI/updater and Runtime.

The baseline is an externally pinned, independently signed prior release. No
mock installer, synthetic success, test-only updater hook or mutable stable
channel pointer is used. A missing baseline or Java replacement is BLOCKED.
"""

import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
from runtime_capabilities_03410 import host_identity
from process_group_03410 import group_flags, kill_tree
import socket
import subprocess
import threading
import time
import zipfile
from staged_readiness_0343 import StartupObserver, log_health

SCHEMA = "launcher.lifecycle-validation.v1"
MAX_ZIP_BYTES = 8 << 30


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(1 << 20), b""):
            h.update(part)
    return h.hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def safe_file(root, name):
    from pathlib import PurePosixPath

    p = PurePosixPath(name)
    require(
        name
        and not name.startswith("/")
        and "\\" not in name
        and "\x00" not in name
        and p.as_posix() == name
        and all(x not in (".", "..", "") for x in name.split("/")),
        "unsafe prior-release archive entry",
    )
    target = root.joinpath(*p.parts)
    require(
        target.resolve().is_relative_to(root.resolve()),
        "prior-release archive traversal",
    )
    return target


def extract_pinned_prior(archive, expected, root, current, pinned_key):
    require(
        re.fullmatch("[0-9a-f]{64}", expected or "") is not None,
        "operator-pinned previous-release ZIP digest required",
    )
    require(
        Path(archive).is_file()
        and not Path(archive).is_symlink()
        and Path(archive).stat().st_size <= MAX_ZIP_BYTES
        and digest(archive) == expected,
        "previous release bytes differ from host-pinned SHA-256",
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        require(
            len(members) <= 50000
            and sum(i.file_size for i in members) <= MAX_ZIP_BYTES,
            "previous-release archive exceeds bounded extraction limits",
        )
        seen = set()
        for info in members:
            if info.is_dir():
                continue
            require(
                (info.external_attr >> 16) & 0o170000
                not in (0o120000, 0o060000, 0o020000),
                "special file in previous-release bundle",
            )
            require(info.filename not in seen, "duplicate archive path")
            seen.add(info.filename)
            path = safe_file(root, info.filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as stream, open(path, "xb") as f:
                remaining = info.file_size
                while remaining:
                    chunk = stream.read(min(1 << 20, remaining))
                    require(chunk, "truncated prior-release entry")
                    f.write(chunk)
                    remaining -= len(chunk)
                f.flush()
                os.fsync(f.fileno())
    pkg = json.loads((root / "staged-package-description.json").read_text())
    signed = json.loads((root / "signed-release-manifest.json").read_text())
    require(
        pkg["packageId"] != current["packageId"]
        and pkg["version"] != current["version"],
        "rollback baseline must be a different actual release",
    )
    for identity in ("projectId", "profileId"):
        require(
            pkg[identity] == current[identity]
            and signed[identity] == current[identity],
            "previous release from unrelated project/profile",
        )
    require(
        pkg["version"] == signed["version"]
        and pkg["channel"] == signed["channel"]
        and signed["signature"]["publicKey"].lower() == pinned_key.lower(),
        "previous release signed identity does not match pinned key",
    )

    # Reject an accidentally supplied newer/same baseline. Certification
    # must exercise a real upgrade, not an arbitrary different version.
    def release_key(value):
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][a-zA-Z0-9.\-]+)?", value)
        require(bool(m), "release version must be semantic version")
        return tuple(int(x) for x in m.groups()[:3])

    require(
        release_key(pkg["version"]) < release_key(current["version"]),
        "baseline must precede the candidate release",
    )
    files = {x["path"]: x for x in pkg["files"]}
    manifest_files = {x["path"]: x for x in signed["files"]}
    require(
        files and len(files) == len(pkg["files"]) == len(manifest_files),
        "prior-release signed file set incomplete",
    )
    for name, item in files.items():
        f = safe_file(root, name)
        require(
            f.is_file()
            and not f.is_symlink()
            and f.stat().st_size == item["size"]
            and digest(f) == item["sha256"].lower()
            and manifest_files[name]["sha256"].lower() == item["sha256"].lower()
            and manifest_files[name]["size"] == item["size"],
            "previous release does not contain exact signed bytes: " + name,
        )
    return pkg, signed


def invoke(cli, name, args, result_file, env, good=True):
    proc = subprocess.run(
        [cli, "client", name, *args, "--output", str(result_file)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=1200,
        env=env,
        check=False,
    )
    if good:
        require(
            proc.returncode == 0 and result_file.is_file(),
            "production client " + name + " failed rc=" + str(proc.returncode),
        )
        return json.loads(result_file.read_text())
    require(proc.returncode != 0, "injected failure unexpectedly succeeded: " + name)
    return {"exitCode": proc.returncode}


def verify_exact(root, pkg):
    actual = {}
    for item in pkg["files"]:
        p = safe_file(root, item["path"])
        require(
            p.is_file()
            and not p.is_symlink()
            and p.stat().st_size == item["size"]
            and digest(p) == item["sha256"].lower(),
            "client content differs from required release: " + item["path"],
        )
        actual[item["path"]] = digest(p)
    return actual


class _InterruptHandler(http.server.BaseHTTPRequestHandler):
    data = b""
    cut = True

    def do_GET(self):
        if not self.path.startswith("/api/v1/staged-runs/"):
            self.send_error(404)
            return
        payload = self.data
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.cut:
            self.wfile.write(payload[: max(1, len(payload) // 2)])
            self.wfile.flush()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        else:
            self.wfile.write(payload)

    def log_message(self, *args):
        pass


def interrupted_download(actual_file, download_exact, scratch):
    """Exercise actual signed downloader against half-closed HTTP with REAL staged bytes."""
    payload = actual_file.read_bytes()
    require(
        len(payload) >= 2,
        "cannot inject interrupted download into empty/single-byte file",
    )

    class Handler(_InterruptHandler):
        data = payload

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    target = scratch / "interrupted-download.bin"
    url = f"http://127.0.0.1:{srv.server_port}"
    try:
        rejected = False
        try:
            download_exact(
                url,
                "/api/v1/staged-runs/fault/files/object",
                "test-only",
                target,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            )
        except (ValueError, OSError, RuntimeError, EOFError):
            rejected = True
        require(
            rejected
            and not target.exists()
            and not target.with_name(target.name + ".partial").exists(),
            "interrupted download was accepted or left a corrupt cache file",
        )
        Handler.cut = False
        download_exact(
            url,
            "/api/v1/staged-runs/fault/files/object",
            "test-only",
            target,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
        )
        require(
            digest(target) == digest(actual_file),
            "retry did not restore exact signed bytes",
        )
        return {
            "interruptedRejected": True,
            "partialRemoved": True,
            "retryVerified": True,
            "artifactSha256": digest(target),
        }
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def run_game_launch(
    runtime,
    manifest,
    pinned_key,
    root,
    java,
    loader,
    preset,
    output,
    env,
    max_seconds=180,
):
    # Import the actual Runtime observer, not a simulated readiness check.
    from staged_readiness_0343 import StartupObserver
    import time as _time
    import subprocess as _subprocess

    cmd = [
        runtime,
        "launch",
        "--manifest",
        str(manifest),
        "--pinned-public-key",
        pinned_key,
        "--root",
        str(root),
        "--java",
        java,
        "--max-runtime-seconds",
        str(max_seconds),
    ]
    if preset:
        cmd.extend(["--preset", preset])
    observer = StartupObserver(
        0, root, output.parent / (output.stem + "-frames"), loader, _time.time(), java
    )
    require(
        not observer.blocked,
        "GUI runner incapable of validating lifecycle launch: " + str(observer.blocked),
    )
    # Same implementation as V03, using a file for stdout to prevent deadlock.
    with (
        open(output.with_suffix(".stdout"), "wb") as stdout,
        open(output.with_suffix(".stderr"), "wb") as stderr,
    ):
        proc = _subprocess.Popen(
            cmd, stdout=stdout, stderr=stderr, env=env, **group_flags()
        )
        observer.root_pid = proc.pid
        try:
            deadline = _time.monotonic() + max_seconds + 150
            while proc.poll() is None:
                if _time.monotonic() > deadline:
                    raise TimeoutError("lifecycle JVM hung")
                observer.tick()
                _time.sleep(0.5)
        finally:
            if proc.poll() is None:
                kill_tree(proc)
            proc.wait(timeout=20)
    raw = output.with_suffix(".stdout").read_bytes()
    require(len(raw) <= 4 << 20, "lifecycle JVM stdout oversized")
    launch = json.loads(raw)
    status, detail = observer.conclude(launch)
    healthy, _ = log_health(root, observer.runtime_log, loader)
    require(
        status == "passed" and healthy, "lifecycle startup not ready: " + str(detail)
    )
    output.write_text(
        json.dumps(
            {
                "status": "passed",
                "javaSha256": digest(java),
                "javaVersion": _subprocess.run(
                    [java, "-version"],
                    stdout=_subprocess.PIPE,
                    stderr=_subprocess.STDOUT,
                    timeout=15,
                )
                .stdout.decode(errors="replace")
                .splitlines()[0],
                "menuSamples": observer.evidence()["samples"],
                "loader": loader,
            },
            indent=2,
        )
    )
    return json.loads(output.read_text())


def run_lifecycle(args, work, current_pkg, signed, download_exact, current_java, env):
    """Actual CLI transactions on isolated installation, previous signed bytes, and JVM launches."""
    work = Path(work)
    root = work / "lifecycle-validation"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    previous = root / "previous-source"
    prior_pkg, prior_manifest = extract_pinned_prior(
        args.previous_bundle,
        args.previous_sha256,
        previous,
        current_pkg,
        args.pinned_public_key,
    )
    require(
        prior_manifest["minecraft"]["loader"].lower()
        == signed["minecraft"]["loader"].lower(),
        "prior version loader differs; explicit supported previous target required",
    )
    current_path = work / "payload" / "staged-package-description.json"
    prior_path = previous / "staged-package-description.json"
    client = root / "installation"
    store = root / "cache"
    opt = ["--client-dir", str(client), "--storage-dir", str(store)]
    summary = {
        "schemaVersion": SCHEMA,
        "previousPackageId": prior_pkg["packageId"],
        "previousVersion": prior_pkg["version"],
        "previousArchiveSha256": args.previous_sha256,
        "currentPackageId": current_pkg["packageId"],
        "currentVersion": current_pkg["version"],
        "checks": {},
        "files": {},
    }

    def call(name, pkg, out, success=True):
        return invoke(
            args.cli,
            name,
            ["--package", str(pkg), *opt],
            root / (out + ".json"),
            env,
            success,
        )

    prior_install = call("install", prior_path, "prior-install")
    require(
        prior_install["status"] == "applied-and-verified",
        "previous signed release not installed",
    )
    verify_exact(client, prior_pkg)
    summary["checks"]["cleanPreviousInstall"] = "passed"
    summary["checks"]["previousDigest"] = hashlib.sha256(
        prior_path.read_bytes()
    ).hexdigest()
    # Deliberately make an updater source fail before commit. The old complete
    # installation MUST remain usable; a successful command would be a defect.
    chosen = min(
        (f for f in current_pkg["files"] if f["size"] > 0), key=lambda f: f["size"]
    )
    source = work / "payload" / chosen["path"]
    original = source.read_bytes()
    require(
        len(original) <= 256 << 20,
        "fault injection picks an unexpectedly large source; use another target",
    )
    try:
        source.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        call("update", current_path, "failed-update", False)
    finally:
        source.write_bytes(original)
    verify_exact(client, prior_pkg)
    summary["checks"]["failedUpdateLeavesPrevious"] = "passed"
    upd = call("update", current_path, "update")
    require(
        upd["status"] == "applied-and-verified" and upd["rollbackSnapshot"],
        "production updater did not commit signed new release",
    )
    verify_exact(client, current_pkg)
    summary["checks"]["upgrade"] = "passed"
    summary["rollbackSnapshot"] = upd["rollbackSnapshot"]
    # Damage both active bytes and the preferred source cache. Repair must
    # reject the poisoned cache; only a fresh verified source can heal it.
    live = safe_file(client, chosen["path"])
    live.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    cache_prefix = upd["apply"]["storagePrefix"]
    cache = safe_file(
        store,
        ("/".join([cache_prefix, chosen["path"]]) if cache_prefix else chosen["path"]),
    )
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    call("repair", current_path, "poisoned-cache", False)
    require(
        digest(live) != chosen["sha256"].lower(),
        "corrupt cache unexpectedly restored damaged client",
    )
    cache.unlink()
    repaired = call("repair", current_path, "repaired")
    require(repaired["status"] == "repaired-and-verified", "production repair failed")
    verify_exact(client, current_pkg)
    summary["checks"]["corruptCacheRejected"] = "passed"
    summary["checks"]["repair"] = "passed"
    download_file = (
        work
        / "payload"
        / max(
            (f for f in current_pkg["files"] if f["size"] > 1), key=lambda x: x["size"]
        )["path"]
    )
    summary["checks"]["interruptedDownload"] = interrupted_download(
        download_file, download_exact, root
    )
    for phase in ("staging", "committing"):
        summary["checks"]["interruptedTransaction-" + phase] = interrupt_and_recover(
            args.cli, prior_path, current_path, root, root, env, phase
        )
    # Different actual Java binaries of the same required major. Do not touch
    # system-managed installations, credentials or distribution checksums.
    replacement = Path(args.replacement_java)
    require(
        replacement.is_file()
        and not replacement.is_symlink()
        and replacement.stat().st_mode & 0o111,
        "replacement Java executable unavailable",
    )
    require(
        digest(current_java) != digest(replacement),
        "Java replacement is identical to original runtime",
    )
    actual_ver = subprocess.run(
        [str(replacement), "-version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
    )
    require(actual_ver.returncode == 0, "replacement Java failed version check")
    required_major = int(
        signed["runtime"]["java"].get("recommendedMajorVersion")
        or signed["runtime"]["java"].get("majorVersion")
    )
    import re

    version_line = actual_ver.stdout.decode(errors="replace").splitlines()[0]
    m = re.search(r'(?:version\s+)?["\']?(1\.)?(\d+)(?:[.\+\-]|["\'])', version_line)
    require(
        m and int(m.group(2)) == required_major,
        "replacement Java major differs from signed release",
    )
    game_dir = root / "current-game"
    adopt = [
        args.runtime,
        "adopt-staged",
        "--manifest",
        str(work / "payload" / "signed-release-manifest.json"),
        "--pinned-public-key",
        args.pinned_public_key,
        "--source",
        str(client),
        "--root",
        str(game_dir),
    ]
    if args.preset:
        adopt.extend(["--preset", args.preset])
    proc = subprocess.run(
        adopt, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900
    )
    require(
        proc.returncode == 0 and json.loads(proc.stdout)["status"] == "ready",
        "native current JVM installation failed",
    )
    run_game_launch(
        args.runtime,
        work / "payload" / "signed-release-manifest.json",
        args.pinned_public_key,
        game_dir,
        str(replacement),
        signed["minecraft"]["loader"].lower(),
        args.preset,
        root / "java-replacement-launch.json",
        env,
        args.runtime_seconds,
    )
    # Real Managed Java II replacement: use the runtime's pinned Temurin
    # distribution installer, corrupt its installed java executable, then
    # require the manager to quarantine/reinstall and successfully launch.
    managed_manifest = Path(args.managed_java_manifest)
    require(
        managed_manifest.is_file()
        and not managed_manifest.is_symlink()
        and re.fullmatch("[0-9a-f]{64}", args.managed_java_sha256 or "")
        and digest(managed_manifest) == args.managed_java_sha256,
        "operator-pinned managed Java distribution manifest missing or changed",
    )
    managed_root = root / "managed-java"
    major = str(required_major)
    ensure_cmd = [
        args.runtime,
        "java",
        "ensure",
        "--major",
        major,
        "--distribution",
        "temurin",
        "--runtime-root",
        str(managed_root),
        "--manifest",
        str(managed_manifest),
        "--manifest-sha256",
        args.managed_java_sha256,
    ]

    def ensure_java():
        proc = subprocess.run(
            ensure_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=1200,
            check=False,
        )
        require(
            proc.returncode == 0 and len(proc.stdout) <= 1 << 20,
            "production Managed Java distribution install/repair failed",
        )
        result = json.loads(proc.stdout)
        require(
            result["status"] == "ready"
            and result["majorVersion"] == required_major
            and result["distribution"] == "temurin"
            and Path(result["javaExecutable"]).is_file(),
            "managed Java did not confirm pinned Temurin installation",
        )
        return result

    installed = ensure_java()
    java_bin = Path(installed["javaExecutable"])
    original_java_sha = digest(java_bin)
    require(
        re.fullmatch("[0-9a-f]{64}", original_java_sha) is not None,
        "initial Managed Java checksum missing",
    )
    with open(java_bin, "r+b") as f:
        b = f.read(1)
        require(bool(b), "managed Java binary empty")
        f.seek(0)
        f.write(bytes([b[0] ^ 1]))
        f.flush()
        os.fsync(f.fileno())
    require(
        digest(java_bin) != original_java_sha, "managed Java corruption not applied"
    )
    repaired_java = ensure_java()
    require(
        repaired_java.get("cached") is False
        and digest(repaired_java["javaExecutable"]) == original_java_sha
        and repaired_java["archiveSha256"] == installed["archiveSha256"],
        "Managed Java manager did not quarantine and restore exact approved runtime",
    )
    run_game_launch(
        args.runtime,
        work / "payload" / "signed-release-manifest.json",
        args.pinned_public_key,
        game_dir,
        repaired_java["javaExecutable"],
        signed["minecraft"]["loader"].lower(),
        args.preset,
        root / "managed-java-repair-launch.json",
        env,
        args.runtime_seconds,
    )
    summary["checks"]["managedJavaRepairAndLaunch"] = "passed"
    summary["managedJava"] = {
        "manifestSha256": args.managed_java_sha256,
        "archiveSha256": installed["archiveSha256"],
        "javaSha256": original_java_sha,
        "majorVersion": required_major,
        "reinstalled": True,
    }
    summary["checks"]["javaReplacementLaunch"] = "passed"
    summary["javaOriginalSha256"] = digest(current_java)
    summary["javaReplacementSha256"] = digest(replacement)
    rb = invoke(
        args.cli,
        "rollback",
        ["--client-dir", str(client), "--target", upd["rollbackSnapshot"]],
        root / "rollback.json",
        env,
    )
    require(
        rb["status"] == "rolled-back"
        and rb["restoredSnapshot"] == upd["rollbackSnapshot"],
        "production rollback transaction did not restore prior snapshot",
    )
    summary["files"] = verify_exact(client, prior_pkg)
    prior_game = root / "previous-game"
    adopt = [
        args.runtime,
        "adopt-staged",
        "--manifest",
        str(previous / "signed-release-manifest.json"),
        "--pinned-public-key",
        args.pinned_public_key,
        "--source",
        str(client),
        "--root",
        str(prior_game),
    ]
    proc = subprocess.run(
        adopt, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900
    )
    require(
        proc.returncode == 0 and json.loads(proc.stdout)["status"] == "ready",
        "previous signed client failed native rollback adoption",
    )

    def major_version(manifest):
        j = manifest.get("runtime", {}).get("java", {})
        return int(j.get("recommendedMajorVersion") or j.get("majorVersion") or 0)

    prior_java = current_java
    if major_version(prior_manifest) != major_version(signed):
        envarch = "ARM64" if host_identity()["arch"] == "arm64" else "X64"
        home = env.get(f"JAVA_HOME_{major_version(prior_manifest)}_{envarch}", "")
        require(
            bool(home), "previous signed release Java major not installed on runner"
        )
        prior_java = str(
            (
                Path(home) / "bin" / ("java.exe" if sys.platform == "win32" else "java")
            ).resolve()
        )
        require(Path(prior_java).is_file(), "previous release Java executable missing")
    run_game_launch(
        args.runtime,
        previous / "signed-release-manifest.json",
        args.pinned_public_key,
        prior_game,
        prior_java,
        prior_manifest["minecraft"]["loader"].lower(),
        "",
        root / "rollback-launch.json",
        env,
        args.runtime_seconds,
    )
    summary["checks"]["rollbackAndLaunch"] = "passed"
    summary["previousJavaSha256"] = digest(prior_java)
    summary["filesSha256"] = hashlib.sha256(
        json.dumps(summary["files"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    summary["status"] = "passed"
    result = work / "update-recovery.json"
    result.write_text(json.dumps(summary, indent=2, sort_keys=True))
    return result


def interrupt_and_recover(
    cli, prior_path, current_path, source_root, parent, env, target_phase
):
    """Kill the real updater after a durable journal transition, then run its production recovery.

    A phase not observed is INCONCLUSIVE, never converted into a PASS.
    """
    require(target_phase in ("staging", "committing"), "invalid fault phase")
    case = parent / ("interrupted-" + target_phase)
    case.mkdir(mode=0o700)
    live = case / "client"
    opts = ["--client-dir", str(live), "--storage-dir", str(case / "no-cache")]
    invoke(
        cli, "install", ["--package", str(prior_path), *opts], case / "prior.json", env
    )
    prior_pkg = json.loads(prior_path.read_text())
    verify_exact(live, prior_pkg)
    cmd = [
        cli,
        "client",
        "update",
        "--package",
        str(current_path),
        *opts,
        "--output",
        str(case / "update.json"),
    ]
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        **group_flags(),
    )
    matched = False
    try:
        cutoff = time.monotonic() + 120
        while time.monotonic() < cutoff and p.poll() is None:
            for j in (live / ".launcher" / "updater").glob(
                "transactions/*/journal.json"
            ):
                try:
                    phase = json.loads(j.read_text()).get("phase")
                except (OSError, ValueError):
                    continue
                if phase == target_phase:
                    try:
                        kill_tree(p)
                    except ProcessLookupError:
                        pass
                    matched = True
                    break
            if matched:
                break
            time.sleep(0.001)
    finally:
        if p.poll() is None:
            try:
                kill_tree(p)
            except ProcessLookupError:
                pass
        p.wait(timeout=10)
    require(
        matched and p.returncode != 0,
        "real updater " + target_phase + " interruption not observed; cannot certify",
    )
    # Use the PUBLIC recovery command, not direct editing of journal/locks.
    recovered = subprocess.run(
        [cli, "update", "recover", "--root", str(live)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        timeout=180,
        env=env,
    )
    require(
        recovered.returncode == 0,
        "production updater did not recover interrupted "
        + target_phase
        + " transaction",
    )
    verify_exact(live, prior_pkg)
    # Continue with exact same release through the normal public API.
    updated = invoke(
        cli, "update", ["--package", str(current_path), *opts], case / "retry.json", env
    )
    require(
        updated["status"] == "applied-and-verified",
        "update after interruption did not commit",
    )
    current_pkg = json.loads(current_path.read_text())
    verify_exact(live, current_pkg)
    return {
        "phase": target_phase,
        "killedUpdater": True,
        "recovery": "passed",
        "previousRestored": True,
        "retryVerified": True,
        "currentPackageId": current_pkg["packageId"],
    }
