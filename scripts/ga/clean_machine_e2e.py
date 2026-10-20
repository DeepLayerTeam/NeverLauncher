#!/usr/bin/env python3
"""Run a *real* clean-VM native-install -> Managed Java -> Minecraft launch.

No stub runtimes or fake JVMs: the installed neverruntime binary performs
manifest signature verification, real Java provisioning, sync and game launch.
This must run inside a disposable OS VM with a graphical session and a signed
offline-capable Minecraft profile; not on a developer workstation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


def checked(command, timeout=900, env=None):
    result = subprocess.run(list(map(str, command)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace", timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {result.stderr[-1000:]}")
    return result.stdout


def from_runtime(binary: Path, *args, timeout=900):
    data = checked([binary, *args], timeout=timeout)
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("NeverRuntime returned non-object JSON")
    return result


def resolve_installed_runtime(root: Path):
    launcher = root / "launcher"
    for slot in ("active-0.json", "active-1.json"):
        pointer = launcher / slot
        if not pointer.is_file() or pointer.is_symlink():
            continue
        rec = json.loads(pointer.read_text())
        release = rec.get("release", "")
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", release) or ".." in release:
            continue
        path = launcher / "releases" / release / ("neverruntime.exe" if os.name == "nt" else "neverruntime")
        if path.is_file() and not path.is_symlink():
            return path
    raise RuntimeError("no native NeverRuntime in activated Prestarter release")


def real_clean_install(*, installer: Path, root: Path, signed_manifest: Path,
                       public_key: str, java_major: int, username: str, benchmark_commit: str):
    if not re.fullmatch("[0-9a-f]{64}", public_key):
        raise ValueError("pinned public key is required")
    if not re.fullmatch("[a-zA-Z0-9_]{3,16}", username):
        raise ValueError("offline Minecraft username must be 3-16 safe characters")
    if not re.fullmatch("[a-f0-9]{40}", benchmark_commit):
        raise ValueError("exact source commit must be supplied")
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("GA clean-machine test requires an EMPTY installation root")
    if os.environ.get("JAVA_HOME"):
        raise RuntimeError("JAVA_HOME must be unset for clean machine bootstrap test")
    if not signed_manifest.is_file() or signed_manifest.is_symlink():
        raise RuntimeError("real signed Minecraft profile required")
    # Package installation is intentionally real, not unpacking package files.
    osname = platform.system()
    if osname == "Linux":
        if os.geteuid() != 0:
            raise RuntimeError("dpkg clean-machine installation requires root inside disposable VM")
        checked(["dpkg", "--install", installer], timeout=600)
        checked(["/usr/bin/neverlauncher", "install", "--root", root, "--no-start"], timeout=1200)
    elif osname == "Darwin":
        checked(["installer", "-pkg", installer, "-target", "/"], timeout=600)
        checked(["/Applications/NeverLauncher.app/Contents/MacOS/NeverLauncher", "install",
                 "--root", root, "--no-start"], timeout=1200)
    elif osname == "Windows":
        checked([installer, "install", "--root", root, "--no-start"], timeout=1200)
        # The native Rust CLI can launch Minecraft on Windows but bypasses the
        # Desktop -> NeverGuard authenticated supervisor boundary. Certification
        # MUST instead use a separate real Desktop/Guard GUI E2E on Windows.
        raise RuntimeError("Windows game-launch certification requires external Desktop/NeverGuard GUI E2E; direct NeverRuntime launch is not a valid security test")
    else:
        raise RuntimeError("unsupported GA OS")
    runtime = resolve_installed_runtime(root)
    runtime_help = from_runtime(runtime, "--help")
    if runtime_help.get("version") != "0.24.0":
        raise RuntimeError("installed runtime is not 0.24.0")
    verification = from_runtime(runtime, "verify", "--manifest", signed_manifest,
                                "--pinned-public-key", public_key)
    if verification.get("status") != "ready":
        raise RuntimeError("signed Minecraft profile was not verified")
    data = json.loads(signed_manifest.read_text())
    signed_major = data.get("runtime", {}).get("java", {}).get("majorVersion")
    if signed_major != java_major:
        raise RuntimeError("Java major differs from the signed profile")
    java = from_runtime(runtime, "java", "ensure", "--major", str(java_major))
    java_path = Path(java.get("javaExecutable", ""))
    if java.get("majorVersion") != java_major or not java_path.is_file() or java_path.is_symlink():
        raise RuntimeError("real Managed Java was not installed")
    checked([java_path, "-version"], timeout=40)
    game_root = root / "profiles" / data["projectId"] / data["profileId"]
    result = from_runtime(runtime, "sync-local", "--manifest", signed_manifest,
                          "--root", game_root, "--pinned-public-key", public_key, timeout=1500)
    if result.get("status") != "ready":
        raise RuntimeError("game file installation failed")
    launched = from_runtime(runtime, "launch", "--manifest", signed_manifest,
                            "--pinned-public-key", public_key, "--root", game_root,
                            "--java", java_path, "--username", username,
                            "--max-runtime-seconds", "90", timeout=120)
    log_path = Path(launched.get("log_path", ""))
    if not log_path.is_file() or not log_path.is_relative_to(game_root):
        raise RuntimeError("Minecraft has no installed runtime log")
    log = log_path.read_text(encoding="utf-8", errors="replace")
    # A Java -version process or a dummy executable cannot pass this check.
    if not any(marker in log for marker in ("LWJGL version", "OpenGL", "Setting user:", "Minecraft")):
        raise RuntimeError("no recognizable Minecraft initialization evidence in real process log")
    if not launched.get("timed_out") and not launched.get("success"):
        raise RuntimeError("Minecraft process crashed before successfully exiting")
    return {"schemaVersion":"neverlauncher.ga.clean-machine.v1", "productVersion":"0.24.0",
            "commit":benchmark_commit, "status":"passed", "simulated":False,
            "platform":osname, "architecture":platform.machine(),
            "installerSha256":hashlib.sha256(installer.read_bytes()).hexdigest(),
            "runtimeSha256":hashlib.sha256(runtime.read_bytes()).hexdigest(),
            "javaSha256":hashlib.sha256(java_path.read_bytes()).hexdigest(),
            "javaMajor":java_major, "minecraftVersion":data.get("minecraft",{}).get("version"),
            "logSha256":hashlib.sha256(log_path.read_bytes()).hexdigest(),
            "launcherExitCode":launched.get("exit_code"), "launchTimedOut":launched.get("timed_out")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--signed-manifest", type=Path, required=True)
    parser.add_argument("--trusted-game-public-key", required=True)
    parser.add_argument("--java-major", type=int, required=True)
    parser.add_argument("--username", default="NLCertPlayer")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = real_clean_install(installer=args.installer.resolve(), root=args.install_root.resolve(),
          signed_manifest=args.signed_manifest.resolve(), public_key=args.trusted_game_public_key,
          java_major=args.java_major, username=args.username, benchmark_commit=args.commit)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        report = {"status":"failed", "productVersion":"0.24.0", "commit":args.commit, "error":str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(f"real clean-machine GA test: {report['status']}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
