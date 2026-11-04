"""Real Linux/X11 Minecraft menu observation for a staged Runtime process.

No file supplied by the game, CI job or caller can assert PASS. The observer
correlates the window's OS PID to the actual Runtime child, captures two
independently rendered frames and recognizes visible menu controls. Unsupported
hosts remain blocked (never interpreted as incompatible Minecraft builds).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time

FATAL = re.compile(
    r"(?im)(?:^|[^\w])(?:OutOfMemoryError|GC overhead limit exceeded|Could not reserve enough space|"
    r"A fatal error has been detected by the Java Runtime Environment|"
    r'Exception in thread ["\x27]main|GLFW error 65542|OpenGL is not supported|'
    r"Guard[^\n]{0,100}(?:violation|denied|blocked)|"
    r"\[(?:[^\]\n]+/)?FATAL\]|\bEXCEPTION_ACCESS_VIOLATION\b|SIGSEGV\b)"
)
LOADER = {
    "fabric": re.compile(
        r"(?i)(?:Loading Minecraft[^\n]{0,120}with Fabric Loader|FabricLoader[^\n]{0,120}initializ)"
    ),
    "quilt": re.compile(
        r"(?i)(?:Loading Minecraft[^\n]{0,120}with Quilt Loader|Quilt Loader[^\n]{0,120}initializ)"
    ),
    "forge": re.compile(
        r"(?i)(?:--fml\.forgeVersion|MinecraftForge[^\n]*initialized|Forge Mod Loader[^\n]*loading|net\.minecraftforge\.fml\.loading)"
    ),
    "neoforge": re.compile(
        r"(?i)(?:--fml\.neoForgeVersion|NeoForge[^\n]{0,120}|net\.neoforged\.fml\.loading)"
    ),
}
MENU = {
    "singleplayer": re.compile(r"(?i)single\s*player"),
    "multiplayer": re.compile(r"(?i)multi\s*player"),
    "options": re.compile(r"(?i)options"),
    "quit": re.compile(r"(?i)quit\s*game"),
}
WINDOW = re.compile(r'^\s*(0x[0-9a-fA-F]+)\s+"([^"\n]{0,200})"', re.M)
PID_PROP = re.compile(r"_NET_WM_PID\(CARDINAL\)\s*=\s*(\d+)")


def command(argv, timeout=7):
    cp = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if cp.returncode:
        raise RuntimeError(
            f"{argv[0]} returned {cp.returncode}: {cp.stderr[:160].decode(errors='replace')}"
        )
    return cp.stdout.decode(errors="replace")


def parent_pid(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat[stat.rfind(")") + 2 :].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def is_descendant(pid, ancestor):
    seen = set()
    while pid and pid > 1 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        pid = parent_pid(pid)
    return False


def find_window(root_pid, java_binary=None):
    if sys.platform in ("win32", "darwin"):
        from native_window_03410 import find_window as native_find_window

        return native_find_window(root_pid, java_binary)
    listing = command(["xwininfo", "-root", "-tree"], 5)
    for wid, name in WINDOW.findall(listing):
        if not re.search(r"(?i)minecraft", name):
            continue
        try:
            prop = command(["xprop", "-id", wid, "_NET_WM_PID"], 4)
        except RuntimeError:
            continue
        match = PID_PROP.search(prop)
        if match:
            pid = int(match.group(1))
            # A name alone is NEVER proof; the Java game must be our child.
            if is_descendant(pid, root_pid):
                if java_binary is not None:
                    # A different process under the same runner cannot masquerade
                    # as the signed release's selected Java executable.
                    try:
                        if not os.path.samefile(f"/proc/{pid}/exe", java_binary):
                            continue
                    except OSError:
                        continue
                return wid, pid
    return None


def log_health(client_dir, runtime_log, loader):
    paths = [
        runtime_log,
        client_dir / "logs" / "latest.log",
        client_dir / "logs" / "debug.log",
    ]
    combined = ""
    for path in paths:
        if path and path.exists() and path.is_file():
            # Bound reads, avoid untrusted huge diagnostics and disk exhaustion.
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 2 * 1024 * 1024))
                combined += "\n" + stream.read(2 * 1024 * 1024).decode(
                    "utf-8", "replace"
                )
    crash_files = (
        list((client_dir / "crash-reports").glob("crash-*.txt"))
        if (client_dir / "crash-reports").is_dir()
        else []
    )
    jvm_crashes = list(client_dir.glob("hs_err_pid*.log"))
    fatal = FATAL.search(combined)
    if crash_files or jvm_crashes or fatal:
        cause = (
            "crash report / fatal JVM file"
            if crash_files or jvm_crashes
            else "fatal output: " + fatal.group(0)[:120]
        )
        return False, cause
    loader = loader.lower()
    if loader in ("vanilla", ""):
        return True, "vanilla: no mod-loader bootstrap required"
    pattern = LOADER.get(loader)
    if pattern is None:
        return False, "unsupported signed loader: " + loader
    return bool(pattern.search(combined)), (
        "loader bootstrap log observed"
        if pattern.search(combined)
        else "required loader bootstrap log absent"
    )


def capture_menu(wid, destination):
    if sys.platform in ("win32", "darwin"):
        from native_window_03410 import capture_menu as native_capture_menu

        return native_capture_menu(wid, destination, MENU)
    # Capture the specific PID-verified window, not the screen or an unrelated app.
    # scrot uses X11 directly; unlike some ImageMagick builds it does not
    # depend on an optional X11 delegate for taking screenshots.
    destination.unlink(missing_ok=True)
    command(["scrot", "--window", wid, "--silent", str(destination)], 9)
    meta = command(
        ["identify", "-format", "%w %h %[entropy]", str(destination)], 6
    ).split()
    if len(meta) != 3:
        raise RuntimeError("invalid X11 capture image")
    width, height, entropy = int(meta[0]), int(meta[1]), float(meta[2])
    if (
        width < 640
        or height < 400
        or entropy < 0.12
        or destination.stat().st_size < 2048
    ):
        return None
    text = command(
        ["tesseract", str(destination), "stdout", "--psm", "4", "-l", "eng"], 9
    )
    controls = sorted(key for key, regex in MENU.items() if regex.search(text))
    if len(controls) < 2:
        # Some title-screen layouts yield better segmentation as sparse text.
        text = command(
            ["tesseract", str(destination), "stdout", "--psm", "11", "-l", "eng"], 9
        )
        controls = sorted(key for key, regex in MENU.items() if regex.search(text))
    # Two distinct native Minecraft controls (e.g. Singleplayer / Multiplayer)
    # actually visible on a rendered frame are stronger than a startup log.
    if len(controls) < 2:
        return None
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    return {
        "window": wid,
        "width": width,
        "height": height,
        "entropy": round(entropy, 4),
        "sha256": digest,
        "menuControls": controls,
    }


class StartupObserver:
    def __init__(
        self, root_pid, client_dir, evidence_dir, loader, started_at, java_binary=None
    ):
        self.root_pid = root_pid
        self.client_dir = Path(client_dir)
        self.evidence_dir = Path(evidence_dir)
        self.loader = loader.lower()
        self.started_at = started_at
        self.java_binary = java_binary
        self.runtime_log = None
        self.samples = []
        self.window_pid = None
        self.failure = None
        self.blocked = None
        self.last_probe = 0
        self.last_frame_hash = None
        self.last_change_monotonic = None
        self.window_last_seen_monotonic = None
        self.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # V10: probe real host capabilities, including a fresh OpenGL context
        # on native Windows/macOS (not a caller-supplied "hasGPU" assertion).
        from runtime_capabilities_03410 import evaluate

        caps = evaluate("gui", java_binary)
        if caps["status"] != "ready":
            self.blocked = "; ".join(caps["blockers"]) or "GUI capability probe blocked"

    def tick(self):
        if self.blocked or self.failure or time.monotonic() - self.last_probe < 2:
            return
        self.last_probe = time.monotonic()
        candidates = sorted((self.client_dir / "logs").glob("runtime-launch-*.log"))
        # Never use a stale log from a previous run to authorize readiness.
        candidates = [p for p in candidates if p.stat().st_mtime >= self.started_at - 1]
        self.runtime_log = candidates[-1] if candidates else None
        ready, detail = log_health(self.client_dir, self.runtime_log, self.loader)
        if detail.startswith(("fatal", "crash")):
            self.failure = detail
            return
        if not ready:
            return
        try:
            window = find_window(self.root_pid, self.java_binary)
            if window is None:
                return
            wid, pid = window
            if self.window_pid is not None and pid != self.window_pid:
                self.samples.clear()
            self.window_pid = pid
            self.window_last_seen_monotonic = time.monotonic()
            # Keep only two distinct proof frames, reuse a scratch capture after that.
            path = self.evidence_dir / (
                f"menu-frame-{len(self.samples) + 1}.png"
                if len(self.samples) < 2
                else "menu-current.png"
            )
            sample = capture_menu(wid, path)
            if sample is None:
                path.unlink(missing_ok=True)
                return
            sample["pid"] = pid
            sample["loader"] = self.loader
            now = time.monotonic()
            if sample["sha256"] != self.last_frame_hash:
                self.last_change_monotonic = now
                self.last_frame_hash = sample["sha256"]
            if len(self.samples) < 2 and (
                not self.samples
                or (
                    sample["sha256"] != self.samples[-1]["sha256"]
                    and now - self.samples[-1]["observedMonotonic"] >= 2
                )
            ):
                sample["observedMonotonic"] = now
                self.samples.append(sample)
            else:
                path.unlink(missing_ok=True)
        except Exception as exc:
            from native_window_03410 import GUIUnavailable

            if isinstance(exc, GUIUnavailable):
                self.blocked = str(exc)[:240]
                return
            if not isinstance(
                exc, (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired)
            ):
                raise
            # Failure to obtain a window is not proof of Minecraft incompatibility.
            self.last_diagnostic = str(exc)[:240]

    def conclude(self, launch):
        ready, detail = log_health(self.client_dir, self.runtime_log, self.loader)
        if self.failure or detail.startswith(("fatal", "crash")):
            return "failed", self.failure or detail
        if self.blocked:
            return "blocked", self.blocked
        if not ready:
            return "failed", f"loader readiness absent: {detail}"
        if launch.get("exit_code") not in (None, 0) and not launch.get("timed_out"):
            return "failed", "Minecraft JVM exited with failure"
        if len(self.samples) != 2:
            return (
                "failed",
                "startup deadline reached without two live rendered main-menu observations",
            )
        if self.samples[0]["sha256"] == self.samples[1]["sha256"]:
            return "failed", "renderer/menu stopped updating"
        now = time.monotonic()
        if self.last_change_monotonic is None or now - self.last_change_monotonic > 12:
            return "failed", "renderer stopped producing fresh menu frames (hang/stall)"
        if (
            self.window_last_seen_monotonic is None
            or now - self.window_last_seen_monotonic > 12
        ):
            return "failed", "Minecraft window disappeared or stopped responding"
        if not launch.get("timed_out") and not launch.get("success"):
            return "failed", "Minecraft JVM failed before startup validation completed"
        return (
            "passed",
            f"game window PID {self.window_pid}, renderer frames and main-menu controls observed; {detail}",
        )

    def evidence(self):
        return {
            "schemaVersion": "launcher.startup-readiness.v1",
            "windowPid": self.window_pid,
            "loader": self.loader,
            "samples": [
                {k: v for k, v in s.items() if k != "observedMonotonic"}
                for s in self.samples
            ],
            "failure": self.failure,
            "blocked": self.blocked,
            "lastDiagnostic": getattr(self, "last_diagnostic", None),
        }
