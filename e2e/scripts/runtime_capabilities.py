#!/usr/bin/env python3
"""V10 host capability detection. A missing display never means the game failed.

No capability may be asserted by environment variables or caller-provided JSON.
Capabilities are observed on the worker itself before any Minecraft launch.
"""

from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
OS = {"linux": "linux", "darwin": "macos", "win32": "windows"}
SUPPORTED = {
    "windows": ("amd64", "arm64"),
    "linux": ("amd64", "arm64"),
    "macos": ("amd64", "arm64"),
}


def host_identity(system=None, machine=None):
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    name = OS.get(system)
    arch = ARCH.get(machine)
    if not name or arch not in SUPPORTED.get(name, ()):
        return {"os": name or system, "arch": arch or machine, "supported": False}
    return {"os": name, "arch": arch, "supported": True}


def _probe_java(java):
    if not java:
        return {"available": False, "reason": "No selected Java binary provided"}
    java = Path(java)
    if not java.is_file():
        return {"available": False, "reason": "Selected Java binary does not exist"}
    try:
        proc = subprocess.run(
            [str(java), "-version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=12,
            check=False,
        )
        if proc.returncode or not re.search(
            rb"(?i)(?:openjdk|java)\s+version|(?:openjdk)\s+\d+", proc.stdout
        ):
            return {
                "available": False,
                "reason": "Selected Java executable failed version probe",
            }
        h = hashlib.sha256()
        with java.open("rb") as stream:
            for data in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(data)
        return {
            "available": True,
            "sha256": h.hexdigest(),
            "version": proc.stdout.decode("utf-8", "replace").splitlines()[0][:240],
        }
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {
            "available": False,
            "reason": "Java execution unavailable: " + type(exc).__name__,
        }


def _linux_gui():
    if not os.environ.get("DISPLAY"):
        return (
            False,
            "DISPLAY is unavailable; an X11-capable GUI runner is required",
            None,
        )
    tools = (
        "xwininfo",
        "xprop",
        "scrot",
        "identify",
        "tesseract",
        "glxinfo",
        "xdotool",
    )
    missing = [x for x in tools if not shutil.which(x)]
    if missing:
        return False, "GUI dependencies absent: " + ",".join(missing), None
    try:
        cp = subprocess.run(
            ["glxinfo", "-B"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
            check=False,
        )
        output = cp.stdout.decode("utf-8", "replace")
        renderer = re.search(r"(?im)^OpenGL renderer string:\s*(.+)$", output)
        version = re.search(r"(?im)^OpenGL version string:\s*(.+)$", output)
        if cp.returncode or not renderer or not version:
            return False, "X11 display has no usable OpenGL renderer", None
        return (
            True,
            "",
            {
                "renderer": renderer.group(1).strip()[:200],
                "version": version.group(1).strip()[:200],
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "OpenGL capability probe failed or timed out", None


def _native_display():
    if sys.platform == "win32":
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            # A service in session 0 or a disconnected session is not GUI-capable.
            session = ctypes.c_uint32(0)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            if (
                not kernel.ProcessIdToSessionId(
                    kernel.GetCurrentProcessId(), ctypes.byref(session)
                )
                or session.value == 0
            ):
                return False, "Windows process has no interactive desktop session"
            if user32.GetSystemMetrics(0) < 640 or user32.GetSystemMetrics(1) < 400:
                return False, "Windows desktop dimensions cannot render Minecraft"
            if not user32.GetDesktopWindow() or not user32.GetForegroundWindow():
                return (
                    False,
                    "Windows interactive/unlocked foreground desktop unavailable",
                )
            return True, ""
        except (OSError, AttributeError):
            return False, "Windows desktop API is unavailable"
    if sys.platform == "darwin":
        try:
            import Quartz

            if not Quartz.CGPreflightScreenCaptureAccess():
                return False, "macOS Screen Recording authorization missing"
            if not Quartz.AXIsProcessTrusted():
                return (
                    False,
                    "macOS Accessibility authorization missing for gameplay input",
                )
            display = Quartz.CGMainDisplayID()
            if (
                Quartz.CGDisplayPixelsWide(display) < 640
                or Quartz.CGDisplayPixelsHigh(display) < 400
            ):
                return False, "macOS has no suitable active display"
            return True, ""
        except (ImportError, AttributeError, RuntimeError, OSError, TypeError):
            return False, "macOS Quartz/Screen Recording unavailable"
    return False, "No native display driver for this OS"


def _native_renderer():
    """Create a REAL hidden OpenGL context; GPU inventory is not enough."""
    try:
        import glfw
        from OpenGL import GL
    except ImportError:
        return False, "glfw/PyOpenGL capability dependencies missing", None
    try:
        if not glfw.init():
            return False, "GLFW failed to initialize a native display", None
        glfw.window_hint(glfw.VISIBLE, glfw.FALSE)
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 2)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 1)
        window = glfw.create_window(64, 64, "Launcher capability probe", None, None)
        if not window:
            return False, "GLFW could not create an OpenGL context", None
        try:
            glfw.make_context_current(window)
            renderer = GL.glGetString(GL.GL_RENDERER)
            version = GL.glGetString(GL.GL_VERSION)
            if not renderer or not version:
                return False, "OpenGL context has no renderer/version", None
            return (
                True,
                "",
                {
                    "renderer": renderer.decode("utf-8", "replace")[:200],
                    "version": version.decode("utf-8", "replace")[:200],
                },
            )
        finally:
            glfw.destroy_window(window)
    except Exception as exc:
        return False, "Native OpenGL context probe failed: " + type(exc).__name__, None
    finally:
        try:
            glfw.terminate()
        except Exception:
            pass


def evaluate(mode="gui", java=None):
    if mode not in ("headless", "gui"):
        raise ValueError("invalid runtime execution mode")
    ident = host_identity()
    capabilities = {
        "schemaVersion": "launcher.runner-capabilities.v1",
        **ident,
        "mode": mode,
        "headless": bool(ident["supported"]),
        "gui": False,
        "java": _probe_java(java),
        "display": False,
        "renderer": None,
        "status": "blocked",
        "blockers": [],
    }
    if not ident["supported"]:
        capabilities["blockers"].append(
            "Unsupported OS/architecture; target cannot execute"
        )
    if not capabilities["java"]["available"]:
        capabilities["blockers"].append(capabilities["java"]["reason"])
    if mode == "gui" and ident["supported"]:
        if ident["os"] == "linux":
            ok, why, renderer = _linux_gui()
            display = bool(os.environ.get("DISPLAY"))
        else:
            display, why = _native_display()
            ok = display
            renderer = None
            if ok:
                ok, why, renderer = _native_renderer()
        capabilities["display"] = display
        capabilities["gui"] = bool(ok)
        capabilities["renderer"] = renderer
        if not ok:
            capabilities["blockers"].append(why)
    if not capabilities["blockers"]:
        capabilities["status"] = "ready"
    return capabilities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("gui", "headless"), required=True)
    parser.add_argument("--java", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = evaluate(args.mode, args.java)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit("capability report must be written into a fresh job directory")
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": report["status"],
                "os": report["os"],
                "arch": report["arch"],
                "mode": args.mode,
                "blockers": report["blockers"],
            }
        )
    )
    return 0 if report["status"] == "ready" else 3


if __name__ == "__main__":
    sys.exit(main())
