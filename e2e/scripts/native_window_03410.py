"""Native Windows/macOS GUI observations. Linux/X11 remains in staged_readiness.

Windows requires an unlocked interactive desktop. macOS needs Screen Recording
and Accessibility grants for the dedicated validation worker user. Never use a
window title alone: verify its PID descends from the launched Runtime and
its executable is the selected Java binary.
"""

import ctypes
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time


class GUIUnavailable(RuntimeError):
    """The host GUI/input infrastructure is unavailable, not Minecraft failure."""


def descendants_java(pid, ancestor, java):
    import psutil

    try:
        root = psutil.Process(ancestor)
        proc = psutil.Process(pid)
        parents = {p.pid for p in proc.parents()}
        if proc.pid != root.pid and root.pid not in parents:
            return False
        executable = proc.exe()
        if java and not os.path.samefile(executable, java):
            return False
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except (psutil.Error, OSError, ValueError):
        return False


def _windows_windows():
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [cb_type, wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.EnumWindows.restype = wintypes.BOOL
    user.GetWindowTextLengthW.restype = ctypes.c_int
    user.GetWindowTextW.restype = ctypes.c_int
    found = []

    @cb_type
    def cb(hwnd, _):
        if not user.IsWindowVisible(hwnd):
            return True
        length = user.GetWindowTextLengthW(hwnd)
        if not 0 < length <= 256:
            return True
        title = ctypes.create_unicode_buffer(length + 1)
        user.GetWindowTextW(hwnd, title, length + 1)
        if re.search(r"(?i)minecraft", title.value):
            pid = wintypes.DWORD()
            user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            found.append((int(hwnd), int(pid.value)))
        return True

    if not user.EnumWindows(cb, 0):
        raise OSError("EnumWindows failed")
    return found


def _mac_windows():
    import Quartz

    opts = (
        Quartz.kCGWindowListOptionOnScreenOnly
        | Quartz.kCGWindowListExcludeDesktopElements
    )
    found = []
    for w in Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID):
        if int(w.get("kCGWindowLayer", -1)) != 0:
            continue
        title = (
            str(w.get("kCGWindowName", "")) + " " + str(w.get("kCGWindowOwnerName", ""))
        )
        if re.search(r"(?i)minecraft", title):
            found.append((int(w["kCGWindowNumber"]), int(w["kCGWindowOwnerPID"])))
    return found


def find_window(root_pid, java=None):
    if sys.platform == "win32":
        windows = _windows_windows()
    elif sys.platform == "darwin":
        windows = _mac_windows()
    else:
        raise RuntimeError("native window observer only supports Windows/macOS")
    for wid, pid in windows:
        if descendants_java(pid, root_pid, java):
            return wid, pid
    return None


def _native_bounds(wid):
    if sys.platform == "win32":
        from ctypes import wintypes

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", wintypes.LONG),
                ("top", wintypes.LONG),
                ("right", wintypes.LONG),
                ("bottom", wintypes.LONG),
            ]

        rect = RECT()
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
        user.GetWindowRect.restype = wintypes.BOOL
        if not user.GetWindowRect(wintypes.HWND(wid), ctypes.byref(rect)):
            raise RuntimeError("window rectangle unavailable")
        return (rect.left, rect.top, rect.right, rect.bottom)
    import Quartz

    for w in Quartz.CGWindowListCopyWindowInfo(
        Quartz.kCGWindowListOptionIncludingWindow, wid
    ):
        if int(w["kCGWindowNumber"]) == wid:
            bound = w["kCGWindowBounds"]
            x = int(bound["X"])
            y = int(bound["Y"])
            return (x, y, x + int(bound["Width"]), y + int(bound["Height"]))
    raise RuntimeError("Minecraft window is no longer onscreen")


def _foreground(wid):
    if sys.platform == "win32":
        from ctypes import wintypes

        user = ctypes.WinDLL("user32", use_last_error=True)
        user.GetForegroundWindow.restype = wintypes.HWND
        return int(user.GetForegroundWindow() or 0) == int(wid)
    import Quartz

    windows = Quartz.CGWindowListCopyWindowInfo(
        Quartz.kCGWindowListOptionOnScreenOnly
        | Quartz.kCGWindowListExcludeDesktopElements,
        Quartz.kCGNullWindowID,
    )
    top = next((w for w in windows if int(w.get("kCGWindowLayer", -1)) == 0), None)
    return top is not None and int(top["kCGWindowNumber"]) == wid


def _capture(wid, destination):
    from PIL import ImageGrab, ImageStat

    if not _foreground(wid):
        raise GUIUnavailable("Minecraft window not foreground; no safe GUI observation")
    bbox = _native_bounds(wid)
    if bbox[2] - bbox[0] < 640 or bbox[3] - bbox[1] < 400:
        raise RuntimeError("Minecraft window dimensions too small")
    image = ImageGrab.grab(bbox=bbox, all_screens=True)
    if image.width < 640 or image.height < 400:
        raise RuntimeError("captured window dimensions too small")
    # Entropy is measured on the actual rendered RGB image, not on the title.
    import math

    hist = image.convert("L").histogram()
    total = sum(hist)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in hist if count
    )
    if entropy < 0.5:
        raise RuntimeError("window does not contain sufficiently rendered pixels")
    image.save(destination, format="PNG")
    if destination.stat().st_size < 2048:
        raise RuntimeError("insufficient rendered frame bytes")
    return image.width, image.height, entropy


def capture_menu(wid, destination, menu):
    path = Path(destination)
    path.unlink(missing_ok=True)
    try:
        width, height, entropy = _capture(wid, path)
        text = ""
        for psm in (4, 11):
            cp = subprocess.run(
                ["tesseract", str(path), "stdout", "--psm", str(psm), "-l", "eng"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=12,
                check=False,
            )
            if cp.returncode:
                raise RuntimeError("tesseract OCR unavailable")
            text = cp.stdout.decode("utf-8", "replace")
            controls = sorted(k for k, rx in menu.items() if rx.search(text))
            if len(controls) >= 2:
                return {
                    "window": wid,
                    "width": width,
                    "height": height,
                    "entropy": round(entropy, 4),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "menuControls": controls,
                }
        path.unlink(missing_ok=True)
        return None
    except Exception:
        path.unlink(missing_ok=True)
        raise


def screenshot_world(wid, path):
    path = Path(path)
    path.unlink(missing_ok=True)
    _capture(wid, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def move_forward(wid, seconds=2):
    # Do not send keys to a background window or a process we did not identify.
    if not _foreground(wid):
        raise GUIUnavailable("Minecraft not focused; refusing gameplay input")
    if sys.platform == "darwin":
        import Quartz

        if not Quartz.AXIsProcessTrusted():
            raise GUIUnavailable("macOS Accessibility permission absent for game input")
    from pynput.keyboard import Controller, KeyCode

    keyboard = Controller()
    key = KeyCode.from_char("w")
    keyboard.press(key)
    try:
        time.sleep(seconds)
    finally:
        keyboard.release(key)
