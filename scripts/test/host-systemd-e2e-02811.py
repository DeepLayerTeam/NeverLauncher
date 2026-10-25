#!/usr/bin/env python3
"""Live Linux integration: actual CLI supervisor, systemd notify, signal, persisted player data."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def wait_for(predicate, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.04)
    raise AssertionError("timed out waiting for supervisor")


def main(binary):
    with tempfile.TemporaryDirectory(prefix="nl-host-systemd-02811-") as temp:
        root = Path(temp) / "minecraft"
        root.mkdir()
        (root / "paper.jar").write_bytes(b"fixture")
        fake_java = root / "java"
        fake_java.write_text('''#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'openjdk version "21.0.1"' >&2; exit 0; fi
printf 'started' > started.marker
read -r command
if [ "$command" = stop ]; then
  mkdir -p world/playerdata plugins/Demo
  printf '{"uuid":"test-uuid"}' > world/playerdata/test.dat
  printf '{"inventory":"retained"}' > plugins/Demo/user.json
  exit 0
fi
exit 91
''')
        fake_java.chmod(0o755)
        subprocess.run([binary, "server-bridge", "host", "configure", "--server-root", str(root),
                        "--platform", "paper", "--server-jar", str(root / "paper.jar"),
                        "--java", str(fake_java), "--restart-policy", "never",
                        "--stop-timeout-seconds", "5"], check=True, stdout=subprocess.DEVNULL)
        sock_path = str(Path(temp) / "notify.sock")
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify.bind(sock_path)
        notify.settimeout(6)
        env = os.environ.copy()
        env.update({"NOTIFY_SOCKET": sock_path, "WATCHDOG_USEC": "1500000"})
        proc = subprocess.Popen([binary, "server-bridge", "host", "run", "--server-root", str(root)],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            messages = []
            wait_for(lambda: (root / "started.marker").exists())
            wait_for(lambda: (root / ".neverlauncher/server-bridge/host/runtime.json").exists())
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline and not (any("READY=1" in s for s in messages) and any("WATCHDOG=1" in s for s in messages)):
                try:
                    messages.append(notify.recv(1024).decode())
                except socket.timeout:
                    break
            assert any("READY=1" in s for s in messages), messages
            assert any("WATCHDOG=1" in s for s in messages), messages
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=12)
            assert proc.returncode == 0, proc.stderr.read().decode()
            assert (root / "world/playerdata/test.dat").read_text() == '{"uuid":"test-uuid"}'
            assert (root / "plugins/Demo/user.json").read_text() == '{"inventory":"retained"}'
            runtime = json.loads((root / ".neverlauncher/server-bridge/host/runtime.json").read_text())
            assert runtime["status"] == "stopped", runtime
            assert runtime["stopMethod"] == "console-stop", runtime
            print("PASS: READY, WATCHDOG, SIGTERM -> Minecraft stdin stop, persisted playerdata/plugin data")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            notify.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    args = parser.parse_args()
    main(str(Path(args.cli).resolve()))
