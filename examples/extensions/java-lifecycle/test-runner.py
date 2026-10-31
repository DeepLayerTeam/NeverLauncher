#!/usr/bin/env python3
"""Real subprocess smoke E2E against Extensions 1.0 HTTP host wire format."""

import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent
STAGE = ROOT / "build" / "package"


class Handler(http.server.BaseHTTPRequestHandler):
    hello = 0
    heartbeats = 0
    expected_pid = 0

    def do_POST(self):
        assert self.client_address[0] in ("127.0.0.1", "::1")
        assert self.headers["Authorization"] == "Bearer test-secret"
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/hello":
            assert body["protocolVersion"] == "1.0"
            assert body["extensionApiVersion"] == "1.0"
            assert body["instanceId"] == "test-instance"
            assert body["extensionId"] == "org.example.java-lifecycle"
            assert body["pid"] == Handler.expected_pid
            Handler.hello += 1
            response = {
                "protocolVersion": "1.0",
                "extensionApiVersion": "1.0",
                "instanceId": "test-instance",
                "heartbeatTimeoutSeconds": 3,
            }
        elif self.path == "/v1/heartbeat":
            Handler.heartbeats += 1
            response = {"ok": True}
        else:
            self.send_error(404)
            return
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    assert (STAGE / "backend/bin/java-lifecycle").is_file(), "run build.sh first"
    host = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=host.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ)
    env.update(
        {
            "NEVERLAUNCHER_EXTENSION_HOST_URL": f"http://127.0.0.1:{host.server_port}",
            "NEVERLAUNCHER_EXTENSION_HOST_TOKEN": "test-secret",
            "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN": "callback-test-secret",
            "NEVERLAUNCHER_EXTENSION_ID": "org.example.java-lifecycle",
            "NEVERLAUNCHER_EXTENSION_VERSION": "0.1.0",
            "NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL": "1.0",
            "NEVERLAUNCHER_EXTENSION_API_VERSION": "1.0",
            "NEVERLAUNCHER_EXTENSION_INSTANCE_ID": "test-instance",
        }
    )
    proc = subprocess.Popen(
        ["backend/bin/java-lifecycle"],
        cwd=STAGE,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    Handler.expected_pid = proc.pid
    try:
        end = time.monotonic() + 12
        while time.monotonic() < end and Handler.heartbeats < 1 and proc.poll() is None:
            time.sleep(0.1)
        assert proc.poll() is None and Handler.hello == 1 and Handler.heartbeats >= 1, (
            "Java extension failed to negotiate and heartbeat"
        )
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=6)
        assert proc.returncode in (0, 128 + signal.SIGTERM), (
            f"Java extension exited with {proc.returncode}: {err}"
        )
        assert "Java extension started" in out and "Java extension stopped" in out, (
            f"lifecycle callbacks missing: {out}"
        )
        assert not err.strip(), f"unexpected Java extension stderr: {err}"
        print(
            "PASS: real Java subprocess hello, PID, heartbeat, SIGTERM lifecycle stop"
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=3)
        host.shutdown()
        host.server_close()
