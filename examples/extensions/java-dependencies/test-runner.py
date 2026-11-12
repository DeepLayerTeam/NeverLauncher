#!/usr/bin/env python3
"""Настоящая исполняемая интеграция JVM Host: зависимость применяется в Extension.start()."""
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
JAR = ROOT / "build/package/backend/java-dependencies.jar"
TOKEN = "java-libraries-integration-0482"


class Handler(http.server.BaseHTTPRequestHandler):
    callback = ""
    hellos = 0
    readies = 0
    beats = 0
    def log_message(self, *_):
        pass
    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.reply(401, {})
        elif self.path == "/v1/manifest":
            body = (ROOT / "launcher-extension.json").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.reply(404, {})
    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401, {})
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if self.path == "/v1/hello":
            assert data["extensionId"] == "org.example.java-dependencies"
            assert data["protocolVersion"] == "1.0"
            Handler.hellos += 1
            Handler.callback = data["callbackUrl"]
            return self.reply(200, {"protocolVersion": "1.0", "extensionApiVersion": "1.0", "instanceId": "host-0482", "heartbeatTimeoutSeconds": 2, "capabilities": []})
        if self.path == "/v1/ready":
            assert data == {"protocolVersion": "1.0", "instanceId": "host-0482"}
            Handler.readies += 1
            return self.reply(200, {"ready": True})
        if self.path == "/v1/heartbeat":
            Handler.beats += 1
            return self.reply(200, {"ok": True})
        return self.reply(404, {})


def main():
    assert JAR.is_file(), "сначала необходимо выполнить build.sh"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ,
        LAUNCHER_EXTENSION_HOST_URL=f"http://127.0.0.1:{server.server_port}",
        LAUNCHER_EXTENSION_HOST_TOKEN=TOKEN,
        LAUNCHER_EXTENSION_CALLBACK_TOKEN="callback-0482",
        LAUNCHER_EXTENSION_HOST_PROTOCOL="1.0",
        LAUNCHER_EXTENSION_API_VERSION="1.0",
        LAUNCHER_EXTENSION_INSTANCE_ID="host-0482",
        LAUNCHER_EXTENSION_ID="org.example.java-dependencies",
        LAUNCHER_EXTENSION_VERSION="0.1.0",
        LAUNCHER_EXTENSION_SCOPE="global",
        LAUNCHER_EXTENSION_SCOPE_ID="",
        LAUNCHER_EXTENSION_TARGET="backend")
    child = subprocess.Popen(["java", "-jar", str(JAR.resolve())], cwd=ROOT / "build/package", env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while Handler.readies < 1 and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert child.poll() is None and Handler.hellos == Handler.readies == 1, f"хост не перешёл в состояние готовности: {child.poll()}"
        # Реально выполненный Extension.start() обязан разрешить вложенный байткод.
        deadline = time.monotonic() + 5
        while Handler.beats == 0 and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert Handler.beats >= 1 and child.poll() is None, "не удалось получить сигнал работоспособности активного хоста"
        req = urllib.request.Request(Handler.callback + "/v1/rpc", headers={"Authorization": "Bearer callback-0482", "Content-Type": "application/json"},
            data=json.dumps({"protocolVersion": "1.0", "requestId": "p-0482", "method": "health", "params": {}, "deadlineMs": 1000}).encode())
        with urllib.request.urlopen(req, timeout=3) as reply:
            data = json.loads(reply.read())
        assert data["result"] == {"state": "RUNNING", "responsive": True}, data
        child.terminate()
        out, err = child.communicate(timeout=8)
        assert child.returncode in (0, 143, -15), (child.returncode, out, err)  # JVM после SIGTERM обычно завершается с кодом 143
        assert "Загружена настоящая JAR-зависимость расширения: dependency-loaded-0482" in out, (out, err)
        print("PASS: реальный запуск java -jar → закреплённая зависимость → Extension.start() → аутентифицированный хост → сигнал активности → RPC → остановка")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        server.shutdown()


if __name__ == "__main__":
    main()
