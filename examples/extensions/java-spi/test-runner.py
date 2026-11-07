#!/usr/bin/env python3
"""Настоящий JVM Host, вложенная зависимость, выбор и смена провайдера через брокер и CLI."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
JAR = ROOT / "build/package/backend/java-spi.jar"
TOKEN = "java-spi-host-0483"


class Handler(http.server.BaseHTTPRequestHandler):
    callback = ""
    hellos = 0
    readies = 0
    beats = 0
    selected = "formal"

    def log_message(self, *_):
        pass

    def reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401, {})
        if self.path != "/v1/manifest":
            return self.reply(404, {})
        payload = (ROOT / "launcher-extension.json").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401, {})
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if self.path == "/v1/hello":
            assert data["protocolVersion"] == "1.0"
            assert data["extensionId"] == "org.example.java-spi"
            Handler.hellos += 1
            Handler.callback = data.get("callbackUrl", "")
            return self.reply(200, {"protocolVersion": "1.0", "extensionApiVersion": "1.0", "instanceId": "host-0483", "heartbeatTimeoutSeconds": 2, "capabilities": ["runtime.config.get"]})
        if self.path == "/v1/capabilities/runtime.config.get":
            assert data == {"key": "spi.active"}, data
            return self.reply(200, {"value": Handler.selected})
        if self.path == "/v1/ready":
            assert data == {"protocolVersion": "1.0", "instanceId": "host-0483"}
            Handler.readies += 1
            return self.reply(200, {"ready": True})
        if self.path == "/v1/heartbeat":
            Handler.beats += 1
            return self.reply(200, {"ok": True})
        return self.reply(404, {})


def rpc(command):
    request = {"protocolVersion": "1.0", "requestId": "spi-0483", "method": "command.invoke", "deadlineMs": 1600,
               "params": {"command": "greet", "payload": command}}
    req = urllib.request.Request(Handler.callback + "/v1/rpc", data=json.dumps(request).encode(),
                                 headers={"Authorization": "Bearer callback-0483", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def env(port, target="backend"):
    return dict(os.environ, LAUNCHER_EXTENSION_HOST_URL=f"http://127.0.0.1:{port}",
                LAUNCHER_EXTENSION_HOST_TOKEN=TOKEN, LAUNCHER_EXTENSION_CALLBACK_TOKEN="callback-0483",
                LAUNCHER_EXTENSION_HOST_PROTOCOL="1.0", LAUNCHER_EXTENSION_API_VERSION="1.0",
                LAUNCHER_EXTENSION_INSTANCE_ID="host-0483", LAUNCHER_EXTENSION_ID="org.example.java-spi",
                LAUNCHER_EXTENSION_VERSION="0.1.0", LAUNCHER_EXTENSION_TARGET=target,
                LAUNCHER_EXTENSION_SCOPE="global", LAUNCHER_EXTENSION_SCOPE_ID="")


def main():
    assert JAR.is_file(), "Сначала запустите build.sh"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    instance_env = env(server.server_port)
    child = subprocess.Popen(["java", "-jar", str(JAR.resolve())], cwd=ROOT / "build/package",
                             env=instance_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        until = time.monotonic() + 10
        while Handler.readies == 0 and child.poll() is None and time.monotonic() < until:
            time.sleep(0.03)
        assert child.poll() is None and Handler.readies == 1 and Handler.hellos == 1, (child.poll(), child.communicate() if child.poll() is not None else "")
        status, response = rpc({"name": "Ada"})
        assert status == 200 and response["result"]["value"] == {"active": "formal", "message": "Добрый день, Ada (locked-spi-lib-0483)"}, (status, response)
        status, response = rpc({"operation": "select", "provider": "friendly", "name": "Lin"})
        assert status == 200 and response["result"]["value"] == {"active": "friendly", "message": "Привет, Lin (locked-spi-lib-0483)"}, (status, response)
        status, response = rpc({"operation": "select", "provider": "missing"})
        assert status == 422, (status, response)
        status, response = rpc({"name": "Ada"})
        assert status == 200 and response["result"]["value"]["active"] == "friendly", (status, response)
        until = time.monotonic() + 5
        while Handler.beats == 0 and time.monotonic() < until:
            time.sleep(0.04)
        assert Handler.beats > 0, "Хост не отправил сигнал активности"
        child.terminate()
        out, err = child.communicate(timeout=8)
        assert child.returncode in (0, 143, -15), (child.returncode, out, err)
        assert "SPI_EXTENSION_STOP" in out and "SPI_PROVIDER_STOP:friendly" in out, (out, err)

        Handler.selected = "formal"
        cli = subprocess.run(["java", "-jar", str((ROOT / "build/package/cli/java-spi.jar").resolve()), "greet"],
                             cwd=ROOT / "build/package", env=env(server.server_port, "cli"), text=True, capture_output=True, timeout=12)
        assert cli.returncode == 0, (cli.stdout, cli.stderr)
        assert '"active":"formal"' in cli.stdout and "Добрый день, World (locked-spi-lib-0483)" in cli.stdout, cli.stdout

        Handler.selected = "incompatible"
        failed = subprocess.run(["java", "-jar", str(JAR.resolve())], cwd=ROOT / "build/package", env=instance_env,
                                text=True, capture_output=True, timeout=10)
        assert failed.returncode != 0 and Handler.readies == 1, (failed.returncode, failed.stdout, failed.stderr)
        assert "unregistered provider" in failed.stderr, failed.stderr
        print("PASS: Java SPI со вложенными библиотеками → выбор конфигурации брокера → готовность JVM → аутентифицированный RPC → переключение провайдера → сигнал активности → CLI → безопасный отказ при несовместимости")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        server.shutdown()


if __name__ == "__main__":
    main()
