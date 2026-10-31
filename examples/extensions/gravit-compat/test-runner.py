#!/usr/bin/env python3
"""Run a ported Gravit-shaped module in two real JVM processes, with authenticated host callbacks."""

import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile
import tempfile

ROOT = Path(__file__).resolve().parent
STAGE = ROOT / "build" / "package"
TOKEN = "ported-gravit-backend-token"
CALLBACK = "ported-gravit-callback-token"


class Handler(http.server.BaseHTTPRequestHandler):
    lock = threading.Lock()
    state = {}
    callback = None
    ready = 0
    hello = 0
    subscriptions = []

    def log_message(self, *args):
        pass

    def answer(self, code, value):
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def do_GET(self):
        if not self.authorized():
            self.answer(401, {"error": "unauthorized"})
            return
        if self.path != "/v1/manifest":
            self.answer(404, {})
            return
        self.answer(200, json.loads((ROOT / "neverlauncher-extension.json").read_text()))

    def do_POST(self):
        if not self.authorized():
            self.answer(401, {"error": "unauthorized"})
            return
        data = json.loads(
            self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}"
        )
        code = 200
        if self.path == "/v1/hello":
            assert (
                data["extensionId"] == "org.example.gravit-port"
                and data["protocolVersion"] == "1.0"
            )
            Handler.hello += 1
            if data.get("callbackUrl"):
                Handler.callback = data["callbackUrl"]
            result = {
                "protocolVersion": "1.0",
                "extensionApiVersion": "1.0",
                "instanceId": "compat-instance",
                "heartbeatTimeoutSeconds": 6,
                "capabilities": ["runtime.storage.get", "runtime.storage.put"],
                "eventProtocolVersion": "1.0",
                "events": ["release.published"],
            }
        elif self.path == "/v1/ready":
            Handler.ready += 1
            result = {"ready": True}
        elif self.path == "/v1/heartbeat":
            result = {"ok": True}
        elif self.path == "/v1/events/subscriptions":
            assert data == {"eventType": "release.published", "mode": "async"}
            Handler.subscriptions.append(data)
            code = 201
            result = {"id": 30}
        elif self.path == "/v1/capabilities/runtime.storage.put":
            with Handler.lock:
                Handler.state[data["key"]] = data["value"]
            result = {"saved": True}
        elif self.path == "/v1/capabilities/runtime.storage.get":
            with Handler.lock:
                value = Handler.state.get(data["key"])
            if value is None:
                code, result = 404, {"error": "missing"}
            else:
                result = {"value": value}
        else:
            code, result = 404, {"error": "not found"}
        self.answer(code, result)

    def do_DELETE(self):
        if not self.authorized():
            self.answer(401, {})
            return
        assert self.path == "/v1/events/subscriptions/30"
        self.send_response(204)
        self.end_headers()


def env(server, target):
    result = os.environ.copy()
    result.update(
        NEVERLAUNCHER_EXTENSION_HOST_URL=f"http://127.0.0.1:{server.server_port}",
        NEVERLAUNCHER_EXTENSION_HOST_TOKEN=TOKEN,
        NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN=CALLBACK,
        NEVERLAUNCHER_EXTENSION_ID="org.example.gravit-port",
        NEVERLAUNCHER_EXTENSION_VERSION="0.1.0",
        NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL="1.0",
        NEVERLAUNCHER_EXTENSION_API_VERSION="1.0",
        NEVERLAUNCHER_EXTENSION_INSTANCE_ID="compat-instance",
        NEVERLAUNCHER_EXTENSION_TARGET=target,
    )
    return result


def callback(url, method, payload, token=CALLBACK):
    data = {
        "protocolVersion": "1.0",
        "requestId": "compat-" + str(time.monotonic_ns()),
        "method": method,
        "params": payload,
        "deadlineMs": 1200,
    }
    request = urllib.request.Request(
        url + "/v1/rpc",
        data=json.dumps(data).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as reply:
            return reply.status, json.load(reply)
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


if __name__ == "__main__":
    jar = STAGE / "backend" / "gravit-port.jar"
    assert jar.exists(), "run build.sh first"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    backend = subprocess.Popen(
        ["java", "-jar", str(jar.resolve())],
        cwd=STAGE,
        env=env(server, "backend"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        until = time.monotonic() + 12
        while (
            time.monotonic() < until and Handler.ready != 1 and backend.poll() is None
        ):
            time.sleep(0.04)
        assert Handler.ready == 1 and backend.poll() is None, (
            backend.poll(),
            backend.stderr.read() if backend.poll() is not None else "not ready",
        )
        assert Handler.subscriptions == [
            {"eventType": "release.published", "mode": "async"}
        ]
        code, response = callback(Handler.callback, "health", {})
        assert code == 200 and response["result"]["state"] == "RUNNING", (
            code,
            response,
        )
        event = {
            "protocolVersion": "1.0",
            "subscription": {"eventType": "release.published", "mode": "async"},
            "event": {
                "type": "release.published",
                "id": "event-37",
                "projectId": "project-1",
                "idempotencyKey": "unique-37",
                "payload": {"release": "5.7.13"},
            },
        }
        code, response = callback(
            Handler.callback, "event.deliver", {"envelope": event}
        )
        assert code == 200 and response["result"]["accepted"], (code, response)
        expected = {
            "eventId": "event-37",
            "projectId": "project-1",
            "payload": {"release": "5.7.13"},
        }
        with Handler.lock:
            assert Handler.state.get("last-release") == expected, Handler.state
        code, response = callback(
            Handler.callback,
            "command.invoke",
            {"command": "status", "payload": {"args": []}},
        )
        assert code == 200 and response["result"]["value"] == {
            "latestRelease": expected
        }, (code, response)
        code, _ = callback(
            Handler.callback,
            "command.invoke",
            {"command": "undeclared", "payload": {"args": []}},
        )
        assert code == 422
        code, _ = callback(Handler.callback, "health", {}, token="wrong")
        assert code == 401
        cli = subprocess.run(
            ["java", "-jar", str(jar.resolve()), "status"],
            cwd=STAGE,
            env=env(server, "cli"),
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert cli.returncode == 0, (cli.returncode, cli.stderr, cli.stdout)
        assert json.loads(cli.stdout.strip()) == {"latestRelease": expected}, cli.stdout
        assert Handler.hello == 2 and Handler.ready == 1
        # Negative-path JVM startup: no ready notification is sent for a class with
        # unresolved Gravit dependencies or an unmapped event subscription.
        with tempfile.TemporaryDirectory() as folder:
            for class_name in ("UnportedModule", "UnsupportedEventModule"):
                broken = Path(folder) / (class_name + ".jar")
                with (
                    zipfile.ZipFile(jar) as original,
                    zipfile.ZipFile(broken, "w") as copy,
                ):
                    for item in original.infolist():
                        contents = original.read(item.filename)
                        if item.filename == "META-INF/MANIFEST.MF":
                            contents = contents.replace(
                                b"ru.example.gravit.PortedModule",
                                ("ru.example.gravit." + class_name).encode(),
                            )
                        copy.writestr(item, contents)
                count = Handler.ready
                failed = subprocess.run(
                    ["java", "-jar", str(broken.resolve())],
                    cwd=STAGE,
                    env=env(server, "backend"),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                assert failed.returncode != 0 and Handler.ready == count, (
                    class_name,
                    failed.stderr,
                )
        print(
            "PASS: signed-package-compatible Gravit port JAR; backend hello/ready, real event subscription, state write, RPC/CLI command, authenticated callbacks"
        )
    finally:
        if backend.poll() is None:
            backend.send_signal(signal.SIGTERM)
        try:
            backend.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            backend.kill()
            backend.communicate()
        server.shutdown()
        server.server_close()
