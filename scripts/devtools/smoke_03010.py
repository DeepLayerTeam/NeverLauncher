#!/usr/bin/env python3
"""Real CLI smoke: javac -> JAR analysis/transform -> JVM process -> HTTP auth fixtures."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile


def command(*args):
    return subprocess.run(
        args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    ).stdout


def request(base, endpoint, payload=None, control=None):
    headers = {}
    if control:
        headers["Authorization"] = "Bearer " + control
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    else:
        data = None
    method = "POST" if payload is not None else "GET"
    req = urllib.request.Request(
        base + endpoint, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as err:
        return err.code, json.load(err)


def main(cli):
    with tempfile.TemporaryDirectory(prefix="never-devtools-cli-") as tmp:
        root = Path(tmp)
        src = root / "Fixture.java"
        src.write_text(
            """public class Fixture {
  public static void main(String[] args) {
    if (System.getenv("LAUNCHER_TOKEN") != null) throw new IllegalStateException("secret leaked");
    System.out.println("fixture:" + args[0]);
  }
}""",
            encoding="utf-8",
        )
        command("javac", "-g", "--release", "17", str(src))
        jar = root / "test.jar"
        with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\nMain-Class: Fixture\r\n\r\n",
            )
            z.write(root / "Fixture.class", "Fixture.class")
        analyzed = json.loads(
            command(cli, "devtools", "jar", "analyze", "--input", str(jar))
        )
        assert analyzed["classes"] == 1 and analyzed["signed"] is False
        transformed = root / "output.jar"
        converted = json.loads(
            command(
                cli,
                "devtools",
                "jar",
                "strip-debug",
                "--input",
                str(jar),
                "--output",
                str(transformed),
            )
        )
        assert (
            converted["modifiedClasses"] == 1
            and converted["removedDebugAttributes"] >= 2
        )
        assert "fixture:ok" in command("java", "-jar", str(transformed), "ok")
        cmd_env = os.environ.copy()
        cmd_env["LAUNCHER_TOKEN"] = "production-secret-must-not-leak"
        run = subprocess.run(
            [
                cli,
                "devtools",
                "component",
                "test",
                "--jar",
                str(transformed),
                "--isolation",
                "process",
                "--ack-unconfined",
                "--",
                "ok",
            ],
            capture_output=True,
            text=True,
            env=cmd_env,
            check=True,
        )
        result = json.loads(run.stdout)
        assert result["exitCode"] == 0 and "fixture:ok" in result["stdout"]
        assert "production-secret" not in result["stdout"]
        env = os.environ.copy()
        env["LAUNCHER_DEVTOOLS_TEST_MODE"] = "1"
        p = subprocess.Popen(
            [cli, "devtools", "auth", "serve", "--ack-test-only", "--duration", "30s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            lines = []
            for _ in range(20):
                line = p.stdout.readline()
                if not line:
                    raise RuntimeError(
                        "test identity server exited before startup: " + p.stderr.read()
                    )
                lines.append(line)
                try:
                    startup = json.loads("".join(lines))
                    break
                except json.JSONDecodeError:
                    continue
            else:
                raise RuntimeError("invalid fixture startup JSON")
            base = startup["baseUrl"]
            status, rejected = request(
                base,
                "/fixture/v1/login",
                {"username": startup["username"], "password": "wrong"},
            )
            assert status == 401, rejected
            status, logged = request(
                base,
                "/fixture/v1/login",
                {"username": startup["username"], "password": startup["password"]},
            )
            assert status == 200 and logged["accessToken"].startswith("nltest.v1."), (
                logged
            )
            token = logged["accessToken"]
            status, state = request(base, "/fixture/v1/introspect", {"token": token})
            assert status == 200 and state["active"] is True
            status, state = request(
                base, "/fixture/v1/revoke", {"token": token}, startup["controlToken"]
            )
            assert status == 200 and state["revoked"]
            status, state = request(base, "/fixture/v1/introspect", {"token": token})
            assert status == 200 and state["active"] is False
            status, state = request(
                base, "/fixture/v1/events", control=startup["controlToken"]
            )
            assert status == 200 and len(state["events"]) >= 4
        finally:
            p.terminate()
            p.wait(timeout=5)
    print(
        "PASS: CLI jar analyze/strip-debug, actual JVM, process env, test auth, login, revoke and events"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    main(os.path.abspath(parser.parse_args().cli))
