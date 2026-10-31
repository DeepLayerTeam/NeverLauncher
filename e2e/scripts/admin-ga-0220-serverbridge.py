#!/usr/bin/env python3
"""Live ServerBridge v3 operational acceptance against a disposable Minecraft server.

Requires a real online Bridge adapter and a freshly MFA-authenticated project
operator. Never falls back to fabricated ACKs or test-only HTTP endpoints.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"GA physical ServerBridge probe requires {name}")
    return value


def request(api: str, path: str, token: str, method="GET", payload=None, key=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if key:
        headers["Idempotency-Key"] = key
    req = urllib.request.Request(api + path, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            result = json.load(res)
            return result.get("data", result)
    except urllib.error.HTTPError as error:
        # Do not expose bearer tokens or a response containing other secrets.
        raise RuntimeError(f"{method} {path} returned HTTP {error.code}") from error


def await_ack(api: str, path: str, token: str, command_id: str, deadline: float):
    while time.monotonic() < deadline:
        cmd = request(api, path + "/" + urllib.parse.quote(command_id, safe=""), token)[
            "command"
        ]
        if cmd.get("id") != command_id:
            raise RuntimeError("ServerBridge ACK command identity mismatch")
        status = cmd.get("status", "")
        if status == "succeeded":
            if not cmd.get("completedAt"):
                raise RuntimeError("ServerBridge success lacks completedAt ACK")
            return cmd
        if status in ("failed", "unsupported", "expired", "indeterminate"):
            raise RuntimeError(f"ServerBridge command {command_id} ended {status}")
        if status not in ("pending", "leased", "delivered"):
            raise RuntimeError(f"Unknown ServerBridge command status: {status}")
        time.sleep(2)
    raise RuntimeError("Timed out waiting for real executed ServerBridge ACK")


def execute(api: str, server: str, token: str, kind: str, payload: dict[str, str]):
    path = (
        "/api/v1/server-bridge/servers/"
        + urllib.parse.quote(server, safe="")
        + "/control"
    )
    key = "ga0220-" + uuid.uuid4().hex
    body = {
        "type": kind,
        "payload": payload,
        "idempotencyKey": key,
        "expiresInSeconds": 180,
    }
    try:
        first = request(api, path, token, "POST", body, key)
    except (TimeoutError, urllib.error.URLError):
        # An unknown response must reuse the same payload and idempotency key.
        first = request(api, path, token, "POST", body, key)
    command = first["command"]
    command_id = command.get("id")
    if not command_id or command.get("serverId") != server:
        raise RuntimeError("ServerBridge returned an invalid command or server binding")
    duplicate = request(api, path, token, "POST", body, key)
    if (
        duplicate["command"].get("id") != command_id
        or duplicate.get("idempotentReplay") is not True
    ):
        raise RuntimeError(
            "Duplicate ServerBridge command request created another side effect"
        )
    await_ack(api, path, token, command_id, time.monotonic() + 185)
    print(f"[admin-ga-0220] {kind} executed with Bridge ACK, command={command_id}")


def main() -> None:
    api = required("E2E_API_URL").rstrip("/")
    token = required("E2E_OPERATOR_TOKEN")
    project = required("E2E_PROJECT_ID")
    server = required("E2E_SERVERBRIDGE_NODE_ID")
    if required("E2E_DESTRUCTIVE_STAGING_ACK") != "I_CONFIRM_DEDICATED_SERVER":
        raise RuntimeError(
            "Refusing drain: not explicitly acknowledged as disposable Minecraft staging server"
        )
    overview = request(
        api,
        "/api/v1/server-bridge/projects/"
        + urllib.parse.quote(project, safe="")
        + "/overview",
        token,
    )
    matches = [n for n in overview.get("nodes", []) if n.get("id") == server]
    if len(matches) != 1:
        raise RuntimeError("Bridge node not found in the operator project")
    node = matches[0]
    if (
        node.get("projectId") != project
        or node.get("status") != "active"
        or node.get("fresh") is not True
        or node.get("protocolVersion") != 3
    ):
        raise RuntimeError(
            "Dedicated ServerBridge v3 is not active/fresh in the selected project"
        )
    runtime = str(node.get("runtimeId", ""))
    if len(runtime) != 64 or not all(c in "0123456789abcdefABCDEF" for c in runtime):
        raise RuntimeError("Missing real ServerBridge runtime identity")
    execute(api, server, token, "server.save", {})
    drain_attempted = False
    try:
        drain_attempted = True
        execute(
            api,
            server,
            token,
            "server.drain",
            {
                "enabled": "true",
                "reason": "Launcher GA 0.22.0 disposable staging probe",
            },
        )
    finally:
        if drain_attempted:
            # Do not leave a test server in maintenance/drain after the probe.
            execute(
                api,
                server,
                token,
                "server.drain",
                {"enabled": "false", "reason": "Launcher GA 0.22.0 probe cleanup"},
            )
    print("[admin-ga-0220] real Bridge save/drain/undrain ACK and replay PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(
            f"[admin-ga-0220] live ServerBridge certification FAILED: {exc}"
        )
