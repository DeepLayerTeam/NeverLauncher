#!/usr/bin/env python3
"""0.35.1 live API journey against a disposable, running Launcher Backend.

Calls real authentication and CRUD handlers, no mocks. Requires explicit opt-in
because it CREATES a project. It cannot certify Minecraft, Desktop or stable GA.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, quote
from urllib.request import (
    Request,
    build_opener,
    HTTPHandler,
    HTTPRedirectHandler,
    ProxyHandler,
)
from urllib.error import HTTPError, URLError
from uuid import uuid4

from ux_0351 import atomic_report, AuditError, require, ROOT

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from certification_run import identity

MAX_BODY = 2 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("redirect refused to protect credentials")


class API:
    def __init__(self, origin):
        self.origin = origin
        self.opener = build_opener(ProxyHandler({}), NoRedirect, HTTPHandler())

    def request(self, method, path, *, payload=None, token=None, expected=(200,)):
        require(path.startswith("/api/v1/") or path == "/health", "invalid API route")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        raw = None
        if payload is not None:
            raw = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = Request(self.origin + path, data=raw, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=10) as resp:
                status = resp.status
                data = resp.read(MAX_BODY + 1)
        except HTTPError as e:
            status = e.code
            data = e.read(MAX_BODY + 1)
        require(len(data) <= MAX_BODY, "oversized Backend response")
        require(
            status in expected, f"{method} {path}: expected {expected}, got {status}"
        )
        if not data:
            return status, {}
        try:
            return status, json.loads(data)
        except ValueError:
            raise AuditError(f"{method} {path}: malformed JSON") from None


def run(base, email, password):
    api = API(base)
    checks = []

    def record(key):
        checks.append(key)

    _, health = api.request("GET", "/health")
    require(
        (ROOT / "VERSION").read_text().strip() in json.dumps(health),
        "wrong backend version",
    )
    record("real-backend-health-0351")

    api.request(
        "POST", "/api/v1/admin/projects", payload={"id": "denied"}, expected=(401, 403)
    )
    record("unauthenticated-admin-mutation-denied")

    _, logged = api.request(
        "POST", "/api/v1/admin/login", payload={"email": email, "password": password}
    )
    token = logged.get("token")
    require(isinstance(token, str) and len(token) >= 16, "no real admin token")
    _, player = api.request(
        "POST",
        "/api/v1/auth/login",
        payload={
            "email": email,
            "password": password,
            "deviceId": "acceptance-0351-" + uuid4().hex[:12],
        },
    )
    access = player.get("data", {}).get("tokens", {}).get("accessToken")
    refresh = player.get("data", {}).get("tokens", {}).get("refreshToken")
    require(
        isinstance(access, str) and isinstance(refresh, str), "no real player session"
    )
    record("real-admin-and-player-sign-in")

    api.request("GET", "/api/v1/auth/accounts", expected=(401, 403))
    api.request("GET", "/api/v1/auth/accounts", token=access)
    record("player-accounts-protected")

    project = "acceptance0351-" + uuid4().hex[:14]
    path = "/api/v1/admin/projects/" + quote(project, safe="")
    _, created = api.request(
        "POST",
        "/api/v1/admin/projects",
        token=token,
        expected=(201,),
        payload={
            "id": project,
            "name": "0351 acceptance project",
            "defaultChannel": "stable",
        },
    )
    require(
        created.get("data", {}).get("project", {}).get("id") == project,
        "project not created",
    )
    api.request(
        "PATCH",
        path,
        token=token,
        payload={"description": "real journey acceptance 0351"},
    )
    _, public = api.request("GET", "/api/v1/projects/" + quote(project, safe=""))
    require(
        public.get("id") == project
        and public.get("description") == "real journey acceptance 0351",
        "player-visible project readback mismatch",
    )
    record("owner-create-update-player-read-project")

    _, profile = api.request(
        "POST",
        path + "/profiles",
        token=token,
        expected=(201,),
        payload={
            "id": "test-vanilla",
            "name": "Vanilla acceptance",
            "loader": "vanilla",
        },
    )
    require(
        profile.get("data", {}).get("profile", {}).get("id") == "test-vanilla",
        "profile create unsuccessful",
    )
    _, profiles = api.request("GET", "/api/v1/projects/" + project + "/profiles")
    require(
        any(x.get("id") == "test-vanilla" for x in profiles.get("items", [])),
        "player cannot discover profile",
    )
    record("owner-create-player-discover-profile")

    _, channel = api.request(
        "POST",
        path + "/channels",
        token=token,
        expected=(201,),
        payload={"id": "acceptance", "name": "Acceptance", "protected": True},
    )
    require(
        channel.get("data", {}).get("channel", {}).get("id") == "acceptance",
        "channel not created",
    )
    _, channels = api.request("GET", "/api/v1/projects/" + project + "/channels")
    require(
        any(x.get("id") == "acceptance" for x in channels.get("items", [])),
        "owner channel not visible to player",
    )
    record("owner-create-player-discover-channel")

    api.request(
        "GET",
        f"/api/v1/projects/{project}/profiles/test-vanilla/manifest?channel=acceptance",
        expected=(404,),
    )
    api.request(
        "GET", f"/api/v1/files/{project}/ws-fake/workspace.txt", expected=(404,)
    )
    record("unpublished-or-workspace-content-not-served")

    api.request("GET", "/api/v1/admin/audit", token=token)
    api.request("GET", "/api/v1/admin/audit", expected=(401, 403))
    record("auditing-requires-operator-authorization")

    _, rotated = api.request(
        "POST", "/api/v1/auth/refresh", payload={"refreshToken": refresh}
    )
    new_access = rotated.get("data", {}).get("tokens", {}).get("accessToken")
    new_refresh = rotated.get("data", {}).get("tokens", {}).get("refreshToken")
    require(
        isinstance(new_access, str)
        and isinstance(new_refresh, str)
        and new_refresh != refresh,
        "refresh tokens not rotated",
    )
    api.request("POST", "/api/v1/auth/logout", token=new_access)
    api.request("GET", "/api/v1/auth/accounts", token=new_access, expected=(401, 403))
    record("refresh-rotation-and-logout-revocation")
    return {
        "schemaVersion": "launcher.owner-player-http-acceptance.v1",
        "version": (ROOT / "VERSION").read_text().strip(),
        "status": "local-loopback-passed",
        "checks": checks,
        "scenarioIds": ["G01", "G07", "G22", "G32", "G34"],
        "projectId": project,
        "realBackend": True,
        "realMinecraftCertification": False,
        "nativeDesktopVerified": False,
        "stablePublicationVerified": False,
        "certificationRun": identity(
            (ROOT / "VERSION").read_text().strip(),
            os.environ.get("GITHUB_SHA", ""),
            root=ROOT,
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend", required=True)
    p.add_argument(
        "--isolated-test-instance",
        action="store_true",
        help="acknowledge this will mutate a disposable local Backend",
    )
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        url = urlsplit(args.backend)
        require(
            args.isolated_test_instance,
            "requires explicit isolated test instance acknowledgment",
        )
        require(
            url.scheme == "http"
            and url.hostname in ("localhost", "127.0.0.1", "::1")
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment
            and not url.path.rstrip("/"),
            "only a local HTTP test Backend is allowed",
        )
        email = os.environ.get("LAUNCHER_TEST_ADMIN_EMAIL", "")
        password = os.environ.get("LAUNCHER_TEST_ADMIN_PASSWORD", "")
        require(
            bool(email) and bool(password),
            "test credentials must be supplied via environment",
        )
        result = run(args.backend.rstrip("/"), email, password)
        atomic_report(args.output, result)
        print(
            "Owner/player live Backend acceptance: PASS; Minecraft and native Desktop: NOT VERIFIED"
        )
        return 0
    except (AuditError, OSError, ValueError, URLError, KeyError, TypeError) as e:
        print("Owner/player HTTP acceptance BLOCKED: " + str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
