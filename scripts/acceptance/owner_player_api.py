#!/usr/bin/env python3
"""Проверка пользовательского сценария через живой API 0.35.1 на запущенном временном Backend Launcher.

Вызываются настоящие обработчики аутентификации и CRUD, без имитаций. Требуется явное согласие,
поскольку создаётся проект. Нельзя использовать как сертификат Minecraft, Desktop или стабильного
GA.
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

from ux import atomic_report, AuditError, require, ROOT

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from certification_run import identity

MAX_BODY = 2 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError("Перенаправление отклонено для защиты учётных данных")


class API:
    def __init__(self, origin):
        self.origin = origin
        self.opener = build_opener(ProxyHandler({}), NoRedirect, HTTPHandler())

    def request(self, method, path, *, payload=None, token=None, expected=(200,)):
        require(path.startswith("/api/v1/") or path == "/health", "некорректный маршрут API")
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
        require(len(data) <= MAX_BODY, "Ответ Backend превышает допустимый размер")
        require(
            status in expected, f"{method} {path}: ожидалось {expected}, получено {status}"
        )
        if not data:
            return status, {}
        try:
            return status, json.loads(data)
        except ValueError:
            raise AuditError(f"{method} {path}: некорректный JSON") from None


def run(base, email, password):
    api = API(base)
    checks = []

    def record(key):
        checks.append(key)

    _, health = api.request("GET", "/health")
    require(
        (ROOT / "VERSION").read_text().strip() in json.dumps(health),
        "Неверная версия Backend",
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
    require(isinstance(token, str) and len(token) >= 16, "Нет действительного токена администратора")
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
        isinstance(access, str) and isinstance(refresh, str), "Нет действительной сессии игрока"
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
        "Проект не был создан",
    )
    api.request(
        "PATCH",
        path,
        token=token,
        payload={"description": "приёмочная проверка реального пользовательского сценария 0351"},
    )
    _, public = api.request("GET", "/api/v1/projects/" + quote(project, safe=""))
    require(
        public.get("id") == project
        and public.get("description") == "приёмочная проверка реального пользовательского сценария 0351",
        "Данные проекта, доступные игроку, не совпадают с ожидаемыми",
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
        "не удалось создать профиль",
    )
    _, profiles = api.request("GET", "/api/v1/projects/" + project + "/profiles")
    require(
        any(x.get("id") == "test-vanilla" for x in profiles.get("items", [])),
        "Игрок не может найти профиль",
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
        "канал не создан",
    )
    _, channels = api.request("GET", "/api/v1/projects/" + project + "/channels")
    require(
        any(x.get("id") == "acceptance" for x in channels.get("items", [])),
        "канал владельца не виден игроку",
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
        "токены обновления не были заменены",
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
        help="Подтвердить, что операция изменит одноразовый локальный Backend",
    )
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        url = urlsplit(args.backend)
        require(
            args.isolated_test_instance,
            "требуется явное подтверждение использования изолированного тестового экземпляра",
        )
        require(
            url.scheme == "http"
            and url.hostname in ("localhost", "127.0.0.1", "::1")
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment
            and not url.path.rstrip("/"),
            "допускается только локальный тестовый Backend по HTTP",
        )
        email = os.environ.get("LAUNCHER_TEST_ADMIN_EMAIL", "")
        password = os.environ.get("LAUNCHER_TEST_ADMIN_PASSWORD", "")
        require(
            bool(email) and bool(password),
            "тестовые учётные данные должны передаваться через переменные окружения",
        )
        result = run(args.backend.rstrip("/"), email, password)
        atomic_report(args.output, result)
        print(
            "Приёмка Backend для владельца и игрока: пройдена; Minecraft и нативный Desktop не проверялись"
        )
        return 0
    except (AuditError, OSError, ValueError, URLError, KeyError, TypeError) as e:
        print("Приёмочные HTTP-проверки владельца и игрока ЗАБЛОКИРОВАНЫ: " + str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
