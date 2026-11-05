#!/usr/bin/env python3
"""Настоящий браузерный сценарий Admin на РАЗРУШАЮЩЕМ выделенном staging.

Все изменения выполняются через отображаемые элементы Admin. Оператор staging должен подготовить
сертифицированный неизменяемый пакет и неисправный пакет; оба привязаны к сохранённым черновикам
выпуска Admin в ОДНОМ изолированном проекте/профиле/канале. Раннер не создаёт подписи, свидетельства
Runtime или положительные результаты публикации.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid

ROOT = Path(__file__).resolve().parents[2]
SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Для E2E-сценария браузера владельца требуется {name}; искусственная замена недопустима")
    return value


def verify_receipt(receipt: dict, *, version: str, commit: str) -> None:
    if (
        receipt.get("schemaVersion") != 1
        or receipt.get("status") != "passed"
        or receipt.get("productVersion") != version
        or receipt.get("sourceCommit") != commit
        or receipt.get("scope") != "live-admin-browser-owner-cycle-0390"
    ):
        raise RuntimeError("Некорректный идентификатор E2E-сценария браузера владельца")
    required = {
        "project-created-in-admin",
        "profile-created-in-admin",
        "bad-package-denied",
        "good-package-published",
        "channel-head-confirmed",
        "rollback-confirmed",
        "operator-cross-project-denied",
        "reload-recovered-original-job",
    }
    checks = receipt.get("checks")
    if (
        not isinstance(checks, list)
        or len(checks) != len(required)
        or set(checks) != required
    ):
        raise RuntimeError("В E2E-сценарии браузера владельца проверки неполны или дублируются")
    if not all(
        isinstance(receipt.get(x), str) and receipt[x]
        for x in (
            "projectId",
            "profileId",
            "goodPackageId",
            "badPackageId",
            "finalReleaseId",
        )
    ):
        raise RuntimeError("В E2E-сценарии браузера владельца отсутствуют реальные идентификаторы ресурсов")
    if (
        not isinstance(receipt.get("initialRevision"), int)
        or not isinstance(receipt.get("finalRevision"), int)
        or receipt["finalRevision"] != receipt["initialRevision"] + 2
    ):
        raise RuntimeError("E2E-сценарий браузера владельца не подтвердил две ревизии канала")


async def main():
    from playwright.async_api import async_playwright

    if env("E2E_OWNER_DESTRUCTIVE_ACK") != "OWNER_0390_DISPOSABLE_STAGING":
        raise RuntimeError(
            "Разрушающий тест владельца запрещён без специального подтверждения тестовой среды"
        )
    web, api = env("E2E_ADMIN_URL").rstrip("/"), env("E2E_API_URL").rstrip("/")
    admin, operator = env("E2E_ADMIN_TOKEN"), env("E2E_OPERATOR_TOKEN")
    project, profile, channel = (
        env("E2E_OWNER_PROJECT_ID"),
        env("E2E_OWNER_PROFILE_ID"),
        env("E2E_OWNER_CHANNEL"),
    )
    good, bad = env("E2E_OWNER_VALID_PACKAGE_ID"), env("E2E_OWNER_BROKEN_PACKAGE_ID")
    good_draft, bad_draft = (
        env("E2E_OWNER_VALID_DRAFT_VERSION"),
        env("E2E_OWNER_BROKEN_DRAFT_VERSION"),
    )
    rollback_version = env("E2E_OWNER_ROLLBACK_VERSION")
    foreign = env("E2E_FOREIGN_PROJECT_ID")
    commit = env("E2E_EXPECTED_COMMIT")
    if (
        not SHA40.fullmatch(commit)
        or project == foreign
        or good == bad
        or good_draft == bad_draft
    ):
        raise RuntimeError(
            "Некорректный коммит, нарушение изоляции проекта или противоречивые тестовые данные"
        )
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    receipt = {
        "schemaVersion": 1,
        "status": "blocked",
        "productVersion": version,
        "sourceCommit": commit,
        "scope": "live-admin-browser-owner-cycle-0390",
        "checks": [],
        "projectId": project,
        "profileId": profile,
        "goodPackageId": good,
        "badPackageId": bad,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
    }

    async with async_playwright() as p:
        request = await p.request.new_context(
            extra_http_headers={"Authorization": f"Bearer {admin}"}
        )

        async def data(path):
            response = await request.get(api + path, timeout=20000)
            if not response.ok:
                raise RuntimeError(
                    f"Реальная предварительная проверка или чтение {path}: HTTP {response.status}"
                )
            body = await response.json()
            return body.get("data", body)

        try:
            status = await data("/api/v1/status")
            if status.get("version") != version or status.get("sourceCommit") != commit:
                raise RuntimeError(
                    "Тестовый Backend запущен не из точной проверяемой версии или коммита"
                )
            heads = (
                f"/api/v1/projects/{project}/profiles/{profile}/channels/{channel}/head"
            )
            original = await data(heads)
            if (
                original.get("projectId") != project
                or original.get("profileId") != profile
                or original.get("channel") != channel
            ):
                raise RuntimeError("Тестовый указатель последнего релиза канала не совпадает")
            receipt["initialRevision"] = original["revision"]
            for package_id, expected in ((good, True), (bad, False)):
                pkg = await data(f"/api/v1/packages/{package_id}")
                validation = await data(f"/api/v1/packages/{package_id}/validations")
                if (
                    pkg.get("projectId") != project
                    or pkg.get("profileId") != profile
                    or pkg.get("channel") != channel
                ):
                    raise RuntimeError(f"Тестовый пакет из другого проекта: {package_id}")
                if (
                    validation.get("publishReadiness", {}).get("eligible")
                    is not expected
                ):
                    raise RuntimeError(
                        f"Предварительная проверка пакета не соответствует реальной готовности к публикации: {package_id}"
                    )
            drafts = await data(f"/api/v1/release-drafts?projectId={project}")
            found = {d.get("version"): d for d in drafts.get("items", [])}
            if (
                good_draft not in found
                or bad_draft not in found
                or found[good_draft].get("packageId") != good
                or found[bad_draft].get("packageId") != bad
            ):
                raise RuntimeError(
                    "Сохранённые черновики Admin не совпадают с сертифицированными и некорректными тестовыми данными"
                )
            browser = await p.chromium.launch(headless=True)
            try:
                ctx = await browser.new_context()
                await ctx.add_init_script(
                    f"sessionStorage.setItem('launcher.admin.token',{json.dumps(admin)}); sessionStorage.setItem('launcher.admin.projectId',{json.dumps(project)}); localStorage.setItem('launcher.backendUrl',{json.dumps(api)});"
                )
                page = await ctx.new_page()
                page.on("dialog", lambda d: asyncio.create_task(d.accept()))
                # Новый реальный проект и его первый настоящий профиль создаются через формы Admin.
                canary = f"owner0390-{uuid.uuid4().hex[:12]}"
                await page.goto(web + "/#/projects?project=" + project)
                await page.get_by_role("heading", name="Рабочие CRUD-формы").wait_for(
                    timeout=25000
                )
                project_form = (
                    page.locator("article.subcard")
                    .filter(has=page.get_by_role("heading", name="Проект", exact=True))
                    .first
                )
                await project_form.get_by_label("ID", exact=True).fill(canary)
                await project_form.get_by_label("Название", exact=True).fill(
                    "Owner 0390 E2E"
                )
                await project_form.get_by_role(
                    "button", name="Создать", exact=True
                ).click()
                await page.get_by_text(f"Проект {canary} создан и выбран.").wait_for(
                    timeout=20000
                )
                receipt["checks"].append("project-created-in-admin")
                await page.goto(web + f"/#/profiles?project={canary}")
                editor = page.get_by_role("article", name="Редактор профиля Minecraft")
                await editor.get_by_label("ID профиля").fill("vanilla-e2e")
                await editor.get_by_label("Название").fill("Vanilla test")
                await editor.get_by_label("Minecraft").fill("1.21.1")
                await editor.get_by_role("button", name="Создать профиль").click()
                await editor.get_by_text("Профиль vanilla-e2e сохранён.").wait_for(
                    timeout=20000
                )
                receipt["checks"].append("profile-created-in-admin")
                # Вернитесь к сертифицированным ресурсам тестового развёртывания и проверьте отрицательный сценарий через UI.
                uri = (
                    web
                    + f"/#/release-workspace?project={project}&profile={profile}&channel={channel}"
                )
                await page.goto(uri)
                await page.get_by_role(
                    "heading", name=f"Release Workspace · {version}"
                ).wait_for(timeout=25000)
                source = await page.locator(
                    "meta[name=launcher-source-commit]"
                ).get_attribute("content")
                if source != commit:
                    raise RuntimeError(
                        "Пакет JavaScript Admin собран не из проверяемого коммита"
                    )
                await page.get_by_role(
                    "button", name=bad_draft, exact=False
                ).first.click()
                await page.get_by_role(
                    "button", name="Публикация и откат", exact=True
                ).click()
                await page.get_by_role("button", name="Предпросмотр публикации").click()
                await page.locator(
                    ".releaseWorkspace .error[role=alert]"
                ).first.wait_for(timeout=20000)
                if await page.get_by_role("button", name="Опубликовать").is_enabled():
                    raise RuntimeError(
                        "Некорректный пакет неожиданно допускается к публикации в Admin"
                    )
                if (await data(heads))["revision"] != original["revision"]:
                    raise RuntimeError("Некорректный пакет изменил указатель последнего релиза канала")
                receipt["checks"].append("bad-package-denied")
                await page.get_by_role(
                    "button", name=good_draft, exact=False
                ).first.click()
                await page.get_by_role(
                    "button", name="Публикация и откат", exact=True
                ).click()
                await page.get_by_role("button", name="Предпросмотр публикации").click()
                await page.get_by_text("Серверный эффект публикации").wait_for(
                    timeout=20000
                )
                await page.get_by_role("button", name="Опубликовать").click()
                await page.get_by_role(
                    "heading", name="Проверка реального результата операции"
                ).wait_for(timeout=20000)
                # Точный исходный ключ идемпотентности и задание должны сохраниться после перезагрузки браузера.
                await page.reload()
                await page.get_by_role(
                    "heading", name="Проверка реального результата операции"
                ).wait_for(timeout=20000)
                receipt["checks"].append("reload-recovered-original-job")
                await page.get_by_text(
                    "Подтверждено Backend: channel head обновлён"
                ).wait_for(timeout=90000)
                published = await data(heads)
                if (
                    published.get("releaseId") != good
                    or published.get("revision") != original["revision"] + 1
                ):
                    raise RuntimeError(
                        "Успешная публикация не обновила указатель последнего релиза канала"
                    )
                receipt["checks"].extend(
                    ("good-package-published", "channel-head-confirmed")
                )
                await page.get_by_role("button", name="Закрыть после проверки").click()
                await page.get_by_label("Целевая опубликованная версия").select_option(
                    rollback_version
                )
                await page.get_by_role("button", name="Предпросмотр отката").click()
                await page.get_by_text("Серверный эффект отката").wait_for(
                    timeout=20000
                )
                await page.get_by_role("button", name="Выполнить откат").click()
                await page.get_by_text(
                    "Подтверждено Backend: channel head обновлён"
                ).wait_for(timeout=90000)
                rolled_back = await data(heads)
                if (
                    rolled_back.get("revision") != published["revision"] + 1
                    or rolled_back.get("releaseId") == good
                ):
                    raise RuntimeError(
                        "Откат не создал новый подтверждённый релиз"
                    )
                receipt["checks"].append("rollback-confirmed")
                receipt["finalRevision"] = rolled_back["revision"]
                receipt["finalReleaseId"] = rolled_back["releaseId"]
                # Токен оператора принадлежит другому субъекту; чтение между проектами запрещено.
                denied = await p.request.new_context(
                    extra_http_headers={"Authorization": f"Bearer {operator}"}
                )
                try:
                    response = await denied.get(
                        api + f"/api/v1/operations/jobs?projectId={foreign}"
                    )
                    if response.status != 403:
                        raise RuntimeError(
                            f"Доступ к чужому проекту: HTTP {response.status}"
                        )
                finally:
                    await denied.dispose()
                receipt["checks"].append("operator-cross-project-denied")
                verify_receipt(
                    {**receipt, "status": "passed"}, version=version, commit=commit
                )
                receipt["status"] = "passed"
            finally:
                await browser.close()
        finally:
            await request.dispose()
    # Это доказательство CI ВНЕ подписанных артефактов, а не подпись GA или оператора.
    output = ROOT / "dist/ga-certification/owner-cycle-0390.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Owner 0.39.0 real browser cycle PASS: {receipt['finalReleaseId']}")


if __name__ == "__main__":
    asyncio.run(main())
