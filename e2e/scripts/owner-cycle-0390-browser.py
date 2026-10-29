#!/usr/bin/env python3
"""Real Admin browser journey on DESTRUCTIVE dedicated staging.

All mutations occur through rendered Admin controls. The staging operator must
prepare a certified immutable package and a broken package, each bound to saved
Admin release drafts in the SAME isolated project/profile/channel. This runner
never manufactures signatures, runtime evidence, or a positive publish result.
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
SHA40 = re.compile(r'[0-9a-f]{40}\Z')


def env(name: str) -> str:
    value = os.getenv(name, '').strip()
    if not value:
        raise RuntimeError(f'owner browser E2E requires {name}; no synthetic fallback')
    return value


def verify_receipt(receipt: dict, *, version: str, commit: str) -> None:
    if (receipt.get('schemaVersion') != 1 or receipt.get('status') != 'passed' or
        receipt.get('productVersion') != version or receipt.get('sourceCommit') != commit or
        receipt.get('scope') != 'live-admin-browser-owner-cycle-0390'):
        raise RuntimeError('invalid owner browser E2E identity')
    required = {'project-created-in-admin', 'profile-created-in-admin', 'bad-package-denied',
                'good-package-published', 'channel-head-confirmed', 'rollback-confirmed',
                'operator-cross-project-denied', 'reload-recovered-original-job'}
    checks = receipt.get('checks')
    if not isinstance(checks, list) or len(checks) != len(required) or set(checks) != required:
        raise RuntimeError('owner browser E2E incomplete or duplicate checks')
    if not all(isinstance(receipt.get(x), str) and receipt[x] for x in
               ('projectId', 'profileId', 'goodPackageId', 'badPackageId', 'finalReleaseId')):
        raise RuntimeError('owner browser E2E lacks actual resource identifiers')
    if (not isinstance(receipt.get('initialRevision'), int) or
        not isinstance(receipt.get('finalRevision'), int) or
        receipt['finalRevision'] != receipt['initialRevision'] + 2):
        raise RuntimeError('owner browser E2E did not prove two channel revisions')


async def main():
    from playwright.async_api import async_playwright
    if env('E2E_OWNER_DESTRUCTIVE_ACK') != 'OWNER_0390_DISPOSABLE_STAGING':
        raise RuntimeError('refusing destructive owner test without dedicated staging acknowledgement')
    web, api = env('E2E_ADMIN_URL').rstrip('/'), env('E2E_API_URL').rstrip('/')
    admin, operator = env('E2E_ADMIN_TOKEN'), env('E2E_OPERATOR_TOKEN')
    project, profile, channel = env('E2E_OWNER_PROJECT_ID'), env('E2E_OWNER_PROFILE_ID'), env('E2E_OWNER_CHANNEL')
    good, bad = env('E2E_OWNER_VALID_PACKAGE_ID'), env('E2E_OWNER_BROKEN_PACKAGE_ID')
    good_draft, bad_draft = env('E2E_OWNER_VALID_DRAFT_VERSION'), env('E2E_OWNER_BROKEN_DRAFT_VERSION')
    rollback_version = env('E2E_OWNER_ROLLBACK_VERSION')
    foreign = env('E2E_FOREIGN_PROJECT_ID')
    commit = env('E2E_EXPECTED_COMMIT')
    if not SHA40.fullmatch(commit) or project == foreign or good == bad or good_draft == bad_draft:
        raise RuntimeError('invalid commit, project isolation or contradictory fixtures')
    version = (ROOT/'VERSION').read_text(encoding='utf-8').strip()
    receipt = {'schemaVersion':1, 'status':'blocked', 'productVersion':version,'sourceCommit':commit,
               'scope':'live-admin-browser-owner-cycle-0390', 'checks':[], 'projectId':project,
               'profileId':profile,'goodPackageId':good,'badPackageId':bad,
               'verifiedAt':datetime.now(timezone.utc).isoformat()}

    async with async_playwright() as p:
        request = await p.request.new_context(extra_http_headers={'Authorization':f'Bearer {admin}'})
        async def data(path):
            response = await request.get(api + path, timeout=20000)
            if not response.ok: raise RuntimeError(f'live preflight/read {path}: HTTP {response.status}')
            body = await response.json()
            return body.get('data',body)
        try:
            status = await data('/api/v1/status')
            if status.get('version') != version or status.get('sourceCommit') != commit:
                raise RuntimeError('staging Backend does not run exact candidate version/commit')
            heads = f'/api/v1/projects/{project}/profiles/{profile}/channels/{channel}/head'
            original = await data(heads)
            if original.get('projectId') != project or original.get('profileId') != profile or original.get('channel') != channel:
                raise RuntimeError('channel head fixture mismatch')
            receipt['initialRevision'] = original['revision']
            for package_id, expected in ((good,True),(bad,False)):
                pkg = await data(f'/api/v1/packages/{package_id}')
                validation = await data(f'/api/v1/packages/{package_id}/validations')
                if pkg.get('projectId') != project or pkg.get('profileId') != profile or pkg.get('channel') != channel:
                    raise RuntimeError(f'foreign package fixture: {package_id}')
                if validation.get('publishReadiness',{}).get('eligible') is not expected:
                    raise RuntimeError(f'package preflight does not match real publish readiness: {package_id}')
            drafts = await data(f'/api/v1/release-drafts?projectId={project}')
            found = {d.get('version'):d for d in drafts.get('items',[])}
            if (good_draft not in found or bad_draft not in found or
                found[good_draft].get('packageId') != good or found[bad_draft].get('packageId') != bad):
                raise RuntimeError('saved Admin drafts do not match certified/broken fixtures')
            browser = await p.chromium.launch(headless=True)
            try:
                ctx = await browser.new_context()
                await ctx.add_init_script(f"sessionStorage.setItem('neverlauncher.admin.token',{json.dumps(admin)}); sessionStorage.setItem('neverlauncher.admin.projectId',{json.dumps(project)}); localStorage.setItem('neverlauncher.backendUrl',{json.dumps(api)});")
                page = await ctx.new_page()
                page.on('dialog',lambda d: asyncio.create_task(d.accept()))
                # Fresh real project and its first real profile, created through Admin forms.
                canary = f'owner0390-{uuid.uuid4().hex[:12]}'
                await page.goto(web + '/#/projects?project=' + project)
                await page.get_by_role('heading',name='Рабочие CRUD-формы').wait_for(timeout=25000)
                project_form = page.locator('article.subcard').filter(has=page.get_by_role('heading',name='Проект',exact=True)).first
                await project_form.get_by_label('ID',exact=True).fill(canary)
                await project_form.get_by_label('Название',exact=True).fill('Owner 0390 E2E')
                await project_form.get_by_role('button',name='Создать',exact=True).click()
                await page.get_by_text(f'Проект {canary} создан и выбран.').wait_for(timeout=20000)
                receipt['checks'].append('project-created-in-admin')
                await page.goto(web + f'/#/profiles?project={canary}')
                editor = page.get_by_role('article',name='Редактор профиля Minecraft')
                await editor.get_by_label('ID профиля').fill('vanilla-e2e')
                await editor.get_by_label('Название').fill('Vanilla test')
                await editor.get_by_label('Minecraft').fill('1.21.1')
                await editor.get_by_role('button',name='Создать профиль').click()
                await editor.get_by_text('Профиль vanilla-e2e сохранён.').wait_for(timeout=20000)
                receipt['checks'].append('profile-created-in-admin')
                # Return to certified staging resources and verify negative case via UI.
                uri = web + f'/#/release-workspace?project={project}&profile={profile}&channel={channel}'
                await page.goto(uri)
                await page.get_by_role('heading',name=f'Release Workspace · {version}').wait_for(timeout=25000)
                source = await page.locator('meta[name=neverlauncher-source-commit]').get_attribute('content')
                if source != commit: raise RuntimeError('Admin JavaScript bundle is not from candidate commit')
                await page.get_by_role('button',name=bad_draft,exact=False).first.click()
                await page.get_by_role('button',name='Публикация и откат',exact=True).click()
                await page.get_by_role('button',name='Предпросмотр публикации').click()
                await page.locator('.releaseWorkspace .error[role=alert]').first.wait_for(timeout=20000)
                if await page.get_by_role('button',name='Опубликовать').is_enabled():
                    raise RuntimeError('invalid package unexpectedly publishable in Admin')
                if (await data(heads))['revision'] != original['revision']:
                    raise RuntimeError('invalid package changed channel head')
                receipt['checks'].append('bad-package-denied')
                await page.get_by_role('button',name=good_draft,exact=False).first.click()
                await page.get_by_role('button',name='Публикация и откат',exact=True).click()
                await page.get_by_role('button',name='Предпросмотр публикации').click()
                await page.get_by_text('Серверный эффект публикации').wait_for(timeout=20000)
                await page.get_by_role('button',name='Опубликовать').click()
                await page.get_by_role('heading',name='Проверка реального результата операции').wait_for(timeout=20000)
                # Exact original idempotency key and job must survive browser reload.
                await page.reload()
                await page.get_by_role('heading',name='Проверка реального результата операции').wait_for(timeout=20000)
                receipt['checks'].append('reload-recovered-original-job')
                await page.get_by_text('Подтверждено Backend: channel head обновлён').wait_for(timeout=90000)
                published = await data(heads)
                if published.get('releaseId') != good or published.get('revision') != original['revision']+1:
                    raise RuntimeError('successful publish did not advance exact channel head')
                receipt['checks'].extend(('good-package-published','channel-head-confirmed'))
                await page.get_by_role('button',name='Закрыть после проверки').click()
                await page.get_by_label('Целевая опубликованная версия').select_option(rollback_version)
                await page.get_by_role('button',name='Предпросмотр отката').click()
                await page.get_by_text('Серверный эффект отката').wait_for(timeout=20000)
                await page.get_by_role('button',name='Выполнить откат').click()
                await page.get_by_text('Подтверждено Backend: channel head обновлён').wait_for(timeout=90000)
                rolled_back = await data(heads)
                if rolled_back.get('revision') != published['revision']+1 or rolled_back.get('releaseId') == good:
                    raise RuntimeError('rollback did not produce a new confirmed release')
                receipt['checks'].append('rollback-confirmed')
                receipt['finalRevision'] = rolled_back['revision']
                receipt['finalReleaseId'] = rolled_back['releaseId']
                # Operator token is a separate principal; no cross-project read.
                denied = await p.request.new_context(extra_http_headers={'Authorization':f'Bearer {operator}'})
                try:
                    response = await denied.get(api + f'/api/v1/operations/jobs?projectId={foreign}')
                    if response.status != 403: raise RuntimeError(f'foreign project access: HTTP {response.status}')
                finally: await denied.dispose()
                receipt['checks'].append('operator-cross-project-denied')
                verify_receipt({**receipt,'status':'passed'},version=version,commit=commit)
                receipt['status']='passed'
            finally:
                await browser.close()
        finally:
            await request.dispose()
    # This is CI evidence OUTSIDE signed artifacts, not a GA/operator signature.
    output = ROOT/'dist/ga-certification/owner-cycle-0390.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(f'Owner 0.39.0 real browser cycle PASS: {receipt["finalReleaseId"]}')


if __name__ == '__main__':
    asyncio.run(main())
