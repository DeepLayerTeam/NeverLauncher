#!/usr/bin/env python3
"""Real browser + real Backend hardening checks. No stub endpoints or mocked replies.

Run against a dedicated disposable NeverLauncher instance; creates/deletes one
release draft. E2E_ADMIN_URL, E2E_API_URL, E2E_ADMIN_TOKEN,
E2E_OPERATOR_TOKEN, E2E_PROJECT_ID and E2E_FOREIGN_PROJECT_ID are required.
"""
from __future__ import annotations
import asyncio
import os
import time
import json
from pathlib import Path
from playwright.async_api import async_playwright


def required(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise SystemExit(f"[admin-hardening-02112] missing {name}; cannot certify browser E2E")
    return value


async def main():
    web = required('E2E_ADMIN_URL').rstrip('/')
    api = required('E2E_API_URL').rstrip('/')
    admin = required('E2E_ADMIN_TOKEN')
    operator = required('E2E_OPERATOR_TOKEN')
    project = required('E2E_PROJECT_ID')
    other = required('E2E_FOREIGN_PROJECT_ID')
    version = (Path(__file__).resolve().parents[2] / 'VERSION').read_text(encoding='utf-8').strip()
    expected_commit = os.environ.get('E2E_EXPECTED_COMMIT', '').strip()
    if expected_commit and (len(expected_commit) != 40 or any(c not in '0123456789abcdef' for c in expected_commit)):
        raise AssertionError('E2E_EXPECTED_COMMIT must be a lowercase 40-digit SHA-1 commit ID')
    # A stale staging deployment is not a release candidate of this checkout.
    async with async_playwright() as probe:
        request = await probe.request.new_context()
        try:
            status = await request.get(api + '/api/v1/status', timeout=15000)
            if status.status != 200 or (await status.json()).get('version') != version:
                raise AssertionError(f'Backend staging version mismatch: expected {version}, status {status.status}')
            if expected_commit and (await status.json()).get('sourceCommit') != expected_commit:
                raise AssertionError('Backend staging source commit does not match candidate SHA')
            readiness = await request.get(api + '/ready', timeout=15000)
            if readiness.status != 200 or (await readiness.json()).get('status') != 'ready':
                raise AssertionError(f'Backend not ready for GA E2E: {readiness.status}')
        finally:
            await request.dispose()
    if project == other:
        raise SystemExit('E2E_PROJECT_ID and E2E_FOREIGN_PROJECT_ID must differ')
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            ctx = await browser.new_context()
            await ctx.add_init_script(f"sessionStorage.setItem('neverlauncher.admin.token', {json.dumps(admin)}); sessionStorage.setItem('neverlauncher.admin.projectId', {json.dumps(project)}); localStorage.setItem('neverlauncher.backendUrl', {json.dumps(api)});")
            page1, page2 = await ctx.new_page(), await ctx.new_page()
            url = web + '/#/release-workspace'
            await asyncio.gather(page1.goto(url), page2.goto(url))
            await asyncio.gather(page1.get_by_role('heading', name=f'Release Workspace · {version}').wait_for(timeout=20000), page2.get_by_role('heading', name=f'Release Workspace · {version}').wait_for(timeout=20000))
            if expected_commit:
                source = await page1.locator('meta[name=neverlauncher-source-commit]').get_attribute('content')
                assert source == expected_commit, 'Admin staging bundle source commit does not match candidate SHA'
            await page1.get_by_text('Черновики проекта').first.wait_for(timeout=20000)
            headers = { 'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json' }
            fields = {
                'projectId': project, 'profileId': '', 'channel': 'stable',
                'version': 'e2e-02112-' + str(time.time_ns()),
                'minecraftVersion': '', 'loader': 'vanilla', 'packageId': '',
                'jobId': '', 'step': 'project'
            }
            created = await ctx.request.post(api + '/api/v1/release-drafts', headers=headers, data=fields)
            if created.status != 201:
                raise AssertionError(f'Draft API create failed: {created.status} {await created.text()}')
            draft = (await created.json())['data']
            draft_id = draft['id']
            try:
                await asyncio.gather(page1.reload(), page2.reload())
                await asyncio.gather(page1.get_by_role('button', name=f"{fields['version']}", exact=False).wait_for(timeout=20000), page2.get_by_role('button', name=f"{fields['version']}", exact=False).wait_for(timeout=20000))
                # Two tabs submit the SAME revision. The server must atomically reject one.
                copy1, copy2 = dict(draft), dict(draft)
                copy1['step'], copy2['step'] = 'profile', 'build'
                target = api + '/api/v1/release-drafts/' + draft_id
                first, second = await asyncio.gather(
                    ctx.request.put(target, headers=headers, data=copy1),
                    ctx.request.put(target, headers=headers, data=copy2))
                assert sorted([first.status, second.status]) == [200, 409], f'CAS failure: {first.status}, {second.status}'
                # Browser loses connectivity, but the already stored draft survives.
                await ctx.set_offline(True)
                await page1.get_by_role('button', name='Обновить', exact=True).first.click()
                await page1.get_by_role('alert').wait_for(timeout=15000)
                await ctx.set_offline(False)
                await page1.reload()
                await page1.get_by_role('button', name=f"{fields['version']}", exact=False).wait_for(timeout=20000)
                # Backend must not leak a foreign project to an operator.
                denied = await ctx.request.get(api + '/api/v1/operations/jobs?projectId=' + other,
                                               headers={'Authorization': 'Bearer ' + operator})
                assert denied.status == 403, f'Cross-project jobs were visible: {denied.status}'
                op_ctx = await browser.new_context()
                await op_ctx.add_init_script(f"sessionStorage.setItem('neverlauncher.admin.token', {json.dumps(operator)}); sessionStorage.setItem('neverlauncher.admin.projectId', {json.dumps(project)}); localStorage.setItem('neverlauncher.backendUrl', {json.dumps(api)});")
                op_page = await op_ctx.new_page()
                await op_page.goto(web + '/#/config')
                await op_page.get_by_text('Нет доступа').wait_for(timeout=20000)
                assert await op_page.get_by_role('button', name='Применить с MFA').count() == 0
                await op_ctx.close()
                # A11y: the unauthenticated login form uses accessible labels.
                login_ctx = await browser.new_context()
                login_page = await login_ctx.new_page()
                await login_page.goto(web)
                for label in ('Email администратора', 'Пароль', 'TOTP (необязательно)', 'Код восстановления (необязательно)'):
                    assert await login_page.get_by_label(label).count() == 1, label
                await login_page.get_by_role('navigation', name='Разделы панели управления').wait_for()
                await login_ctx.close()
                print('[admin-hardening-02112] browser PASS: live Backend, two tabs CAS, offline/recovery, RBAC, labels')
            finally:
                await ctx.set_offline(False)
                deleted = await ctx.request.delete(api + '/api/v1/release-drafts/' + draft_id, headers=headers)
                if deleted.status != 200:
                    print(f'[admin-hardening-02112] warning: failed to clean draft {draft_id}: {deleted.status}')
            await ctx.close()
        finally:
            await browser.close()


if __name__ == '__main__':
    asyncio.run(main())
