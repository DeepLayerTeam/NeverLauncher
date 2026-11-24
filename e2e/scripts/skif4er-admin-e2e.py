#!/usr/bin/env python3
"""Real Chromium + built Admin SPA. Default: deterministic IdP/API fixture.
--live: use a dedicated already-linked staging account and real SkiF4er ID.
Never save browser state, screenshots, traces or credentials.
"""
import argparse
import base64
import json
import mimetypes
import os
from pathlib import Path
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
ISSUER = 'https://id.skif4er.ru/realms/skif4er'
CALLBACK = '/auth/skif4er/callback'
PENDING = 'launcher.admin.skif4er.pending'
TOKEN = 'launcher.admin.token'
REFRESH = 'launcher.admin.refreshToken'

def jwt(seq):
    body = base64.urlsafe_b64encode(json.dumps({'exp': int(time.time())+3600, 'seq': seq}).encode()).decode().rstrip('=')
    return 'header.'+body+'.signature'


def fixture(browser):
    origin = 'https://admin.example.test'
    dist = ROOT / 'apps/admin/dist'
    assert (dist/'index.html').is_file(), 'Build Admin Panel first'
    ctx = browser.new_context()
    page = ctx.new_page()
    linked = True
    calls = {'complete': 0, 'link': 0, 'mfa': 0, 'refresh': 0, 'logout': 0, 'unlink': 0}
    state, transaction = 's'*43, 'sealed-transaction'
    access, refresh = jwt(0), 'refresh-0'
    user = {'id':'u-1','email':'fixture@example.test','roleId':'player','status':'active','projectRoles':{}}
    local = {'id':'local-1','provider':'local','email':user['email']}
    ski = {'id':'ski-1','provider':'skif4er-id','email':'external@example.test'}
    def session():
        return {'status':'authenticated','provider':'skif4er-id','user':user,'session':{'id':'session-1'},'tokens':{'accessToken':access,'refreshToken':refresh}}
    def route_handler(route):
        nonlocal linked, access, refresh
        req = route.request
        url = urlsplit(req.url)
        path = url.path
        def reply(data, status=200):
            route.fulfill(status=status, json={'data':data} if status<400 else {'error':{'message':'fixture rejection'}})
        if req.url.startswith(ISSUER+'/protocol/openid-connect/auth?'):
            q = parse_qs(url.query)
            assert q['code_challenge_method']==['S256'] and q['redirect_uri']==[origin+CALLBACK]
            route.fulfill(status=302, headers={'Location':origin+CALLBACK+'?'+urlencode({'code':'one-use-code','state':q['state'][0],'iss':ISSUER})}); return
        if url.netloc != 'admin.example.test':
            route.abort(); return
        if not path.startswith('/api/'):
            target = dist / (path.lstrip('/') if path.startswith('/assets/') else 'index.html')
            route.fulfill(status=200, body=target.read_bytes(), content_type=mimetypes.guess_type(target)[0] or 'application/octet-stream'); return
        if path.endswith('/auth/providers'):
            reply({'items':[{'id':'skif4er-id','healthy':True,'capabilities':['browser-auth']} ]}); return
        if path.endswith('/begin') and ('/oidc/skif4er-id/' in path or '/skif4er-id/link/' in path):
            body=req.post_data_json
            assert body['redirectUri']==origin+CALLBACK and body['deviceId']=='admin-browser'
            params={'client_id':'launcher','state':state,'nonce':'n'*43,'code_challenge':'c'*43,'code_challenge_method':'S256','response_type':'code','redirect_uri':origin+CALLBACK}
            if '/link/' in path: params['prompt']='login'
            reply({'authorizationUrl':ISSUER+'/protocol/openid-connect/auth?'+urlencode(params),'state':state,'transaction':transaction,'expiresAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+600))}); return
        if path.endswith('/link/complete'):
            assert req.headers.get('authorization')=='Bearer '+access
            assert req.post_data_json['transaction']==transaction
            linked=True; calls['link']+=1; reply({'status':'linked','identity':ski}); return
        if path.endswith('/oidc/skif4er-id/complete'):
            assert req.post_data_json['state']==state and req.post_data_json['code']=='one-use-code'
            calls['complete']+=1
            reply({'status':'mfa-required','method':'totp-or-recovery','transactionToken':'fixture-mfa','expiresInSeconds':300},202); return
        if path.endswith('/oidc/skif4er-id/mfa/complete'):
            assert req.post_data_json=={'transactionToken':'fixture-mfa','totp':'123456'}
            calls['mfa']+=1; reply(session()); return
        if path.endswith('/auth/refresh'):
            assert req.post_data_json['refreshToken']==refresh
            calls['refresh']+=1; access,refresh=jwt(calls['refresh']),'refresh-'+str(calls['refresh']); reply(session()); return
        if path.endswith('/auth/logout'):
            assert req.headers.get('authorization')=='Bearer '+access
            calls['logout']+=1; reply({'status':'logged-out','sessionId':'session-1'}); return
        if path.endswith('/admin/login'):
            reply({'token':access,'refreshToken':refresh,'sessionId':'session-1','user':user}); return
        if path.endswith('/auth/identities/ski-1') and req.method=='DELETE':
            calls['unlink']+=1; linked=False; reply({'status':'unlinked'}); return
        if path.endswith('/auth/identities'):
            reply({'items':[local, ski] if linked else [local]}); return
        if path.endswith('/admin/me'):
            reply({'user':user,'permissions':[],'projectPermissions':{}}); return
        if path.endswith('/admin/overview'):
            reply({k:[] for k in ('projects','profiles','channels','versions','files','users','audit')}); return
        reply({'items':[],'count':0})
    ctx.route('**/*',route_handler)
    page.goto(origin)
    page.get_by_role('button',name='Войти через SkiF4er ID',exact=True).click()
    expect(page.get_by_role('heading',name='Подтвердите вход SkiF4er ID')).to_be_visible()
    assert page.evaluate(f'sessionStorage.getItem({json.dumps(TOKEN)})') is None
    assert CALLBACK not in page.url and 'one-use-code' not in page.url
    page.get_by_label('TOTP',exact=True).fill('123456')
    page.get_by_role('button',name='Подтвердить MFA').click()
    expect(page.get_by_text('Вход через SkiF4er ID выполнен.',exact=True)).to_be_visible()
    page.get_by_text('Безопасность сеанса и ключи доступа',exact=True).click()
    page.get_by_role('button',name='Обновить сессию',exact=True).click()
    expect(page.get_by_text('Сессия обновлена.',exact=True)).to_be_visible()
    assert page.evaluate(f'sessionStorage.getItem({json.dumps(REFRESH)})')=='refresh-1'
    page.reload()
    expect(page.get_by_role('button',name='Привязать SkiF4er ID')).to_be_visible()
    page.get_by_text('Безопасность сеанса и ключи доступа',exact=True).click()
    page.get_by_role('button',name='Выйти',exact=True).click()
    expect(page.get_by_text('Сессия завершена на сервере.',exact=True)).to_be_visible()
    assert page.evaluate(f'sessionStorage.getItem({json.dumps(TOKEN)})') is None
    page.get_by_placeholder('почта администратора').fill(user['email'])
    page.get_by_placeholder('пароль',exact=True).fill('fixture-password')
    page.get_by_role('button',name='Войти',exact=True).click()
    page.get_by_role('button',name='Отвязать SkiF4er ID').click()
    page.get_by_role('button',name='Подтвердить отвязку').click()
    expect(page.get_by_text('SkiF4er ID отвязан; связанные сессии отозваны.',exact=True)).to_be_visible()
    expect(page.get_by_role('button',name='Привязать SkiF4er ID')).to_be_enabled()
    page.get_by_role('button',name='Привязать SkiF4er ID').click()
    expect(page.get_by_text('SkiF4er ID привязан.',exact=True)).to_be_visible()
    page.goto(origin+CALLBACK+'?'+urlencode({'code':'one-use-code','state':state,'iss':ISSUER}))
    expect(page.get_by_text('Транзакция SkiF4er ID отсутствует или уже использована.',exact=True)).to_be_visible()
    assert calls=={'complete':1,'link':1,'mfa':1,'refresh':1,'logout':1,'unlink':1},calls
    ctx.close()
    print('Admin browser E2E (fixture): PASS')


def live(browser):
    # Dedicated staging user, pre-linked to an existing Launcher account. No automatic
    # provisioning or destructive account edits in the live smoke.
    origin=os.environ['SKIF4ER_E2E_ADMIN_URL'].rstrip('/')
    backend=os.environ['SKIF4ER_E2E_BACKEND_URL'].rstrip('/')
    assert origin.startswith('https://') and backend.startswith('https://')
    ctx=browser.new_context(); page=ctx.new_page()
    try:
        page.goto(origin)
        page.get_by_text('URL серверной части',exact=True).locator('..').locator('input').fill(backend)
        page.get_by_role('button',name='Войти через SkiF4er ID',exact=True).click(timeout=30000)
        page.wait_for_url(ISSUER+'/**')
        page.locator('input[name="username"]').fill(os.environ['SKIF4ER_E2E_USERNAME'])
        page.locator('input[name="password"]').fill(os.environ['SKIF4ER_E2E_PASSWORD'])
        page.locator('#kc-login').click()
        page.wait_for_url(origin+'/**',timeout=120000)
        mfa = page.get_by_role('heading',name='Подтвердите вход SkiF4er ID')
        success = page.get_by_text('Вход через SkiF4er ID выполнен.',exact=True)
        expect(mfa.or_(success)).to_be_visible(timeout=30000)
        if mfa.is_visible():
            # One-use recovery code for the dedicated test account, supplied outside the repo.
            page.get_by_label('Код восстановления',exact=True).fill(os.environ['SKIF4ER_E2E_RECOVERY_CODE'])
            page.get_by_role('button',name='Подтвердить MFA').click()
        expect(page.get_by_text('Вход через SkiF4er ID выполнен.',exact=True)).to_be_visible(timeout=30000)
        access=page.evaluate(f'sessionStorage.getItem({json.dumps(TOKEN)})')
        response=ctx.request.get(backend+'/api/v1/admin/me',headers={'Authorization':'Bearer '+access})
        assert response.ok and response.json()['user']['id']==os.environ['SKIF4ER_E2E_CANONICAL_USER_ID']
        page.get_by_text('Безопасность сеанса и ключи доступа',exact=True).click()
        page.get_by_role('button',name='Обновить сессию',exact=True).click()
        expect(page.get_by_text('Сессия обновлена.',exact=True)).to_be_visible(timeout=30000)
        access=page.evaluate(f'sessionStorage.getItem({json.dumps(TOKEN)})')
        page.get_by_role('button',name='Выйти',exact=True).click()
        expect(page.get_by_text('Сессия завершена на сервере.',exact=True)).to_be_visible(timeout=30000)
        assert ctx.request.get(backend+'/api/v1/admin/me',headers={'Authorization':'Bearer '+access}).status==401
        print('Admin browser E2E (real Keycloak): PASS')
    finally:
        ctx.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--live',action='store_true'); args=parser.parse_args()
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        try: (live if args.live else fixture)(browser)
        finally: browser.close()
