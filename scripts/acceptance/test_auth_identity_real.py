#!/usr/bin/env python3
"""Регрессионные модульные и отрицательные тесты. Фикстуры модуля не подтверждают реальную аутентификацию."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth_identity_real as auth


def example_input():
    return {
        'scope':'dedicated-disposable-accounts', 'allowIdentityMutation':True,
        'origin':'https://launcher.example.test',
        'local': {'identifier':'owner@example.test','password':'secret-password','providerId':'local'},
        'secondary': {'identifier':'second@example.test','password':'different-secret','providerId':'local'},
        'sql': {'identifier':'sqlowner@example.test','password':'external-password','providerId':'sql'},
        'oidc': {'providerId':'oidc','kind':'generic'},
        'official': {'userType':'msa','authServerBaseUrl':'','username':'TestPlayer',
                     'uuid':'1234567890abcdef1234567890abcdef','accessToken':'very-private-minecraft-token'},
    }


class AuthAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)

    def input(self, data, name='input.json'):
        p=self.folder / name
        p.write_text(json.dumps(data))
        p.chmod(0o600)
        return p

    def test_strict_real_provider_selection(self):
        fixture=example_input()
        auth.check_input(fixture)
        for mutation in [
            lambda f: f.update(scope='not-real'),
            lambda f: f.update(allowIdentityMutation=False),
            lambda f: f['sql'].update(providerId='local'),
            lambda f: f['secondary'].update(identifier='owner@example.test'),
            lambda f: f['official'].update(userType='mojang'),
            lambda f: f['oidc'].update(kind='unknown'),
            lambda f: f['official'].update(uuid='not-a-uuid'),
        ]:
            changed=example_input(); mutation(changed)
            with self.assertRaises(auth.Blocked): auth.check_input(changed)

    def test_https_no_redirect_or_host_injection(self):
        for origin in ('http://launcher.example.test','https://user:pass@launcher.example.test',
                       'https://launcher.example.test/path','https://launcher.example.test?token=secret',
                       'https://launcher.example.test#fragment'):
            with self.assertRaises(auth.Blocked): auth.LiveAPI(origin)
        api=auth.LiveAPI('https://launcher.example.test')
        for path in ('http://outside.test','//evil.test','/api/v1/../x#fragment',
                     '/api/v1/\\unsafe','/health'):
            with self.assertRaises(auth.Blocked): api.request('GET',path)
        self.assertIsNone(auth.NoRedirect().redirect_request(None,None,None,None,None,None))

    def test_private_inputs_and_exclusive_secure_output(self):
        input_path=self.input(example_input())
        self.assertEqual(auth.private_json(input_path)['scope'],'dedicated-disposable-accounts')
        input_path.chmod(0o644)
        with self.assertRaises(auth.Blocked): auth.private_json(input_path)
        input_path.chmod(0o600)
        link=self.folder/'alias.json'; link.symlink_to(input_path)
        with self.assertRaises(auth.Blocked): auth.private_json(link)
        output=self.folder/'result.json'
        auth.private_write(output,{'status':'blocked','reason':'negative fixture'})
        self.assertEqual(output.stat().st_mode & 0o777,0o600)
        with self.assertRaises(auth.Blocked): auth.private_write(output, {'status':'passed'})
        self.assertEqual(json.loads(output.read_text())['status'],'blocked')

    def test_missing_actual_browser_codes_cannot_run(self):
        raw=example_input()
        proof={'version':auth.VERSION,'origin':raw['origin'],'providerId':'oidc',
               'ownerSha256':auth.user_digest('owner'), 'generatedAt':int(time.time()),
               'link':{'code':'','state':'s','transaction':'t'},
               'login':{'code':'','state':'s2','transaction':'t2'}}
        api=auth.LiveAPI(raw['origin'])
        with self.assertRaises(auth.Blocked):
            auth.live_run(api,raw,proof)
        proof['generatedAt'] -= 700
        with self.assertRaises(auth.Blocked): auth.live_run(api,raw,proof)
        proof['generatedAt'] += 1400
        with self.assertRaises(auth.Blocked): auth.live_run(api,raw,proof)

    def test_prepare_requires_true_browser_transactions(self):
        raw=example_input()
        class FakeAPI:
            origin='https://launcher.example.test'
            def __init__(self): self.calls=[]
            def request(self, method, route, *, data=None, token=None):
                self.calls.append((method,route))
                if route.endswith('/auth/login'):
                    return {'data':{'user':{'id':'owner','status':'active','roleId':'owner'},
                                    'tokens':{'accessToken':'x'*40,'refreshToken':'y'*40},'provider':'local'}}
                if route.endswith('/link/begin'):
                    return {'data':{'state':'a','transaction':'encrypted-a','authorizationUrl':'https://oidc.example/auth?state=a'}}
                return {'data':{'state':'b','transaction':'encrypted-b','authorizationUrl':'https://oidc.example/auth?state=b'}}
        fake=FakeAPI()
        out=self.folder/'oidc-private.json'
        auth.prepare(fake,raw,out)
        values=auth.private_json(out)
        self.assertEqual(values['link']['code'],'')
        self.assertEqual(values['login']['code'],'')
        self.assertNotEqual(values['link']['state'],values['login']['state'])
        self.assertEqual(out.stat().st_mode & 0o777,0o600)
        with self.assertRaises(auth.Blocked): auth.prepare(fake,raw,out)

    def test_bad_real_login_response_does_not_count(self):
        class BadAPI:
            def request(self,*a,**kw):
                return {'data':{'user':{'id':'someone','roleId':'player','status':'active'},
                                'provider':'wrong-provider',
                                'tokens':{'accessToken':'x'*40, 'refreshToken':'y'*40}}}
        data=example_input()['local']
        with self.assertRaisesRegex(auth.Blocked,'Маршрутизация провайдера'):
            auth.auth_login(BadAPI(),data,'local')

    def test_negative_cli_rejects_missing_private_accounts_no_pass(self):
        err=io.StringIO()
        with contextlib.redirect_stderr(err):
            code=auth.main(['run','--secrets',str(self.folder/'absent.json'),
                            '--oidc-proof',str(self.folder/'absent-proof.json'),
                            '--output',str(self.folder/'result.json')])
        self.assertEqual(code,2)
        self.assertIn('ЗАБЛОКИРОВАНО',err.getvalue())
        self.assertFalse((self.folder/'result.json').exists())


if __name__=='__main__': unittest.main()
