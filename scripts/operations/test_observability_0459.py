import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest import TestCase, mock
import tempfile
import unittest
import zipfile

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('obs_0459',HERE/'observability_0459.py')
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class Monitoring0459(TestCase):
    def test_https_receiver_policy(self):
        for url in ('http://example.org/hook','https://localhost/a','https://127.0.0.1/a','https://x.local/a','https://user:pass@example.org/a','https://x/a#fragment','', 'https://foo/a'):
            with self.subTest(url=url),self.assertRaises(mod.OperatorError):mod.ensure_https(url)
        self.assertEqual(mod.ensure_https('https://alerts.example.org/secret/callback'),'https://alerts.example.org/secret/callback')

    def test_atomic_private_receiver_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'alertmanager.json'
            mod.configure(argparse.Namespace(webhook_url='https://alerts.example.org/secret',output=str(path)))
            self.assertEqual(path.stat().st_mode&0o777,0o640)
            cfg=json.loads(path.read_text())
            self.assertEqual(cfg['receivers'][0]['webhook_configs'][0]['url'],'https://alerts.example.org/secret')
            path.unlink(); path.symlink_to('/etc/passwd')
            with self.assertRaises(mod.OperatorError):mod.configure(argparse.Namespace(webhook_url='https://alerts.example.org/secret',output=str(path)))

    def test_log_whitelist_does_not_leak_legacy(self):
        raw='''2026 legacy PASSWORD=not-for-public
api | {"msg":"http_request","correlation_id":"abcdef0123456789abcdef0123456789","method":"POST","route_group":"api","status":200,"Authorization":"Bearer SECRET","url":"/password/path?key=SECRET"}
nginx | {"event":"reverse_proxy_request","method":"GET","status":502,"request_id":"abcdef0123456789abcdef0123456789","ip":"SECRET"}
'''
        records=mod.sanitize_logs(raw)
        self.assertEqual(len(records),2)
        self.assertEqual(records[0]['correlation_id'],'abcdef0123456789abcdef0123456789')
        self.assertNotIn('SECRET',json.dumps(records))
        self.assertNotIn('password',json.dumps(records).lower())

    def test_no_attacker_values_in_allowed_log_fields(self):
        attacks='''{"msg":"http_request","method":"SECRET","route_group":"api","correlation_id":"SECRET","status":200,"time":"Bearer SECRET"}
'''
        self.assertNotIn('SECRET',json.dumps(mod.sanitize_logs(attacks)))
        self.assertEqual(mod.sanitize_logs('{"msg":"http_request","status":200,"method":{"authorization":"SECRET"}}')[0]['status'],200)

    def test_metric_whitelist(self):
        rows=mod.sanitize_metrics('''# TYPE anything counter
launcher_http_requests_60s 100
not_launcher_secret 100
launcher_process_heap_alloc_bytes 2048
''')
        self.assertEqual(rows,['launcher_http_requests_60s 100','launcher_process_heap_alloc_bytes 2048'])

    def test_incident_docker_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'incident.zip'
            log='''api | {"msg":"http_request","correlation_id":"abcdef0123456789abcdef0123456789","route_group":"api","status":503,"query":"password=SECRET"}
'''
            def fake_run(prefix,extra,**kw):
                if extra[:2]==['ps','--format']:
                    return json.dumps([{'Service':'api','Name':'nl-api','State':'running','Health':'healthy','Environment':'SECRET'},{'Service':'postgres','Name':'nl-postgres','State':'running'}])
                if extra[0]=='logs':return log
                return 'launcher_http_requests_60s 1\nlauncher_process_heap_alloc_bytes 200\n'
            with mock.patch.object(mod,'run_compose',side_effect=fake_run):
                mod.incident(argparse.Namespace(compose='test.yml',overlay=None,project='nl-test',since='15m',version='0.45.9',output=str(output)))
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            with zipfile.ZipFile(output) as archive:
                payload=archive.read('incident.json')
                sha=archive.read('sha256.txt').decode().split()[0]
            self.assertEqual(hashlib.sha256(payload).hexdigest(),sha)
            self.assertNotIn(b'SECRET',payload)
            obj=json.loads(payload)
            self.assertEqual(obj['system']['status'][0]['Service'],'api')
            self.assertEqual(obj['metrics']['api'],['launcher_http_requests_60s 1','launcher_process_heap_alloc_bytes 200'])
            with mock.patch.object(mod,'run_compose',side_effect=fake_run):
                with self.assertRaises(mod.OperatorError):mod.incident(argparse.Namespace(compose='test.yml',overlay=None,project='nl-test',since='15m',version='0.45.9',output=str(output)))

if __name__=='__main__':unittest.main()
