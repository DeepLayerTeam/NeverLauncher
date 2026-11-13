"""Локальные регрессионные тесты действующего инструментария приёмки HTTP/SQLite; это НЕ промышленный E2E."""
from __future__ import annotations

from contextlib import closing
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from scripts.integration import live_upgrade as a


class LiveAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'private'
        self.root.mkdir(mode=0o700)
        self.db = []
        for kind in ('core','http','coordinator'):
            p = self.root / (kind + '.sqlite')
            with closing(sqlite3.connect(p)) as db:
                db.execute('CREATE TABLE state (id integer primary key, value text not null)')
                db.execute("INSERT INTO state(value) VALUES (?)", (kind + '-persistent',))
                db.commit()
            p.chmod(0o600)
            self.db.append(p)
        self.storage = self.root / 'blobs'
        self.storage.mkdir()
        (self.storage / 'my-object').write_bytes(b'actual-blob-body')
        self.target_storage = self.root/'target-blobs'
        self.target_storage.mkdir()
        (self.target_storage/'my-object').write_bytes(b'actual-blob-body')
        self.credentials = self.root / 'owner.json'
        self.credentials.write_text(json.dumps({'email':'owner@example.test','password':'old-password'}))
        self.credentials.chmod(0o600)
        self.server_version = '0.47.8'
        self.project_name = 'Original project'
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                req = json.loads(self.rfile.read(length))
                if self.path != '/api/v1/admin/login' or req.get('email') != 'owner@example.test' or req.get('password') != 'old-password':
                    self.send_error(401);return
                self.output({'token':'x'*32, 'user':{'id':'u-old-123','email':'owner@example.test'}})
            def do_GET(self):
                if self.path == '/api/v1/status':
                    self.output({'version':outer.server_version}); return
                if self.path == '/ready':
                    self.output({'status':'ok'});return
                if self.headers.get('Authorization') != 'Bearer ' + 'x'*32:
                    self.send_error(403);return
                if self.path.endswith('/profiles'):
                    self.output({'items':[{'id':'profile-9','name':'my-profile'}]})
                elif self.path.endswith('/channels'):
                    self.output({'items':[{'id':'stable'}]})
                elif self.path.endswith('/versions'):
                    self.output({'items':[{'version':'3.2','signed':'yes'}]})
                elif self.path.endswith('/revisions'):
                    self.output({'items':[{'revision':2}]})
                elif self.path.endswith('/export'):
                    self.output({'id':'project-123','profiles':['profile-9']})
                elif self.path.endswith('project-123'):
                    self.output({'id':'project-123','name':outer.project_name})
                else:
                    self.send_error(404)
            def output(self,doc):
                data = json.dumps(doc).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self,*args):
                return
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.args = argparse.Namespace(
            base_url='http://127.0.0.1:'+str(self.server.server_address[1]),
            owner_credentials=self.credentials,old_version='0.47.8',
            project='project-123',profile='profile-9',channel='stable',
            core_db=self.db[0],http_db=self.db[1],coordinator_db=self.db[2],
            storage=self.storage,target_storage=self.target_storage,output=self.root/'baseline.json',
            baseline=None,operator_work=None,backend_env=None)

    def baseline(self):
        x = a.capture(self.args)
        self.assertEqual(x['originalVersion'],'0.47.8')
        self.assertEqual(x['owner']['id'],'u-old-123')
        self.assertTrue(self.args.output.exists())
        return x

    def prepare_verified_cutover(self):
        self.baseline()
        self.server_version = '0.48.0'
        w = self.root / 'operator'; w.mkdir(mode=0o700)
        doc = {'completed':list(a.STAGES),'cutoverSupported':True,'writeBoundaryCrossed':True,
               'receipts':{'verify':{'verified':True,'readyForBackendCutover':True,'ownerId':'u-old-123'}}}
        f = w/'state.json'; f.write_text(json.dumps(doc)); f.chmod(0o600)
        self.args.baseline = self.args.output
        self.args.operator_work = w
        self.args.output = self.root / 'acceptance.json'
        self.args.backend_env = self.root / 'backend.env'
        self.args.backend_env.write_text('LAUNCHER_REPOSITORY_DRIVER=postgres\n');self.args.backend_env.chmod(0o600)

    def test_operator_health_check_real_owner_session_and_protected_export(self):
        # Проверяйте производственный HTTP-путь доказательств оператора на реальном локальном
        # сокете сервера. Это функциональный unit-harness, НЕ успешная PG GA.
        from scripts.operations.sqlite_pg_cutover import Operator, CutoverError
        env = self.root/'current.env'
        env.write_text('LAUNCHER_REPOSITORY_DRIVER=postgres\nLAUNCHER_DATABASE_DSN=postgres://internal/test\n')
        env.chmod(0o600)
        options = argparse.Namespace(work_dir=str(self.root/'operator'),source_env=str(env),
                 health_url=self.args.base_url+'/ready',owner_credentials=str(self.credentials),
                 owner_email='owner@example.test',project='project-123',dsn_env='LAUNCHER_POSTGRES_DSN')
        op=Operator(options)
        op.env['LAUNCHER_POSTGRES_DSN']='postgres://internal/test'
        op.state['receipts']={'verify':{'ownerId':'u-old-123'}}
        self.assertTrue(op.health_check()['ownerAuthenticated'])
        op.a.owner_credentials=''
        with self.assertRaisesRegex(CutoverError,'учётных данных'):
            op.health_check()

    def test_real_http_and_durable_sqlite_capture(self):
        self.baseline()
        for kind in ('core','http','coordinator'):
            b = self.root / (kind+'-captured.sqlite')
            self.assertTrue(b.is_file())
            a.validate_sqlite_backup(b)

    def test_old_owner_password_rejected_without_session(self):
        self.credentials.write_text(json.dumps({'email':'owner@example.test','password':'wrong'}))
        with self.assertRaises(a.AcceptanceError):
            a.capture(self.args)

    def test_source_database_tamper_rejected_post_upgrade(self):
        self.prepare_verified_cutover()
        with closing(sqlite3.connect(self.db[0])) as db:
            db.execute("UPDATE state SET value='changed'");db.commit()
        with patch.object(a, 'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'original core SQLite data changed'):
                a.verify(self.args)

    def test_same_count_blob_mutation_detected(self):
        self.prepare_verified_cutover()
        (self.storage/'my-object').write_bytes(b'changed-blob-body')
        with patch.object(a, 'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'изменилось исходное локальное хранилище'):
                a.verify(self.args)

    def test_target_blob_mutation_detected(self):
        self.prepare_verified_cutover()
        (self.target_storage/'my-object').write_bytes(b'same-size-altered')
        with patch.object(a, 'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'хранилище целевого PostgreSQL'):
                a.verify(self.args)

    def test_project_mutation_detected(self):
        self.prepare_verified_cutover()
        self.project_name='reinitialized demo'
        with patch.object(a,'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'проекта, профиля, канала'):
                a.verify(self.args)

    def test_unapproved_cutover_cannot_pass(self):
        self.prepare_verified_cutover()
        state = self.args.operator_work / 'state.json'
        x = json.loads(state.read_text());x['cutoverSupported']=False
        state.write_text(json.dumps(x))
        with patch.object(a, 'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'разрешённое переключение на PostgreSQL'):
                a.verify(self.args)

    def test_full_local_acceptance_requires_database_probe(self):
        self.prepare_verified_cutover()
        with patch.object(a, 'postgres_live_probe', side_effect=a.AcceptanceError('PG unreachable')):
            with self.assertRaisesRegex(a.AcceptanceError, 'PG unreachable'):
                a.verify(self.args)

    def test_backend_version_must_advance(self):
        self.prepare_verified_cutover()
        self.server_version='0.47.8'
        with patch.object(a,'postgres_live_probe'):
            with self.assertRaisesRegex(a.AcceptanceError, 'не работает на версии 0.48.0'):
                a.verify(self.args)

    def test_positive_local_dry_run_does_not_claim_independent_ga(self):
        self.prepare_verified_cutover()
        with patch.object(a,'postgres_live_probe'):
            doc=a.verify(self.args)
        self.assertEqual(doc['ownerLogin'],'actual-session')
        self.assertEqual(doc['apiEquivalent'],True)
        self.assertEqual(json.loads(self.args.output.read_text())['version'],'0.48.0')


if __name__ == '__main__':
    unittest.main()
