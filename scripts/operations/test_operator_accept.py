"""Real SQLite and atomic evidence tests; Compose is injected only at subprocess boundary."""
import importlib.util
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operator_accept_04513', Path(__file__).with_name('operator_accept_04513.py'))
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


class HTTPResponse:
    status = 200
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    def __init__(self, body):
        self.stream = io.BytesIO(json.dumps(body).encode())
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self, n):
        return self.stream.read(n)


class OperatorTests(unittest.TestCase):
    def test_docs_resolve(self):
        result = op.verify_docs()
        self.assertEqual(result['checkedFiles'], 7)
        self.assertGreater(result['checkedLinksAndEntrypoints'], 35)

    def test_public_readiness_rejects_bad_urls_and_mismatches(self):
        for url in ('http://launcher.example.org', 'https://a@launcher.example.org',
                    'https://launcher.example.org:444', 'https://launcher.example.org/ready?token=x',
                    'https://launcher.example.org:garbage'):
            with self.subTest(url=url), self.assertRaises(op.AcceptanceError):
                op.inspect_url(url)
        good = dict(status='ready', version='0.45.13', repository='postgres', storage='s3')
        def respond(request, timeout=15):
            self.assertEqual(request.full_url, 'https://launcher.example.org/ready')
            return HTTPResponse(good)
        self.assertEqual(op.ready('https://launcher.example.org', '0.45.13', 'postgres', 's3', opener=respond)['status'], 'ready')
        for key, bad in [('status', 'not_ready'), ('repository', 'sqlite'), ('storage', 'local'),
                         ('version', '0.45.12')]:
            payload = dict(good, **{key: bad})
            with self.subTest(key=key), self.assertRaises(op.AcceptanceError):
                op.ready('https://launcher.example.org/ready', '0.45.13', 'postgres', 's3',
                         opener=lambda request, timeout=15: HTTPResponse(payload))

    def test_env_origin_and_version_pinning(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / '.env'
            f.write_text('LAUNCHER_PUBLIC_URL=https://launcher.example.org\nLAUNCHER_DEPLOYMENT_MODE=standard\nLAUNCHER_IMAGE_TAG=0.45.13\n')
            f.chmod(0o600)
            self.assertTrue(op.operator_env(f, expected_mode='standard', expected_version='0.45.13', public_url='https://launcher.example.org/ready'))
            with self.assertRaises(op.AcceptanceError):
                op.operator_env(f, expected_mode='standard', expected_version='0.45.12', public_url='https://launcher.example.org')
            with self.assertRaises(op.AcceptanceError):
                op.operator_env(f, expected_mode='standard', expected_version='0.45.13', public_url='https://other.example.org')
            with self.assertRaises(op.AcceptanceError):
                op.operator_env(f, expected_mode='network-ha', expected_version='0.45.13', public_url='https://launcher.example.org')

    def test_compose_strict_states(self):
        entries = [{'Service': name, 'State': 'running', 'Health': 'healthy'}
                   for name in op.CHECKS['standard']]
        parsed = op.parse_ps(json.dumps(entries).encode())
        self.assertEqual(len(parsed), 4)
        with tempfile.TemporaryDirectory() as temporary:
            env = Path(temporary) / '.env'
            env.write_text('LAUNCHER_PUBLIC_URL=https://launcher.example.org\nLAUNCHER_DEPLOYMENT_MODE=standard\nLAUNCHER_IMAGE_TAG=0.45.13\n')
            env.chmod(0o600)
            with patch.object(op, 'run', return_value=json.dumps(entries).encode()):
                actual = op.probe_compose('launcher', env, 'standard')
                self.assertEqual(len(actual), 4)
            with patch.object(op, 'run', return_value=json.dumps(entries[:3]).encode()):
                with self.assertRaises(op.AcceptanceError):
                    op.probe_compose('launcher', env, 'standard')
            env.chmod(0o644)
            with self.assertRaises(op.AcceptanceError):
                op.probe_compose('launcher', env, 'standard')
        with self.assertRaises(op.AcceptanceError):
            op.parse_ps(json.dumps(entries + entries).encode())

    def test_ha_direct_worker_checks(self):
        entries = [{'Service': name, 'State': 'running', 'Health': 'healthy'}
                   for name in op.CHECKS['network-ha']]
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / '.env'
            env.write_text('LAUNCHER_PUBLIC_URL=https://launcher.example.org\nLAUNCHER_DEPLOYMENT_MODE=network-ha\nLAUNCHER_IMAGE_TAG=0.45.13\n')
            env.chmod(0o600)
            def real_like(args, timeout=30):
                if args[-4:] == ['ps', '--all', '--format', 'json']:
                    return json.dumps(entries).encode()
                return json.dumps({'status': 'ready', 'repository': 'postgres', 'storage': 's3'}).encode()
            with patch.object(op, 'run', side_effect=real_like) as mock:
                result = op.probe_compose('launcher', env, 'network-ha')
                self.assertEqual(len(result), 8)
                self.assertEqual(mock.call_count, 5)
            def failed_worker(args, timeout=30):
                if args[-4:] == ['ps', '--all', '--format', 'json']:
                    return json.dumps(entries).encode()
                payload = {'status': 'not_ready' if 'worker-b' in args else 'ready',
                           'repository': 'postgres', 'storage': 's3'}
                return json.dumps(payload).encode()
            with patch.object(op, 'run', side_effect=failed_worker), self.assertRaises(op.AcceptanceError):
                op.probe_compose('launcher', env, 'network-ha')

    def make_minimal(self, root):
        (root / 'config').mkdir()
        env = root / 'config/backend.env'
        env.write_text('LAUNCHER_PUBLIC_URL=https://launcher.example.org\n'
                       'LAUNCHER_DEPLOYMENT_MODE=single-node\n'
                       f'LAUNCHER_DATABASE_DSN={root / "db/http.sqlite"}\n'
                       f'LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH={root / "db/coordinator.sqlite"}\n'
                       f'LAUNCHER_STORAGE_LOCAL_PATH={root / "storage"}\n')
        env.chmod(0o600)
        (root / 'db').mkdir()
        for name in ('http.sqlite', 'coordinator.sqlite'):
            with sqlite3.connect(root / 'db' / name) as connection:
                connection.execute('CREATE TABLE data(id INTEGER PRIMARY KEY, value TEXT)')
                connection.execute('INSERT INTO data(value) VALUES (?)', ('persisted',))
        for name in ('storage', 'factory', 'extensions', 'backups'):
            (root / name).mkdir()

    def test_minimal_root_binding_cannot_accept_unrelated_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_minimal(root)
            env = root / 'config/backend.env'
            contents = env.read_text().replace(str(root / 'db/http.sqlite'), '/tmp/other.sqlite')
            env.write_text(contents)
            report = root / 'acceptance.json'
            self.assertEqual(op.main(['live', '--mode', 'minimal', '--minimal-root', str(root),
                                      '--url', 'https://launcher.example.org', '--report', str(report)]), 1)
            self.assertFalse(report.exists())

    def test_real_sqlite_checks_and_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_minimal(root)
            result = op.probe_minimal(root)
            self.assertEqual(result['http.sqlite'], 'integrity + foreign keys ok')
            self.assertEqual(result['coordinator.sqlite'], 'integrity + foreign keys ok')
            (root / 'db/coordinator.sqlite').write_bytes(b'bad database')
            with self.assertRaises((op.AcceptanceError, sqlite3.Error)):
                op.probe_minimal(root)

    def test_report_is_atomic_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / 'out.json'
            op.atomic_report(report, {'status': 'passed', 'checks': {'api': 'ready'}})
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertEqual(json.loads(report.read_text())['status'], 'passed')
            with self.assertRaises(op.AcceptanceError):
                op.atomic_report(report, {'status': 'failed'})
            self.assertEqual(json.loads(report.read_text())['status'], 'passed')

    def test_integration_minimal_failure_does_not_create_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'minimal'
            root.mkdir()
            self.make_minimal(root)
            report = Path(temporary) / 'acceptance.json'
            fake = dict(status='ready', version='0.45.13', repository='sqlite', storage='local')
            with patch.object(op, 'ready', side_effect=op.AcceptanceError('backend not ready')):
                self.assertEqual(op.main(['live', '--mode', 'minimal', '--minimal-root', str(root),
                                          '--url', 'https://launcher.example.org', '--report', str(report)]), 1)
            self.assertFalse(report.exists())
            with patch.object(op, 'ready', return_value=fake):
                self.assertEqual(op.main(['live', '--mode', 'minimal', '--minimal-root', str(root),
                                          '--url', 'https://launcher.example.org', '--report', str(report)]), 0)
            self.assertTrue(report.is_file())
            self.assertEqual(json.loads(report.read_text())['status'], 'passed')


if __name__ == '__main__':
    unittest.main()
