"""Регрессионные и отрицательные тесты; реальные Docker и удалённые хосты НЕ имитируются как GA."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import independent_accept as ia


class IndependentAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.private = self.root / 'evidence'
        self.private.mkdir(mode=0o700)
        self.host = 'a' * 64

    def file(self, name, data=b'secret'):
        p = self.private / name
        p.write_bytes(data)
        p.chmod(0o600)
        return p

    def test_private_file_rejects_unsafe_files(self):
        private = self.file('key')
        self.assertEqual(ia.private_file(private), private)
        private.chmod(0o644)
        with self.assertRaises(ia.Rejected): ia.private_file(private)
        private.chmod(0o600)
        link = self.private / 'link'
        link.symlink_to(private)
        with self.assertRaises(ia.Rejected): ia.private_file(link)

    def test_atomic_receipt_exclusive_and_private(self):
        output = self.private / 'ok.json'
        ia.atomic_report(output, {'status': 'passed', 'schema': 1})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(output.read_text())['status'], 'passed')
        with self.assertRaises(ia.Rejected): ia.atomic_report(output, {'status': 'fake'})
        self.assertEqual(json.loads(output.read_text())['status'], 'passed')

    def test_bad_report_directory_rejected(self):
        self.private.chmod(0o755)
        with self.assertRaises(ia.Rejected): ia.atomic_report(self.private / 'no.json', {'status': 'passed'})

    def test_actor_must_differ_from_primary(self):
        with patch('independent_accept.pwd.getpwuid') as uid, \
                patch('independent_accept.os.geteuid', return_value=1000), \
                patch.dict(os.environ, {'SUDO_USER': ''}):
            uid.return_value.pw_name = 'operator2'
            self.assertEqual(ia.actor('operator1'), 'operator2')
            with self.assertRaises(ia.Rejected): ia.actor('operator2')
            with self.assertRaises(ia.Rejected): ia.actor('../admin')

    def test_root_without_sudo_operator_is_not_independent(self):
        with patch('independent_accept.os.geteuid', return_value=0), \
                patch.dict(os.environ, {'SUDO_USER': ''}):
            with self.assertRaisesRegex(ia.Rejected, 'требуется sudo'):
                ia.actor('operator1')

    def test_cannot_invoke_arbitrary_command(self):
        with self.assertRaises(ia.Rejected):
            ia.invoke([ia.sys.executable, '/bin/sh', '-c', 'echo bypass'])

    def test_command_failure_is_not_reported_as_success(self):
        completed = type('P', (), {'returncode': 1, 'stdout': b''})()
        with patch.object(ia.subprocess, 'run', return_value=completed):
            with self.assertRaises(ia.Rejected): ia.invoke([ia.sys.executable, str(ia.DR), 'verify'])

    def test_verify_receipts_is_not_one_host_fake(self):
        upgrade = {'schema': 1, 'status': 'passed', 'stage': 'upgrade-standard',
                   'machineFingerprint': self.host, 'release': ia.VERSION,
                   'secondOperator': 'operator2', 'firstOperator': 'operator1',
                   'backupManifestSha256': 'b' * 64, 'from': '0.45.13', 'to': ia.VERSION,
                   'identity': {'oldProjectId': 'smoke-project'}}
        initial = dict(upgrade, stage='install-standard', installedVersion=ia.VERSION)
        source = self.file('upgrade.json', json.dumps(upgrade).encode())
        install = self.file('install.json', json.dumps(initial).encode())
        recovery = dict(upgrade, stage='restore-standard', machineFingerprint='c' * 64,
                        sourceHostFingerprint=self.host, sourceReceiptSha256=ia.sha(source),
                        recoveredVersion='0.45.13')
        restore = self.file('restore.json', json.dumps(recovery).encode())
        fail = dict(upgrade, stage='failover-network-ha',
                    faults=sorted(['postgres-stopped', 'redis-stopped', 's3-stopped',
                                   'api-stopped', 'worker-a-network-partition']))
        chaos = self.file('chaos.json', json.dumps(fail).encode())
        args = type('Args', (), {'install_receipt': install, 'upgrade_receipt': source,
                                 'restore_receipt': restore, 'failover_receipt': chaos})()
        self.assertEqual(len(ia.accept_verify(args)['stages']), 4)
        recovery['machineFingerprint'] = self.host
        restore.write_text(json.dumps(recovery))
        with self.assertRaises(ia.Rejected): ia.accept_verify(args)
        recovery['machineFingerprint'] = 'c' * 64
        restore.write_text(json.dumps(recovery))
        source.write_text(json.dumps(dict(upgrade, backupManifestSha256='d' * 64)))
        with self.assertRaises(ia.Rejected): ia.accept_verify(args)

    def test_restore_requires_different_machine_and_matching_snapshot(self):
        receipt = {'schema': 1, 'status': 'passed', 'stage': 'upgrade-standard',
                   'machineFingerprint': self.host, 'firstOperator': 'operator1',
                   'secondOperator': 'operator2', 'from': '0.45.13',
                   'backupManifestSha256': 'a' * 64}
        source = self.file('source.json', json.dumps(receipt).encode())
        snapshot = self.private / 'backup'
        snapshot.mkdir()
        (snapshot / 'manifest.json').write_text('{}')
        args = type('Args', (), dict(project='launcher', confirm='launcher',
                  maintenance_approved=True, source_receipt=source,
                  snapshot=snapshot, primary_operator='operator1'))()
        with patch.object(ia, 'host_id', return_value=self.host):
            with self.assertRaisesRegex(ia.Rejected, 'другом Linux-узле'):
                ia.accept_restore(args)
        with patch.object(ia, 'host_id', return_value='c' * 64):
            with self.assertRaisesRegex(ia.Rejected, 'Снимок не соответствует'):
                ia.accept_restore(args)

    def test_restore_requires_explicit_maintenance(self):
        args = type('Args', (), dict(project='launcher', confirm='launcher', maintenance_approved=False))()
        with self.assertRaises(ia.Rejected): ia.accept_restore(args)

    def test_upgrade_requires_explicit_maintenance(self):
        args = type('Args', (), dict(project='launcher', confirm='launcher', maintenance_approved=False))()
        with self.assertRaises(ia.Rejected): ia.accept_upgrade(args)

    def test_failover_rejects_production_project(self):
        args = type('Args', (), dict(project='launcher', confirm='launcher'))()
        with self.assertRaisesRegex(ia.Rejected, 'изолированных'):
            ia.accept_failover(args)

    def test_install_rejects_legacy_deployment(self):
        args = type('Args', (), dict(project='launcher', env_file=self.file('.env'),
                  version=ia.VERSION, url='https://test.example', password_file=self.file('pass')) )()
        with patch.object(ia, 'checked_env'):
            (self.private / '.launcher-compose-state.json').write_text('{}')
            with self.assertRaisesRegex(ia.Rejected, 'чистая установка'):
                ia.accept_install(args)

    def test_strict_failover_report_checks_all_faults(self):
        env = self.file('.env', b'LAUNCHER_IMAGE_TAG=0.45.14')
        args = type('Args', (), dict(project='nl-dr-check', confirm='nl-dr-check',
                  env_file=env, version=ia.VERSION, url='https://127.0.0.1/ready',
                  s3_endpoint='http://127.0.0.1:19000', s3_bucket='nl-dr-test', timeout=30))()
        with patch.object(ia, 'checked_env'), patch.object(ia, 'invoke', return_value={'status': 'passed'}):
            with self.assertRaises(Exception): ia.accept_failover(args)
        # Один успешный возврат дочернего процесса не должен означать PASS.

    def test_versioned_updater_rejects_env_drift(self):
        import component_upgrade as comp
        old = self.file('before.env', b'LAUNCHER_IMAGE_TAG=0.45.13\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\nSITE=unchanged\n')
        new = self.file('after.env', b'LAUNCHER_IMAGE_TAG=0.45.14\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\nSITE=unchanged\n')
        self.assertEqual(comp.assert_same_config(old, new, source_version='0.45.13', target_version='0.45.14'), '0.45.13')
        new.write_bytes(new.read_bytes().replace(b'unchanged', b'modified'))
        with self.assertRaises(comp.ComponentError):
            comp.assert_same_config(old, new, source_version='0.45.13', target_version='0.45.14')

    def test_fresh_install_rejects_existing_volumes_and_containers(self):
        def proc(out=b'', rc=0):
            return type('Completed', (), {'returncode': rc, 'stdout': out})()
        with patch.object(ia.subprocess, 'run', side_effect=[proc(b''), proc(b'launcher_launcher_postgres\n')]):
            with self.assertRaisesRegex(ia.Rejected, 'существующая конфигурация Compose volume'):
                ia.assert_fresh_compose_project('launcher')
        with patch.object(ia.subprocess, 'run', return_value=proc(b'container-1')):
            with self.assertRaisesRegex(ia.Rejected, 'существующая конфигурация Compose container'):
                ia.assert_fresh_compose_project('launcher')
        with patch.object(ia.subprocess, 'run', return_value=proc(b'', rc=1)):
            with self.assertRaisesRegex(ia.Rejected, 'завершилась безопасным отказом'):
                ia.assert_fresh_compose_project('launcher')
        with patch.object(ia.subprocess, 'run', side_effect=[proc(), proc()]):
            ia.assert_fresh_compose_project('launcher')

    def test_real_upgrade_cli_is_invoked_with_explicit_release_versions(self):
        env1 = self.file('old.env'); env2 = self.file('new.env')
        snapshot = self.private / 'checkpoint'; snapshot.mkdir()
        (snapshot / 'manifest.json').write_text('{}')
        args = type('Args', (), dict(project='launcher', confirm='launcher',
                  maintenance_approved=True, from_version='0.45.13', to_version=ia.VERSION,
                  source_env=env1, target_env=env2, url='https://host.example',
                  snapshot=snapshot, admin_email='admin@example.org',
                  admin_password_file=self.file('admin-pass', b'long-strong-admin-password'),
                  totp_file=None, project_id='smoke-project'))()
        seen = []
        def invoke(args, **kwargs):
            seen.append(args)
            if 'standard' in args and args[1].endswith('component_upgrade.py'):
                return {'status': 'upgraded', 'from': '0.45.13', 'to': ia.VERSION, 'backendVerified': True}
            return {'status': 'verified', 'postgresArchiveChecked': True}
        with patch.object(ia, 'checked_env'), patch.object(ia, 'invoke', side_effect=invoke), \
                patch.object(ia, 'probe', return_value={'version': ia.VERSION}), \
                patch.object(ia, 'verify_old_owner', return_value={'oldProjectId': 'smoke-project'}):
            result = ia.accept_upgrade(args)
        self.assertEqual(result['from'], '0.45.13')
        self.assertIn('--from-version', seen[0])
        self.assertIn('--to-version', seen[0])
        self.assertIn('--maintenance-approved', seen[0])
        self.assertEqual(len(seen), 2)

    def test_restored_owner_actual_https_login_and_project_read(self):
        password = self.file('owner-password', b'correct-horse-battery-staple')
        responses = [
            {'token': 't' * 32, 'user': {'email': 'admin@example.org'}},
            {'email': 'admin@example.org'},
            {'version': '0.45.13', 'projects': [{'id': 'existing-project'}]},
        ]
        calls = []
        class Response:
            status = 200
            headers = {'Content-Type': 'application/json'}
            def __init__(self, body): self.body = json.dumps(body).encode()
            def __enter__(self): return self
            def __exit__(self, *unused): pass
            def read(self, maximum): return self.body
        class Opener:
            def open(self, req, timeout=15):
                calls.append(req)
                return Response(responses.pop(0))
        with patch.object(ia.urllib.request, 'build_opener', return_value=Opener()):
            result = ia.verify_old_owner('https://example.org', 'admin@example.org', password,
                                         'existing-project', '0.45.13')
        self.assertEqual(result['oldProjectRead'], 'verified')
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0].full_url, 'https://example.org/api/v1/admin/login')
        self.assertEqual(calls[1].get_header('Authorization'), 'Bearer ' + 't' * 32)
        self.assertNotIn('password', json.dumps(result).lower())
        self.assertNotIn('t' * 32, json.dumps(result))

    def test_missing_restored_project_fails_closed(self):
        pwd = self.file('pwd', b'correct-horse-battery-staple')
        data = [
            {'token': 't' * 32, 'user': {'email': 'admin@example.org'}},
            {'email': 'admin@example.org'},
            {'version': '0.45.13', 'projects': []},
        ]
        class Response:
            status = 200
            headers = {'Content-Type': 'application/json'}
            def __init__(self, payload): self.raw = json.dumps(payload).encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, n): return self.raw
        class Opener:
            def open(self, req, timeout=15): return Response(data.pop(0))
        with patch.object(ia.urllib.request, 'build_opener', return_value=Opener()):
            with self.assertRaisesRegex(ia.Rejected, 'существующий проект'):
                ia.verify_old_owner('https://example.org', 'admin@example.org', pwd, 'missing', '0.45.13')

    def test_failed_operation_does_not_create_receipt(self):
        with patch.object(ia, 'actor', return_value='operator2'), patch.object(ia, 'accept_failover', side_effect=ia.Rejected('real fault failed')):
            target = self.private / 'fail.json'
            rc = ia.main(['failover-network-ha', '--primary-operator', 'operator1',
                          '--project', 'nl-dr-check', '--confirm', 'nl-dr-check',
                          '--env-file', str(self.file('env')), '--url', 'https://127.0.0.1/ready',
                          '--s3-endpoint', 'http://127.0.0.1:19000', '--s3-bucket', 'nl-dr-test',
                          '--report', str(target)])
            self.assertEqual(rc, 1)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
