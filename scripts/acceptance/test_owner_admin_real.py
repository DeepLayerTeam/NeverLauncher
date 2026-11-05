"""Отрицательные и модульные регрессии; не доказательство работы на производственной машине или удалённой JVM."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('owner_admin_real_0523.py')
SPEC = importlib.util.spec_from_file_location('owner_admin_real_0523', PATH)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class OwnerAdminReal0523Tests(unittest.TestCase):
    def test_totp_ietf_vectors(self):
        # По RFC 6238 для SHA-1 на 59-й секунде восьмизначный код равен 94287082.
        self.assertEqual(mod.totp_now('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', at=59), '287082')
        self.assertNotEqual(mod.totp_now('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', at=59),
                            mod.totp_now('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', at=89))

    def test_never_send_credentials_to_http_origin(self):
        for url in ('http://localhost', 'https://example.test/path', 'https://user:pass@example.test',
                    'https://example.test?debug=1', 'file:///tmp/secure'):
            with self.subTest(url=url), self.assertRaises(mod.Blocked):
                mod.HTTPS(url)

    def test_http_path_validation_rejects_server_override(self):
        api = mod.HTTPS('https://example.test')
        for path in ('//other', '/admin', 'http://localhost/secret', '/api/v1/x\\evil', '/api/v1/x#y'):
            with self.subTest(path=path), self.assertRaises(mod.Blocked):
                api.request('GET', path)

    def test_private_password_rejects_symlink_and_world_readable(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'password'
            p.write_text('test-password-not-real')
            p.chmod(0o644)
            with self.assertRaisesRegex(mod.Blocked, 'Небезопасные'):
                mod.private_bytes(p)
            p.chmod(0o600)
            self.assertEqual(mod.private_bytes(p), b'test-password-not-real')
            other = Path(t) / 'alias'
            other.symlink_to(p)
            with self.assertRaisesRegex(mod.Blocked, 'обычному файлу'):
                mod.private_bytes(other)

    def test_user_data_marker_mutation_is_detectable(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'world-user.dat'
            p.write_bytes(b'uuid: aacc-0123, level: 9')
            before = mod.sha_file(p)
            p.write_bytes(b'uuid: aacc-0123, level: 999')
            self.assertNotEqual(mod.sha_file(p), before)
            p.unlink()
            with self.assertRaises(mod.Blocked):
                mod.sha_file(p)

    def test_atomic_report_is_private_and_idempotent(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / 'evidence' / 'result.json'
            mod.save_report(target, {'status': 'blocked'})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            mod.save_report(target, {'status': 'passed'})
            self.assertEqual(json.loads(target.read_text())['status'], 'passed')
            self.assertEqual(len(list(target.parent.iterdir())), 1)

    def test_compose_project_is_disposable_only(self):
        for value in ('launcher', 'prod', 'nl0523Bad', '../bad', 'nl0523abc', 'nl0523'+'a'*24):
            with self.subTest(value=value), self.assertRaises(mod.Blocked):
                mod.no_existing_project(value)

    def test_reject_fake_host_status(self):
        class Fake:
            def request(self, *args, **kwargs):
                return {'data': {'host': {'status': {'processAlive': 'yes'}},
                                 'bridge': {'serverId': 'node-test'}}}
        with self.assertRaises(mod.Blocked):
            mod.host_status(Fake(), 'node-test', 'not-real')

    def test_refuse_pass_for_fake_admin_login(self):
        class Fake:
            def request(self, *args, **kwargs):
                return {'token': 'abc', 'user': {'email': 'real@example.test'}}
        with self.assertRaisesRegex(mod.Blocked, 'входе администратора'):
            mod.login(Fake(), 'real@example.test', 'not-real')

    def test_full_runner_missing_preflight_blocks_without_docker(self):
        with tempfile.TemporaryDirectory() as t:
            report = Path(t) / 'report.json'
            cmd = [sys.executable, str(PATH), '--env', str(Path(t)/'no-env'),
                   '--email', 'owner@example.test', '--password-file', str(Path(t)/'no-password'),
                   '--server-id', 'real-server', '--bridge-registration-file', str(Path(t)/'no-key'),
                   '--world-marker', str(Path(t)/'no-world'), '--report', str(report),
                   '--isolated-destructive-acceptance']
            proc = subprocess.run(cmd, capture_output=True, timeout=15)
            self.assertNotEqual(proc.returncode, 0)
            doc = json.loads(report.read_text())
            self.assertEqual(doc['status'], 'blocked')
            self.assertFalse(doc['gaCertified'])
            self.assertEqual(doc['checks'], [])
            self.assertNotIn('not-real', json.dumps(doc))

    def test_only_dedicated_standard_may_mount_real_host_credentials(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for name in ('targets', 'ca', 'token'):
                f = root / name
                f.write_text('test-data-not-a-secret')
                f.chmod(0o600)
            env = root / '.env'
            env.write_text('LAUNCHER_COMPOSE_PROJECT=nl0523abcdefgh\n'
                           + 'LAUNCHER_0523_HOST_TARGETS_FILE=' + str(root/'targets') + '\n'
                           + 'LAUNCHER_0523_HOST_CA_FILE=' + str(root/'ca') + '\n'
                           + 'LAUNCHER_0523_HOST_TOKEN_FILE=' + str(root/'token') + '\n')
            env.chmod(0o600)
            args = mod.DEPLOY.compose_args(env, 'standard')
            self.assertIn(str(mod.ROOT/'deploy/production/docker-compose.owner-e2e-0523.yml'), args)
            self.assertIn('nl0523abcdefgh', args)
            env.write_text(env.read_text().replace('nl0523abcdefgh', 'launcher'))
            with self.assertRaisesRegex(RuntimeError, 'изолированном'):
                mod.DEPLOY.compose_args(env, 'standard')
            env.write_text(env.read_text().replace('launcher\n', 'nl0523abcdefgh\n'))
            (root/'token').chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'права доступа'):
                mod.DEPLOY.compose_args(env, 'standard')

    def test_game_console_must_receive_real_agent_ack(self):
        class RejectedGame:
            calls = 0
            def request(self, method, route, **kwargs):
                self.calls += 1
                if method == 'POST':
                    return {'data': {'command': {'id': 'command-1', 'type': 'server.console'},
                                     'idempotentReplay': False}}
                return {'data': {'command': {'status': 'rejected'}}}
        api = RejectedGame()
        with self.assertRaisesRegex(mod.Blocked, 'Команда игрового агента'):
            mod.real_game_command(api, 'real-paper', 'auth-token')
        self.assertEqual(api.calls, 2)

    def test_failed_step_is_not_recorded(self):
        checks = {'checks': []}
        with self.assertRaises(mod.Blocked):
            mod.check(checks, 'synthetic-check', lambda: mod.require(False, 'fail'))
        self.assertEqual(checks['checks'], [])


if __name__ == '__main__':
    unittest.main()
