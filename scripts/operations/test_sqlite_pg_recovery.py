"""0.47.7: проверки инъекции отказов в настоящем автономном операторском коде.

Для резервирования/целостности/отката используются SQLite-файлы, а не имитация в памяти. Сбои PG
внедряются на границе подпроцесса; интеграция PostgreSQL требует отдельного окружения Go +
SQLRepository и здесь не утверждается.
"""
from __future__ import annotations

import importlib.util
from contextlib import closing
import json
from pathlib import Path
import os
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).with_name('sqlite_pg_cutover_0475.py')
spec = importlib.util.spec_from_file_location('cutover_0477', MODULE)
opmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(opmod)


class FailureRecovery0477(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.work = self.root / 'operator'
        self.env = self.root / 'backend.env'
        self.core = self.root / 'core.sqlite'
        self.http = self.root / 'http.sqlite'
        self.coord = self.root / 'coordinator.sqlite'
        self.source = self.root / 'local-original'
        self.target = self.root / 'local-postgres'
        self.source.mkdir()
        self.target.mkdir()
        self.env.write_text(f'LAUNCHER_REPOSITORY_DRIVER=sqlite\nLAUNCHER_DATABASE_DSN={self.http}\n')
        self.env.chmod(0o600)
        for f in (self.core, self.http, self.coord):
            with closing(sqlite3.connect(f)) as db:
                db.execute('CREATE TABLE identity (id TEXT PRIMARY KEY, value BLOB NOT NULL)')
                db.execute('INSERT INTO identity VALUES (?, ?)', ('stable-project-id', b'kept'))
                db.commit()
            f.chmod(0o600)
        args = opmod.argparse.Namespace(
            work_dir=str(self.work), launcher_sqlite='launcher-sqlite',
            source_env=str(self.env), core_db=str(self.core), http_db=str(self.http),
            coordinator_db=str(self.coord), storage_source=str(self.source),
            storage_target=str(self.target), units=['launcher-api.service', 'launcher-bridge.service'],
            project='stable-project-id', owner_email='owner@example.test',
            dsn_env='LAUNCHER_POSTGRES_DSN', mfa_key_file='', pg_secret_env='',
            health_url='http://127.0.0.1:8080/ready')
        self.op = opmod.Operator(args)
        self.op.env[args.dsn_env] = 'postgres://127.0.0.1/neverlauncher_test'
        self.op.init_workdir()

    def original(self):
        with closing(sqlite3.connect(self.core)) as db:
            return db.execute('SELECT value FROM identity WHERE id=?', ('stable-project-id',)).fetchone()[0]

    def rollback_ready(self):
        self.op.state['completed'] = ['preflight', 'backup', 'freeze']
        opmod.write_secure(self.op.original_env, self.env.read_bytes())
        self.op.save()

    def test_preflight_fails_without_disk_reserve_and_never_stops_units(self):
        fake = mock.Mock(f_bavail=1, f_frsize=4096)
        with mock.patch.object(opmod.os, 'statvfs', return_value=fake):
            with self.assertRaisesRegex(opmod.CutoverError, 'insufficient disk space'):
                self.op.preflight()
        self.assertEqual(self.op.state['completed'], [])
        self.assertEqual(self.original(), b'kept')

    def test_real_sqlite_online_backup_corruption_is_rejected(self):
        backup = self.root / 'backup.sqlite'
        opmod.sqlite_backup(str(self.core), backup)
        self.assertEqual(self.original(), b'kept')
        backup.write_bytes(b'corrupted backup page')
        with self.assertRaises(sqlite3.DatabaseError):
            opmod.validate_sqlite_backup(backup)

    def test_interrupted_frozen_backup_cannot_be_reused(self):
        self.op.http_backup.write_bytes(b'partial sqlite copy')
        self.op.http_backup.chmod(0o600)
        with mock.patch.object(self.op, 'inactive'):
            with self.assertRaisesRegex(opmod.CutoverError, 'incomplete frozen backup'):
                self.op.frozen_backup()
        self.assertEqual(self.op.http_backup.read_bytes(), b'partial sqlite copy')

    def test_partial_frozen_backup_does_not_prevent_source_recovery(self):
        self.rollback_ready()
        self.op.http_backup.write_bytes(b'partial backup after ENOSPC')
        self.op.http_backup.chmod(0o600)
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(self.op, 'service', return_value=(0, b'')):
            restored = self.op.rollback()
        self.assertTrue(restored['sourceDatabaseUntouched'])
        self.assertEqual(self.original(), b'kept')
        self.assertEqual(self.op.http_backup.read_bytes(), b'partial backup after ENOSPC')

    def test_wal_footprint_included_in_estimate(self):
        fake = Path(str(self.core) + '-wal')
        fake.write_bytes(b'x' * 8192)
        self.assertGreaterEqual(opmod.sqlite_size_on_disk(self.core), self.core.stat().st_size + 8192)

    def test_pg_lost_during_import_must_not_retry_automatically(self):
        self.op.state['sourceEnvSHA256'] = opmod.sha256_file(self.env)
        self.op.save()
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'run_cmd', side_effect=opmod.CutoverError('PostgreSQL connection lost')):
            with self.assertRaisesRegex(opmod.CutoverError, 'connection lost'):
                self.op.importing()
        resumed = opmod.Operator(self.op.a)
        resumed.init_workdir()
        self.assertTrue(resumed.state['importOutcomeUnknown'])
        with self.assertRaisesRegex(opmod.CutoverError, 'outcome unknown'):
            resumed.run()
        self.assertEqual(self.original(), b'kept')

    def test_unique_id_conflict_is_not_claimed_as_success(self):
        self.op.state['sourceEnvSHA256'] = opmod.sha256_file(self.env)
        for problem in ('duplicate key value violates unique constraint', 'SQLite MFA key mismatch'):
            with self.subTest(problem=problem):
                with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'run_cmd', side_effect=opmod.CutoverError(problem)):
                    with self.assertRaises(opmod.CutoverError):
                        self.op.importing()
                self.assertTrue(self.op.state['importOutcomeUnknown'])
                self.assertNotIn('import', self.op.state['completed'])
                self.assertEqual(self.original(), b'kept')

    def test_source_file_content_change_same_size_blocks_receipt(self):
        blob = self.source / 'data.bin'
        blob.write_bytes(b'AAAA')
        def corrupted(_args, **_kw):
            blob.write_bytes(b'BBBB')
            return {'verified': True, 'sourceSha256': 'a' * 64,
                    'checked': 1, 'catalogSha256': 'b' * 64}
        self.op.state['sourceSHA256'] = 'a' * 64
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'run_cmd', side_effect=corrupted):
            with self.assertRaisesRegex(opmod.CutoverError, 'source blobs changed'):
                self.op.files()
        self.assertNotIn('copy_files', self.op.state.get('receipts', {}))

    def test_missing_file_catalog_digest_blocks_receipt(self):
        (self.source / 'data.bin').write_bytes(b'AAAA')
        self.op.state['sourceSHA256'] = 'a' * 64
        receipt = {'verified': True, 'sourceSha256': 'a' * 64, 'checked': 1}
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'run_cmd', return_value=receipt):
            with self.assertRaisesRegex(opmod.CutoverError, 'catalog digest'):
                self.op.files()

    def test_space_failure_prevents_copy_start(self):
        (self.source / 'data.bin').write_bytes(b'A' * 32)
        spy = mock.Mock()
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'run_cmd', spy), mock.patch.object(opmod, 'enough_space', side_effect=opmod.CutoverError('insufficient disk space')):
            with self.assertRaisesRegex(opmod.CutoverError, 'disk space'):
                self.op.files()
        spy.assert_not_called()

    def test_symlink_blob_rejected_before_copy(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'secret')
        (self.source / 'link').symlink_to(outside)
        with self.assertRaisesRegex(opmod.CutoverError, 'non-directory or symlink|unsafe source'):
            opmod.storage_fingerprint(self.source)

    def test_hardlinked_blob_rejected_before_copy(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'secret')
        os.link(outside, self.source / 'shared')
        with self.assertRaisesRegex(opmod.CutoverError, 'link or special'):
            opmod.storage_fingerprint(self.source)

    def test_out_of_order_persisted_stages_rejected(self):
        self.op.state['completed'] = ['preflight', 'import']
        self.op.save()
        with self.assertRaisesRegex(opmod.CutoverError, 'out-of-order'):
            opmod.Operator(self.op.a).init_workdir()

    def test_receipt_without_completed_stage_rejected(self):
        self.op.state['receipts'] = {'verify': {'verified': True}}
        self.op.save()
        with self.assertRaisesRegex(opmod.CutoverError, 'uncommitted'):
            opmod.Operator(self.op.a).init_workdir()

    def test_precutover_rollback_recovers_both_services_and_data(self):
        self.rollback_ready()
        opmod.change_env(self.env, 'postgres://db/test', 'postgres', str(self.target))
        calls = []
        def service(cmd, unit):
            calls.append((cmd, unit))
            return (0, b'')
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(self.op, 'service', side_effect=service):
            result = self.op.rollback()
        self.assertTrue(result['sourceDatabaseUntouched'])
        self.assertEqual(self.original(), b'kept')
        self.assertEqual(opmod.parse_env(self.env)['LAUNCHER_REPOSITORY_DRIVER'], 'sqlite')
        self.assertEqual([u for cmd, u in calls if cmd == 'start'], self.op.a.units)

    def test_rollback_service_start_failure_does_not_claim_success(self):
        self.rollback_ready()
        def service(cmd, unit):
            if cmd == 'start' and unit == self.op.a.units[1]:
                return (1, b'')
            return (0, b'')
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(self.op, 'service', side_effect=service) as called:
            with self.assertRaisesRegex(opmod.CutoverError, 'services stopped'):
                self.op.rollback()
        self.assertFalse(self.op.state.get('rolledBack'))
        self.assertEqual(len([args for args, _ in called.call_args_list if args[0] == 'stop']), 2)

    def test_corrupted_sqlite_source_blocks_rollback_before_config_rewrite(self):
        self.rollback_ready()
        opmod.change_env(self.env, 'postgres://db/test', 'postgres', str(self.target))
        self.http.write_bytes(b'corrupt SQLite')
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(self.op, 'service', return_value=(0, b'')):
            with self.assertRaises(sqlite3.DatabaseError):
                self.op.rollback()
        self.assertEqual(opmod.parse_env(self.env)['LAUNCHER_REPOSITORY_DRIVER'], 'postgres')
        self.assertFalse(self.op.state.get('rolledBack'))

    def test_write_boundary_durable_before_config_rewrite_even_on_crash(self):
        self.op.state['completed'] = list(opmod.STAGES[:7])
        self.op.state['cutoverSupported'] = True
        self.op.state['receipts'] = {'verify': {'readyForBackendCutover': True}}
        self.op.save()
        def killed(*_a, **_kw):
            # Представляет прерывание процесса во время атомарной записи env.
            state = json.loads(self.op.state_path.read_text())
            self.assertTrue(state['writeBoundaryCrossed'])
            raise OSError('Искусственно вызванный сбой при переключении')
        with mock.patch.object(self.op, 'inactive'), mock.patch.object(opmod, 'change_env', side_effect=killed):
            with self.assertRaisesRegex(OSError, 'Искусственно вызванный сбой при переключении'):
                self.op.cutover()
        with self.assertRaisesRegex(opmod.CutoverError, 'automatic rollback forbidden'):
            opmod.Operator(self.op.a).rollback()
        self.assertEqual(self.original(), b'kept')

    def test_post_cutover_fault_stops_writers_without_rollback(self):
        self.op.state['completed'] = list(opmod.STAGES[:7])
        self.op.state['writeBoundaryCrossed'] = True
        self.op.save()
        stops = []
        def service(cmd, unit):
            stops.append((cmd, unit))
            return (1, b'inactive') if cmd == 'is-active' else (0, b'')
        with mock.patch.object(self.op, 'service', side_effect=service):
            with self.assertRaisesRegex(opmod.CutoverError, 'automatic rollback forbidden|unsafe'):
                self.op.run()
        # Успешное переключение не объявляется; все возможные записывающие процессы
        # PostgreSQL остановлены.
        self.assertNotIn('health_check', self.op.state['completed'])
        self.assertEqual([u for cmd, u in stops if cmd == 'stop'], self.op.a.units)


if __name__ == '__main__':
    unittest.main()
