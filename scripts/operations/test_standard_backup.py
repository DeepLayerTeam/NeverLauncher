"""Регрессия резервного копирования Standard: настоящие байты SQLite/tar и блокирующая при ошибке
оркестрация Docker.

Вызовы Docker здесь имитируются; реальное восстановление на двух внешних хостах — отдельный
сценарий. Эти тесты никогда не помечают интеграцию PostgreSQL как PASS.
"""
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import dr_03512 as dr


def coordinator_tar(target, *, invalid=False, missing=False):
    with tempfile.TemporaryDirectory() as temp:
        state = Path(temp) / 'state.db'
        connection = sqlite3.connect(state)
        connection.execute('CREATE TABLE coord_meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        connection.execute("INSERT INTO coord_meta VALUES ('version', ?)", (2 if invalid else 1,))
        connection.commit()
        connection.close()
        with tarfile.open(target, 'w:gz') as stream:
            if not missing:
                stream.add(state, arcname='./state.db')
            lock = b''
            item = tarfile.TarInfo('./state.db.owner.lock')
            item.size = len(lock)
            stream.addfile(item, io.BytesIO(lock))


def empty_tar(target):
    with tarfile.open(target, 'w:gz') as stream:
        item = tarfile.TarInfo('.')
        item.type = tarfile.DIRTYPE
        stream.addfile(item)


class StandardBackupTests(unittest.TestCase):
    def test_sqlite_coordinator_contents_are_actually_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'coordinator.tar.gz'
            coordinator_tar(path)
            dr.verify_coordinator(path)
            coordinator_tar(path, invalid=True)
            with self.assertRaisesRegex(dr.DrillError, 'incompatible schema'):
                dr.verify_coordinator(path)
            coordinator_tar(path, missing=True)
            with self.assertRaisesRegex(dr.DrillError, 'missing'):
                dr.verify_coordinator(path)

    def test_quiescence_uses_actual_postgres_sessions_and_states(self):
        with patch.object(dr, 'compose_states', return_value={
                'postgres': 'running', 'api': 'exited', 'admin': 'exited', 'nginx': 'exited'
            }), patch.object(dr, 'compose') as compose:
            compose.return_value.stdout = b'0|0/ABC123\n'
            dr.assert_quiescent('nl-dr-source', Path('/env'))
            compose.return_value.stdout = b'1|0/ABC123\n'
            with self.assertRaisesRegex(dr.DrillError, 'active client'):
                dr.assert_quiescent('nl-dr-source', Path('/env'))
        for state in ('running', 'restarting', 'paused'):
            with patch.object(dr, 'compose_states', return_value={
                    'postgres': 'running', 'api': state
                }), patch.object(dr, 'compose') as compose:
                with self.assertRaisesRegex(dr.DrillError, 'writes not fenced'):
                    dr.assert_quiescent('nl-dr-source', Path('/env'))
                compose.assert_not_called()

    def test_parse_compose_json_array_and_ndjson(self):
        with patch.object(dr, 'compose') as compose:
            for data in (
                b'[ {"Service":"postgres","State":"running"}, {"Service":"api","State":"exited"} ]',
                b'{"Service":"postgres","State":"running"}\n{"Service":"api","State":"exited"}\n',
            ):
                compose.return_value.stdout = data
                self.assertEqual(dr.compose_states('nl-dr-one', Path('/env')), {'postgres':'running','api':'exited'})
            compose.return_value.stdout = b'{"Service":"api","State":"running"}\n{"Service":"api","State":"exited"}'
            with self.assertRaisesRegex(dr.DrillError, 'duplicate'):
                dr.compose_states('nl-dr-one', Path('/env'))

    def test_cold_snapshot_dumps_postgres_and_copies_every_standard_volume(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            env = base / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.3\n')
            snapshot = base / 'snapshot'
            calls = []
            running = {'postgres':'running','api':'running','nginx':'running','admin':'exited'}

            def states(*_):
                return running.copy()

            def compose(*args, **kwargs):
                cmds = args[2:]
                calls.append(cmds)
                if cmds[0] == 'stop':
                    running[cmds[-1]] = 'exited'
                    return None
                if cmds[0] == 'up':
                    running[cmds[-1]] = 'running'
                    return None
                if cmds[0] == 'exec':
                    return type('result', (), {'stdout': b'0|0/ABC123\n'})()
                raise AssertionError('Неожиданный вызов compose: ' + str(cmds))

            def tar_backup(volume, output):
                if volume.endswith('coordinator'):
                    coordinator_tar(output)
                else:
                    empty_tar(output)

            with patch.object(dr, 'compose_states', side_effect=states), \
                 patch.object(dr, 'compose', side_effect=compose), \
                 patch.object(dr, 'compose_pg_dump', side_effect=lambda p,e,d: d.write_bytes(b'pgdump-data')), \
                 patch.object(dr, 'pg_validate'), \
                 patch.object(dr, 'docker_volume_exists', return_value=True), \
                 patch.object(dr, 'docker_tar_backup', side_effect=tar_backup):
                result = dr.snapshot('nl-dr-source', env, snapshot, 'nl-dr-source')
                self.assertEqual(result['schema'], 2)
                self.assertEqual(dr.verify_snapshot(snapshot)['schema'], 2)
            self.assertEqual(running['api'], 'running')
            self.assertEqual(running['nginx'], 'running')
            self.assertEqual(running['admin'], 'exited')  # был остановлен ранее и должен оставаться остановленным
            self.assertEqual((snapshot / 'database.dump').read_bytes(), b'pgdump-data')
            self.assertEqual(len([f for f in snapshot.iterdir() if f.name.endswith('.tar.gz')]), len(dr.STANDARD_VOLUMES))
            self.assertEqual(len([v for v in calls if v[0] == 'exec']), 2)

    def test_snapshot_fails_on_live_pg_connection_and_still_restarts_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / '.env'
            env.write_text('private\n')
            up = []
            states = {'postgres':'running', 'api':'running'}
            def compose(*args, **kwargs):
                cmds = args[2:]
                if cmds[0] == 'stop':
                    states[cmds[-1]] = 'exited'
                    return None
                if cmds[0] == 'up':
                    up.append(cmds[-1])
                    return None
                if cmds[0] == 'exec':
                    return type('result', (), {'stdout': b'2|0/ABC123\n'})()
                raise AssertionError(cmds)
            with patch.object(dr, 'compose_states', side_effect=lambda *_: states.copy()), \
                 patch.object(dr, 'compose', side_effect=compose), \
                 self.assertRaisesRegex(dr.DrillError, 'active client'):
                dr.snapshot('nl-dr-source', env, root / 'backup', 'nl-dr-source')
            self.assertEqual(up, ['api'])
            self.assertFalse((root / 'backup').exists())

    def test_restore_validates_pg_dump_before_creating_any_container(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / '.env'
            env.write_text('PRIVATE=1\n')
            manifest = {'schema': 2, 'sourceProject':'nl-dr-old', 'volumes':list(dr.STANDARD_VOLUMES), 'storage':'local-volume'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                 patch.object(dr, 'docker_volume_exists', return_value=False), \
                 patch.object(dr, 'pg_validate', side_effect=dr.DrillError('invalid PG archive')), \
                 patch.object(dr, 'compose') as compose, \
                 self.assertRaisesRegex(dr.DrillError, 'invalid PG'):
                dr.restore_fresh('nl-dr-new', env, root, 'nl-dr-new', ready_url='https://new.example/ready')
            compose.assert_not_called()


class StandardRecoveryHardeningTests(unittest.TestCase):
    def test_wal_movement_aborts_snapshot_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.3\n')
            stages = []
            def check(*args):
                stages.append('check')
                return '0/1000' if len(stages) == 1 else '0/1001'
            def fake_tar(name, dest):
                if name.endswith('coordinator'):
                    coordinator_tar(dest)
                else:
                    empty_tar(dest)
            with patch.object(dr, 'compose_states', return_value={'postgres':'running'}), \
                 patch.object(dr, 'assert_quiescent', side_effect=check), \
                 patch.object(dr, 'compose_pg_dump', side_effect=lambda p,e,d: d.write_bytes(b'pgdump')), \
                 patch.object(dr, 'pg_validate'), \
                 patch.object(dr, 'docker_volume_exists', return_value=True), \
                 patch.object(dr, 'docker_tar_backup', side_effect=fake_tar), \
                 self.assertRaisesRegex(dr.DrillError, 'WAL advanced'):
                dr.snapshot('nl-dr-test', env, root / 'backup', 'nl-dr-test')
            self.assertFalse((root / 'backup').exists())
            self.assertEqual(list(root.glob('.dr-stage-*')), [])

    def test_ready_requires_correct_version_storage_and_postgres(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, *args):
                return json.dumps({'status':'ready','version':'0.45.3','storage':'local','repository':'postgres'}).encode()
        with patch.object(dr, 'urlopen', return_value=Response()):
            self.assertTrue(dr.ready('https://launcher.example.org/ready', expected_version='0.45.3', expected_storage='local'))
            self.assertFalse(dr.ready('https://launcher.example.org/ready', expected_version='0.45.2', expected_storage='local'))
            self.assertFalse(dr.ready('https://launcher.example.org/ready', expected_version='0.45.3', expected_storage='s3'))
        for url in ('http://external.example/ready', 'https://host/other', 'https://user:secret@host/ready', 'file:///etc/passwd'):
            with self.assertRaises(dr.DrillError):
                dr.validate_ready_url(url)

    def test_restore_requires_exact_version_before_any_docker_operation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.2\n')
            manifest = {'schema':2,'sourceProject':'launcher','version':'0.45.3','volumes':list(dr.STANDARD_VOLUMES),'storage':'local-volume'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                 patch.object(dr, 'compose') as compose, \
                 self.assertRaisesRegex(dr.DrillError, 'target image version differs'):
                dr.restore_fresh('launcher', env, root, 'launcher', ready_url='https://launcher.example.org/ready', production=True, approved=True)
            compose.assert_not_called()

    def test_restoring_same_project_on_clean_replacement_host_is_not_forbidden(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.3\n')
            manifest = {'schema':2,'sourceProject':'launcher','version':'0.45.3','volumes':list(dr.STANDARD_VOLUMES),'storage':'local-volume'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                 patch.object(dr, 'docker_volume_exists', return_value=False), \
                 patch.object(dr, 'pg_validate'), \
                 patch.object(dr, 'compose_states', return_value={}), \
                 patch.object(dr, 'compose', side_effect=dr.DrillError('simulated create failed')) as compose, \
                 self.assertRaisesRegex(dr.DrillError, 'simulated create failed'):
                dr.restore_fresh('launcher', env, root, 'launcher', ready_url='https://launcher.example.org/ready', production=True, approved=True)
            self.assertTrue(compose.called)  # операция дошла до создания и не отклонена из-за совпадения имени исходного проекта

    def test_unsafe_coordinator_member_is_rejected_by_real_tar_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            tarfile_path = Path(folder) / 'coordinator.tar.gz'
            with tarfile.open(tarfile_path, 'w:gz') as archive:
                member = tarfile.TarInfo('../state.db')
                data = b'untrusted'
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(dr.DrillError, 'unsafe archive'):
                dr.verify_coordinator(tarfile_path)


class RestoredContainerReadinessTests(unittest.TestCase):
    def test_readiness_must_come_from_restored_api_container(self):
        correct = json.dumps({'status':'ready','version':'0.45.3','repository':'postgres','storage':'local'}).encode()
        with patch.object(dr, 'compose') as compose:
            compose.return_value.stdout = correct
            result = dr.check_restored_backend('launcher', Path('/env'), version='0.45.3', storage='local', timeout=2)
            self.assertEqual(result['version'], '0.45.3')
            self.assertIn('api', compose.call_args.args)
        with patch.object(dr, 'compose') as compose, \
             patch.object(dr.time, 'sleep'), patch.object(dr.time, 'monotonic', side_effect=[0, 1, 3]):
            compose.return_value.stdout = b'{"status":"ready", "version":"0.45.2", "repository":"postgres", "storage":"local"}'
            with self.assertRaisesRegex(dr.DrillError, 'restored API'):
                dr.check_restored_backend('launcher', Path('/env'), version='0.45.3', storage='local', timeout=2)


if __name__ == "__main__":
    unittest.main()
