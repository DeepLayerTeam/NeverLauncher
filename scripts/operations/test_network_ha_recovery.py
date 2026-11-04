"""Real filesystem recovery tests; Docker/PostgreSQL orchestration uses controlled doubles.
Live two-host PostgreSQL, S3, JVM and ServerBridge runs require the HA acceptance runner.
"""
import hashlib
import io
import json
import os
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import dr_03512 as dr


def make_world(root: Path, name='paper') -> Path:
    ident = 'a' * 32
    backup = root / name / ident
    (backup / 'payload' / 'world' / 'region').mkdir(parents=True)
    (backup / 'payload' / 'world' / 'region' / 'r.0.0.mca').write_bytes(b'actual Minecraft region bytes')
    (backup / 'payload' / 'server.properties').write_text('level-name=world\n')
    entries = [
        {'path': 'server.properties', 'type': 'file', 'mode': 0o600, 'size': 17,
         'sha256': dr.sha256_file(backup / 'payload' / 'server.properties')},
        {'path': 'world', 'type': 'dir', 'mode': 0o700},
        {'path': 'world/region', 'type': 'dir', 'mode': 0o700},
        {'path': 'world/region/r.0.0.mca', 'type': 'file', 'mode': 0o600,
         'size': 29, 'sha256': dr.sha256_file(backup / 'payload' / 'world' / 'region' / 'r.0.0.mca')},
    ]
    for e in entries:
        if e['type'] == 'file':
            e['size'] = (backup / 'payload' / e['path']).stat().st_size
    manifest = {'schema': 'launcher-world-backup/v1', 'id': ident, 'consistency': 'confirmed-stopped',
                'worlds': ['world'], 'entries': entries,
                'totalBytes': sum(e['size'] for e in entries if e['type'] == 'file')}
    (backup / 'manifest.json').write_text(json.dumps(manifest))
    return backup


class WorldRestore0454Tests(unittest.TestCase):
    def test_copies_actual_world_bytes_and_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            original = make_world(base / 'source')
            stage = base / 'snapshot'
            stage.mkdir()
            receipts = dr.archive_world_backups(stage, {'paper': original})
            dr.validate_world_receipts(stage, receipts)
            targets = {'paper': base / 'restored-paper'}
            dr.validate_world_destinations(receipts, targets, stage)
            dr.restore_world_backup(stage / 'worlds' / 'paper' / original.name, targets['paper'])
            self.assertEqual((targets['paper'] / 'world' / 'region' / 'r.0.0.mca').read_bytes(),
                             b'actual Minecraft region bytes')
            self.assertEqual((targets['paper'] / 'server.properties').read_text(), 'level-name=world\n')
            self.assertFalse(list(base.glob('.world-restore-*')))
            with self.assertRaisesRegex(dr.DrillError, 'exists'):
                dr.validate_world_destinations(receipts, targets, stage)

    def test_integrity_rejects_corruption_missing_extra_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = make_world(Path(tmp))
            world_file = backup / 'payload/world/region/r.0.0.mca'
            world_file.write_bytes(b'altered')
            with self.assertRaisesRegex(dr.DrillError, 'checksum'):
                dr.safe_world_backup(backup)
            world_file.write_bytes(b'actual Minecraft region bytes')
            (backup / 'payload/world/extra').write_bytes(b'rogue')
            with self.assertRaisesRegex(dr.DrillError, 'unexpected'):
                dr.safe_world_backup(backup)
            (backup / 'payload/world/extra').unlink()
            world_file.unlink()
            world_file.symlink_to('/etc/hosts')
            with self.assertRaisesRegex(dr.DrillError, 'unsafe'):
                dr.safe_world_backup(backup)

    def test_missing_world_dir_and_unconfirmed_stop_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = make_world(Path(tmp))
            path = backup / 'manifest.json'
            info = json.loads(path.read_text())
            info['consistency'] = 'running'
            path.write_text(json.dumps(info))
            with self.assertRaisesRegex(dr.DrillError, 'unsupported'):
                dr.safe_world_backup(backup)
            info['consistency'] = 'confirmed-stopped'
            info['entries'] = [e for e in info['entries'] if e['path'] != 'world']
            path.write_text(json.dumps(info))
            with self.assertRaisesRegex(dr.DrillError, 'directory'):
                dr.safe_world_backup(backup)

    def test_world_restore_cannot_escape_to_snapshot_or_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            stage = base / 'snap'
            stage.mkdir()
            receipts = dr.archive_world_backups(stage, {'a': make_world(base / 'source', 'a')})
            for dest in [stage / 'foo', base / 'source', base / 'no-such-directory' / 'foo']:
                with self.assertRaises(dr.DrillError):
                    dr.validate_world_destinations(receipts, {'a': dest}, stage)
            with self.assertRaisesRegex(dr.DrillError, 'each captured'):
                dr.validate_world_destinations(receipts, {}, stage)

    @unittest.skipUnless(os.environ.get('NL_WORLD_CLI'), 'set NL_WORLD_CLI to a real built Go launcher binary')
    def test_native_go_cli_world_backup_is_consumed_and_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            server = base / 'server'
            (server / 'world' / 'region').mkdir(parents=True)
            (server / 'server.properties').write_text('level-name=world\n')
            (server / 'world' / 'region' / 'r.0.0.mca').write_bytes(b'real Go CLI snapshot bytes')
            destination = base / 'source-world-backups'
            subprocess.run([os.environ['NL_WORLD_CLI'], 'server-bridge', 'host', 'world-backup', 'create',
                            '--server-root', str(server), '--backup-root', str(destination), '--consistency', 'stopped'],
                           check=True, stdout=subprocess.DEVNULL, timeout=30)
            backups = [p for p in destination.iterdir() if p.is_dir()]
            self.assertEqual(len(backups), 1)
            stage = base / 'dr'
            stage.mkdir()
            receipts = dr.archive_world_backups(stage, {'paper': backups[0]})
            dr.validate_world_receipts(stage, receipts)
            target = base / 'new-game-root'
            dr.restore_world_backup(stage / 'worlds/paper' / backups[0].name, target)
            self.assertEqual((target / 'world/region/r.0.0.mca').read_bytes(), b'real Go CLI snapshot bytes')

    def test_duplicate_and_relative_paths_rejected(self):
        with self.assertRaises(dr.DrillError):
            dr.parse_world_args(['bad name=/tmp/a'])
        with self.assertRaises(dr.DrillError):
            dr.parse_world_args(['paper=/tmp/a', 'paper=/tmp/b'])
        with self.assertRaises(dr.DrillError):
            dr.parse_world_args(['paper=relative'])


class NetworkHA0454Tests(unittest.TestCase):
    def setUp(self):
        self.original = list(dr.COMPOSE_PROFILES)
        dr.COMPOSE_PROFILES[:] = ['network-ha']

    def tearDown(self):
        dr.COMPOSE_PROFILES[:] = self.original

    def test_redis_not_restored_into_new_cluster(self):
        self.assertNotIn('launcher_redis', dr.required_volumes())
        with patch.object(dr, 'docker_volume_exists', return_value=True), patch.object(dr, 'run') as runner:
            dr.ensure_empty_redis_volume('launcher')
            cmd = runner.call_args.args[0]
            self.assertIn('--network', cmd)
            self.assertIn('readonly', ' '.join(cmd))
        with patch.object(dr, 'docker_volume_exists', return_value=False), self.assertRaises(dr.DrillError):
            dr.ensure_empty_redis_volume('launcher')

    def test_network_ha_backup_captures_verified_world_s3_and_no_redis_aof(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env = base / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            source = make_world(base / 'source')
            target = base / 'backed-up'
            s3_reads = []
            def fake_tar(volume, path):
                with tarfile.open(path, 'w:gz') as archive:
                    entry = tarfile.TarInfo('./')
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
            def fake_s3(bucket, path, endpoint):
                s3_reads.append(path)
                path.mkdir()
                (path / 'objects.bin').write_bytes(b'real object bytes')
            with patch.object(dr, 'compose_states', return_value={'postgres':'running'}), \
                    patch.object(dr, 'assert_quiescent', return_value='0/ABC'), \
                    patch.object(dr, 'compose_pg_dump', side_effect=lambda p,e,d:d.write_bytes(b'pgdump')), \
                    patch.object(dr, 'pg_validate'), \
                    patch.object(dr, 'docker_volume_exists', return_value=True), \
                    patch.object(dr, 'docker_tar_backup', side_effect=fake_tar), \
                    patch.object(dr, 's3_download', side_effect=fake_s3):
                result = dr.snapshot('launcher', env, target, 'launcher',
                         'launcher-source', production=True, approved=True,
                         world_backups={'paper':source})
            self.assertEqual(len(s3_reads), 2)
            self.assertEqual(result['schema'], 3)
            self.assertEqual(result['redis'], 'fresh-ephemeral-not-restored')
            self.assertFalse((target / 'launcher_redis.tar.gz').exists())
            self.assertEqual(len(result['worlds']), 1)
            self.assertEqual(dr.verify_snapshot(target)['schema'], 3)
            self.assertEqual((target / 's3-objects' / 'objects.bin').read_bytes(), b'real object bytes')

    def test_s3_mutation_during_backup_refuses_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env = base / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            source = make_world(base / 'source')
            dst = base / 'backed-up'
            calls = []
            def fake_tar(volume, path):
                with tarfile.open(path, 'w:gz') as archive:
                    entry = tarfile.TarInfo('./')
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
            def fake_s3(bucket, path, endpoint):
                calls.append(path)
                path.mkdir()
                (path / 'objects.bin').write_bytes(b'initial' if len(calls) == 1 else b'changed')
            with patch.object(dr, 'compose_states', return_value={'postgres':'running'}), \
                    patch.object(dr, 'assert_quiescent', return_value='0/ABC'), \
                    patch.object(dr, 'compose_pg_dump', side_effect=lambda p,e,d:d.write_bytes(b'pgdump')), \
                    patch.object(dr, 'pg_validate'), \
                    patch.object(dr, 'docker_volume_exists', return_value=True), \
                    patch.object(dr, 'docker_tar_backup', side_effect=fake_tar), \
                    patch.object(dr, 's3_download', side_effect=fake_s3), \
                    self.assertRaisesRegex(dr.DrillError, 'S3 objects changed'):
                dr.snapshot('launcher', env, dst, 'launcher',
                         'launcher-source', production=True, approved=True,
                         world_backups={'paper':source})
            self.assertFalse(dst.exists())
            self.assertEqual(list(base.glob('.dr-stage-*')), [])

    def test_fencing_sql_expires_commands_and_rotates_runtime_epoch(self):
        sql = dr.FENCE_SQL_0454
        for marker in ('BEGIN;', 'COMMIT;', "status='indeterminate'", "status='credential-rotation-required'",
                       'runtime_epoch=runtime_epoch+1', "status='invalidated'", 'lease_fence=lease_fence+1',
                       'fencing_token=fencing_token+1'):
            self.assertIn(marker, sql)
        with patch.object(dr, 'compose') as compose:
            compose.return_value.stdout = b'UPDATE 1\n0|0|0|0|0|0|0|0|0|0\n'
            dr.fence_restored_serverbridge('launcher', Path('/env'))
            kwargs = compose.call_args.kwargs
            self.assertIn(b'BEGIN;', kwargs['stdin'].getvalue())
        with patch.object(dr, 'compose') as compose:
            compose.return_value.stdout = b'0|0|1|0|0|0|0|0|0|0\n'
            with self.assertRaisesRegex(dr.DrillError, 'readback'):
                dr.fence_restored_serverbridge('launcher', Path('/env'))

    def test_network_ha_legacy_snapshot_is_rejected_before_compose_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            manifest = {'schema':2, 'sourceProject':'launcher', 'version':'0.45.4',
                        'volumes':list(dr.VOLUMES), 'storage':'s3-objects'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), patch.object(dr, 'compose') as compose, \
                    self.assertRaisesRegex(dr.DrillError, 'legacy Redis-bearing'):
                dr.restore_fresh('launcher', env, root, 'launcher', ready_url='https://launcher.example.org/ready',
                                 production=True, approved=True)
            compose.assert_not_called()

    def test_snapshot_rejects_missing_worlds_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            with patch.object(dr, 'compose_states') as states, self.assertRaisesRegex(dr.DrillError, 'world'):
                dr.snapshot('launcher', env, Path(tmp)/'backup', 'launcher', 'bucket-name',
                            production=True, approved=True)
            states.assert_not_called()

    def test_full_restore_fences_database_and_restores_world_before_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            source = make_world(root / 'source')
            folder = root / 'snapshot'
            folder.mkdir()
            receipts = dr.archive_world_backups(folder, {'paper': source})
            dest = root / 'new-world'
            manifest = {'schema':3, 'version':'0.45.4', 'sourceProject':'old',
                        'volumes':list(dr.STANDARD_VOLUMES), 'storage':'s3-objects',
                        's3SourceBucket':'source-bucket', 's3Files':{}, 'worlds':receipts}
            events = []
            checks = {'count':0}
            def exists(*args):
                checks['count'] += 1
                return checks['count'] > 5
            def fake_compose(*args, **kwargs):
                events.append(args[-3:])
                return MagicMock(stdout=b'')
            def fake_fence(*args):
                events.append('fenced')
            real_restore = dr.restore_world_backup
            def fake_world(src, out):
                events.append('world')
                real_restore(src, out)
            def fake_ready(*args, **kwargs):
                events.append('ready')
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                    patch.object(dr, 'docker_volume_exists', side_effect=exists), \
                    patch.object(dr, 'compose_states', return_value={}), \
                    patch.object(dr, 'pg_validate'), \
                    patch.object(dr, 'compose', side_effect=fake_compose), \
                    patch.object(dr, 'docker_tar_restore'), \
                    patch.object(dr, 'compose_pg_restore'), \
                    patch.object(dr, 'ensure_empty_redis_volume', side_effect=lambda *a:events.append('fresh-redis')), \
                    patch.object(dr, 'fence_restored_serverbridge', side_effect=fake_fence), \
                    patch.object(dr, 'restore_world_backup', side_effect=fake_world), \
                    patch.object(dr, 's3_list_first', return_value=False), \
                    patch.object(dr, 's3_upload_fresh'), \
                    patch.object(dr, 'check_restored_backend', side_effect=fake_ready), \
                    patch.object(dr, 'await_readiness'):
                result = dr.restore_fresh('launcher', env, folder, 'launcher',
                       ready_url='https://launcher.example.org/ready', target_s3_bucket='new-bucket',
                       production=True, approved=True, world_destinations={'paper':dest})
            self.assertTrue(result['serverbridgeFenced'])
            self.assertFalse(result['redisRestored'])
            self.assertEqual((dest / 'world/region/r.0.0.mca').read_bytes(), b'actual Minecraft region bytes')
            idx = events.index('fenced')
            self.assertLess(idx, events.index('world'))
            self.assertLess(events.index('world'), events.index('ready'))
            self.assertLess(events.index('fresh-redis'), idx)

    def test_fence_failure_never_starts_api_or_publishes_world(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.env'
            env.write_text('LAUNCHER_IMAGE_TAG=0.45.4\n')
            source = make_world(root / 'source')
            folder = root / 'snapshot'
            folder.mkdir()
            receipts = dr.archive_world_backups(folder, {'paper': source})
            dest = root / 'new-world'
            manifest = {'schema':3, 'version':'0.45.4', 'sourceProject':'old',
                        'volumes':list(dr.STANDARD_VOLUMES), 'storage':'s3-objects',
                        's3SourceBucket':'source-bucket', 's3Files':{}, 'worlds':receipts}
            checks = {'count':0}
            def exists(*args):
                checks['count'] += 1
                return checks['count'] > 5
            calls = []
            def fake_compose(*args, **kwargs):
                calls.append(args)
                return MagicMock(stdout=b'')
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                    patch.object(dr, 'docker_volume_exists', side_effect=exists), \
                    patch.object(dr, 'compose_states', return_value={}), \
                    patch.object(dr, 'pg_validate'), \
                    patch.object(dr, 'compose', side_effect=fake_compose), \
                    patch.object(dr, 'docker_tar_restore'), \
                    patch.object(dr, 'compose_pg_restore'), \
                    patch.object(dr, 'ensure_empty_redis_volume'), \
                    patch.object(dr, 'fence_restored_serverbridge', side_effect=dr.DrillError('DB fence refused')), \
                    patch.object(dr, 's3_list_first', return_value=False), \
                    self.assertRaisesRegex(dr.DrillError, 'DB fence refused'):
                dr.restore_fresh('launcher', env, folder, 'launcher',
                       ready_url='https://launcher.example.org/ready', target_s3_bucket='new-bucket',
                       production=True, approved=True, world_destinations={'paper':dest})
            self.assertFalse(dest.exists())
            self.assertFalse(any(c[-3:] in (('up', '-d', 'api'), ('up', '-d', 'redis')) for c in calls))

    def test_schema_3_snapshot_rejects_corrupted_worlds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Проверка целевой квитанции выполняется на реальных байтах.
            source = make_world(root / 'remote')
            stage = root / 'snap'
            stage.mkdir()
            receipts = dr.archive_world_backups(stage, {'paper': source})
            dr.validate_world_receipts(stage, receipts)
            file = stage / 'worlds/paper' / source.name / 'payload/world/region/r.0.0.mca'
            file.write_bytes(b'tampered')
            with self.assertRaisesRegex(dr.DrillError, 'checksum'):
                dr.validate_world_receipts(stage, receipts)

if __name__ == '__main__':
    unittest.main()
