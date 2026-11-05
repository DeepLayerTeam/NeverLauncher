"""Регрессионные тесты реальных байтов резервного копирования/восстановления SQLite и безопасной оркестрации DDL PostgreSQL."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, call

import db_upgrade_0457 as u
import dr_03512 as dr


class SQLiteUpgradeTests(unittest.TestCase):
    def fixture(self, root: Path):
        for folder in ('db', 'config', 'storage', 'backups', 'extensions', 'factory'):
            (root / folder).mkdir(parents=True, mode=0o700)
        for name in ('db/http.sqlite', 'db/coordinator.sqlite'):
            with sqlite3.connect(root / name) as db:
                if name.endswith('http.sqlite'):
                    db.execute('PRAGMA user_version=326')
                    db.execute('CREATE TABLE marker(id INTEGER PRIMARY KEY, value TEXT)')
                    db.execute("INSERT INTO marker(value) VALUES('original')")
                else:
                    db.execute('CREATE TABLE coord_meta(key TEXT PRIMARY KEY,value INTEGER)')
                    db.execute("INSERT INTO coord_meta VALUES('version',1)")
        env = {'LAUNCHER_DEPLOYMENT_MODE': 'single-node',
               'LAUNCHER_REPOSITORY_DRIVER': 'sqlite',
               'LAUNCHER_STORAGE_DRIVER': 'local',
               'LAUNCHER_DATABASE_DSN': str(root / 'db/http.sqlite'),
               'LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH': str(root / 'db/coordinator.sqlite'),
               'LAUNCHER_STORAGE_LOCAL_PATH': str(root / 'storage'),
               'LAUNCHER_BACKUP_ROOT': str(root / 'backups'),
               'LAUNCHER_EXTENSION_ROOT': str(root / 'extensions'),
               'LAUNCHER_AUTH_TOKEN_SECRET': 'existing-key',
               'LAUNCHER_FACTORY_ROOT': str(root / 'factory')}
        (root / 'config/backend.env').write_text(''.join(f'{k}={v}\n' for k,v in env.items()))
        (root / 'storage/client.txt').write_bytes(b'PLAYER FILE')
        (root / 'extensions/module.txt').write_bytes(b'EXTENSION')
        os.chmod(root / 'config/backend.env', 0o600)

    def test_real_sqlite_snapshot_and_new_host_restore(self):
        import sys
        sys.path.insert(0, str(u.MINIMAL_BACKUP.parent))
        import minimal_backup as mb
        with tempfile.TemporaryDirectory() as base:
            home = Path(base)
            root = home / 'source'; root.mkdir(mode=0o700)
            self.fixture(root)
            copy = home / 'backup'; restored = home / 'recovered'; os.chmod(home,0o700)
            u.schema_check_sqlite(root)
            mb.backup(root, copy)
            self.assertEqual(mb.verify(copy)['sourceRoot'], str(root))
            # Имитируйте прерванное настоящее обновление схемы SQLite (DDL уже
            # зафиксирован).
            with sqlite3.connect(root / 'db/http.sqlite') as db:
                db.execute('ALTER TABLE marker ADD COLUMN changed INTEGER')
                db.execute('PRAGMA user_version=327')
                db.execute("UPDATE marker SET value='modified'")
            u.schema_check_sqlite(root,target_version=327)
            mb.restore(copy, restored)
            u.schema_check_sqlite(restored,target_version=326)
            with sqlite3.connect(restored / 'db/http.sqlite') as db:
                self.assertEqual(db.execute('SELECT value FROM marker').fetchone(), ('original',))
            self.assertEqual((restored / 'storage/client.txt').read_bytes(),b'PLAYER FILE')
            self.assertIn('LAUNCHER_AUTH_TOKEN_SECRET=existing-key', (restored / 'config/backend.env').read_text())
            self.assertIn(str(restored / 'db/http.sqlite'), (restored / 'config/backend.env').read_text())

    def test_schema_check_detects_corrupt_and_future_versions(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base); self.fixture(root)
            with self.assertRaisesRegex(u.UpgradeError,'!= expected'):
                u.schema_check_sqlite(root,target_version=999)
            (root / 'db/coordinator.sqlite').write_bytes(b'not-a-database')
            with self.assertRaises((u.UpgradeError, sqlite3.DatabaseError)):
                u.schema_check_sqlite(root)

    def test_retry_and_health_probe_fail_closed(self):
        for url in ('https://example.com/ready','http://localhost:8080/ready','http://127.0.0.1:8080/admin'):
            with self.assertRaisesRegex(u.UpgradeError,'loopback'):
                u.wait_loopback_ready(url,timeout=0)

    def test_switch_native_execstart_persists_and_failed_reload_cleans(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            binary=Path('/opt/launcher/releases/0.45.7/bin/launcher-api')
            with patch.object(u,'exec_checked') as command:
                override=u.switch_native_service(binary,'launcher.service',unit_root=root)
                self.assertEqual(override.read_text(),
                    '[Service]\nExecStart=\nExecStart=/opt/launcher/releases/0.45.7/bin/launcher-api\n')
                with self.assertRaisesRegex(u.UpgradeError,'already exists'):
                    u.switch_native_service(binary,'launcher.service',unit_root=root)
                u.revert_native_service(override)
                self.assertFalse(override.exists())
                command.assert_any_call(['systemctl','daemon-reload'],timeout=30)
            with patch.object(u,'exec_checked',side_effect=u.UpgradeError('reload refused')):
                with self.assertRaisesRegex(u.UpgradeError,'reload refused'):
                    u.switch_native_service(binary,'launcher.service',unit_root=root)
                self.assertFalse(override.exists())
            with self.assertRaisesRegex(u.UpgradeError,'only managed'):
                u.switch_native_service(binary,'ssh.service',unit_root=root)


class PostgreSQLUpgradeTests(unittest.TestCase):
    def test_env_prohibits_secret_or_topology_rotation(self):
        with tempfile.TemporaryDirectory() as base:
            first = Path(base)/'source'; second=Path(base)/'target'
            first.write_text('LAUNCHER_IMAGE_TAG=0.45.6\nPOSTGRES_PASSWORD=same\n')
            second.write_text('LAUNCHER_IMAGE_TAG=0.45.7\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\nPOSTGRES_PASSWORD=same\n')
            self.assertEqual(u.validate_source_target(first,second,False),'0.45.6')
            second.write_text('LAUNCHER_IMAGE_TAG=0.45.7\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\nPOSTGRES_PASSWORD=changed\n')
            with self.assertRaisesRegex(u.UpgradeError,'POSTGRES_PASSWORD'):
                u.validate_source_target(first,second,False)
            second.write_text('LAUNCHER_IMAGE_TAG=0.45.6\nPOSTGRES_PASSWORD=same\n')
            with self.assertRaisesRegex(u.UpgradeError,'target 0.45.7'):
                u.validate_source_target(first,second,False)

    def test_postgres_migration_runs_real_one_shot_twice(self):
        with patch.object(dr,'compose') as mock:
            u.postgres_migrate('nl-dr-a',Path('/source'))
            self.assertEqual(mock.call_count,2)
            for args, kwargs in mock.call_args_list:
                self.assertIn('LAUNCHER_PROCESS_ROLE=migrate',args)
                self.assertIn('LAUNCHER_DATABASE_AUTO_MIGRATE=true',args)
                self.assertIn('--no-deps',args)
                self.assertIn('--rm',args)

    def test_postgres_recovery_recreates_db_then_verified_volumes(self):
        with patch.object(dr,'compose') as compose, patch.object(dr,'compose_pg_restore') as restore, \
             patch.object(dr,'run') as run, patch.object(dr,'docker_tar_restore') as volume:
            u.reset_postgres('nl-dr-a',Path('/env'),Path('/backup'))
            self.assertIn('dropdb',compose.call_args[0][-1])
            self.assertEqual(volume.call_count,len(dr.STANDARD_VOLUMES))
            self.assertEqual(run.call_count,len(dr.STANDARD_VOLUMES))
            restore.assert_called_once_with('nl-dr-a',Path('/env'),Path('/backup/database.dump'))

    def test_failures_force_backup_recovery_before_old_api(self):
        with tempfile.TemporaryDirectory() as home:
            src=Path(home)/'from'; target=Path(home)/'to'; backup=Path(home)/'backup'
            src.write_text('LAUNCHER_IMAGE_TAG=0.45.6\n')
            target.write_text('LAUNCHER_IMAGE_TAG=0.45.7\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\n')
            states={'postgres':'running','api':'running','admin':'running','nginx':'running'}
            with patch.object(dr,'compose_states',return_value=states),\
                 patch.object(dr,'snapshot') as snapshot, patch.object(dr,'pg_validate'), patch.object(dr,'verify_snapshot'),\
                 patch.object(u,'postgres_migrate',side_effect=u.UpgradeError('bad DDL')),\
                 patch.object(u,'reset_postgres') as reset, patch.object(u,'resume') as resume,\
                 patch.object(dr,'compose'), patch.object(dr,'check_restored_backend'), patch.object(dr,'run'):
                snapshot.return_value={'version':'0.45.6'}
                with self.assertRaisesRegex(u.UpgradeError,'restored and verified'):
                    u.upgrade_postgres('nl-dr-source',src,target,backup,'nl-dr-source')
                self.assertFalse(resume.call_args_list[0].kwargs['network_ha'])
                self.assertEqual(resume.call_args_list[0].args[1],src)
                snapshot.assert_called_once()
                self.assertFalse(snapshot.call_args.kwargs['resume_after'])
                reset.assert_called_once()

    def test_success_starts_old_running_services_with_target(self):
        with tempfile.TemporaryDirectory() as home:
            src=Path(home)/'from'; target=Path(home)/'to'; backup=Path(home)/'backup'
            src.write_text('LAUNCHER_IMAGE_TAG=0.45.6\n')
            target.write_text('LAUNCHER_IMAGE_TAG=0.45.7\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\n')
            with patch.object(dr,'compose_states',return_value={'postgres':'running','api':'running','admin':'exited','nginx':'running'}),\
                 patch.object(dr,'snapshot'), patch.object(dr,'pg_validate'),\
                 patch.object(u,'postgres_migrate') as migrate, patch.object(u,'resume') as resume, patch.object(dr,'check_restored_backend'), patch.object(dr,'compose'), patch.object(dr,'run'):
                result=u.upgrade_postgres('nl-dr-source',src,target,backup,'nl-dr-source')
                self.assertEqual(result['status'],'upgraded')
                migrate.assert_called_once()
                self.assertEqual(resume.call_args.args[2], ['nginx','api'])
                self.assertEqual(resume.call_args.kwargs['expected'], '0.45.7')


if __name__=='__main__':
    unittest.main()
