"""Исполняемые положительные и строгие отрицательные регрессионные тесты обновления компонентов 0.45.8."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import component_upgrade_0458 as c
import dr_03512 as dr


class StandardComponentTests(unittest.TestCase):
    def fixture(self, root):
        source = root / 'source.env'
        target = root / 'target.env'
        source.write_text('LAUNCHER_IMAGE_TAG=0.45.7\nSECRET=value\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\n')
        target.write_text('LAUNCHER_IMAGE_TAG=0.45.8\nSECRET=value\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\n')
        source.chmod(0o600); target.chmod(0o600)
        return source, target

    def test_running_container_must_match_pinned_image(self):
        fake_id='f'*64
        class Result:
            def __init__(self, value):
                self.stdout=value
        with patch.object(c,'image_id',return_value='sha256:'+'a'*64), \
             patch.object(dr,'compose',return_value=Result(fake_id.encode())), \
             patch.object(c,'run',return_value=('sha256:'+'a'*64).encode()):
            c.verify_service_image('nl-dr-check',Path('/test.env'),'worker-a',c.TARGET)
        with patch.object(c,'image_id',return_value='sha256:'+'a'*64), \
             patch.object(dr,'compose',return_value=Result(fake_id.encode())), \
             patch.object(c,'run',return_value=('sha256:'+'b'*64).encode()):
            with self.assertRaisesRegex(c.ComponentError,'unexpected image digest'):
                c.verify_service_image('nl-dr-check',Path('/test.env'),'api-b',c.TARGET)

    def test_source_version_and_secret_changes_are_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = self.fixture(Path(tmp))
            self.assertEqual(c.assert_same_config(source, target), '0.45.7')
            target.write_text('LAUNCHER_IMAGE_TAG=0.45.8\nSECRET=different\nLAUNCHER_DATABASE_AUTO_MIGRATE=false\n')
            with self.assertRaisesRegex(c.ComponentError, 'differ'):
                c.assert_same_config(source, target)
            target.write_text('LAUNCHER_IMAGE_TAG=0.45.8\nSECRET=value\nLAUNCHER_DATABASE_AUTO_MIGRATE=true\n')
            with self.assertRaisesRegex(c.ComponentError, 'DDL'):
                c.assert_same_config(source, target)
            target.chmod(0o644)
            with self.assertRaisesRegex(c.ComponentError, 'private'):
                c.assert_same_config(source, target)

    def test_success_uses_real_backup_before_cutover(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            source, target = self.fixture(root)
            actions = []
            images = {'api': {'old': 'sha256:'+'a'*64, 'new': 'sha256:'+'b'*64},
                      'admin': {'old': 'sha256:'+'c'*64, 'new': 'sha256:'+'d'*64}}
            def image(tag):
                service = tag.split(':')[0].split('-')[-1]
                return images[service]['old' if tag.endswith('0.45.7') else 'new']
            with patch.object(dr, 'authorize_project'), patch.object(dr, 'compose_states', return_value={
                'postgres': 'running', 'api': 'running', 'admin': 'running', 'nginx': 'running'}), \
                patch.object(dr, 'check_restored_backend') as backend, \
                patch.object(dr, 'snapshot', side_effect=lambda *a,**k: actions.append('snapshot')) as snap, \
                patch.object(dr, 'verify_snapshot', side_effect=lambda *a: actions.append('verify') or {'postgresWalLsn':'0/0'}), \
                patch.object(dr, 'assert_quiescent', return_value='0/0'), \
                patch.object(dr, 'compose', side_effect=lambda *a,**k: actions.append(a[-1]) or None), \
                patch.object(c, 'image_id', side_effect=image), \
                patch.object(c, 'restore_service_set', side_effect=lambda *a,**k: actions.append('start')):
                result = c.standard('nl-dr-test','nl-dr-test', source, target, root/'snapshot')
                self.assertEqual(result['status'], 'upgraded')
                self.assertEqual(actions, ['admin', 'snapshot', 'verify', 'start'])
                self.assertFalse(snap.call_args.kwargs['resume_after'])
                self.assertEqual(backend.call_args.kwargs['version'], c.SOURCE)

    def test_failed_health_rolls_back_prior_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700)
            source,target=self.fixture(root)
            versions=[]
            with patch.object(dr, 'authorize_project'), patch.object(dr, 'compose_states', return_value={
                'postgres':'running','api':'running','admin':'running','nginx':'running'}), \
                patch.object(dr,'check_restored_backend'), patch.object(dr,'snapshot'), \
                patch.object(dr,'verify_snapshot', return_value={'postgresWalLsn':'0/0'}), patch.object(dr,'assert_quiescent', return_value='0/0'), \
                patch.object(dr,'compose'), \
                patch.object(c,'image_id',side_effect=lambda tag: 'sha256:'+('a' if tag.endswith(c.SOURCE) else 'b')*64), \
                patch.object(c,'restore_service_set',side_effect=lambda *a,**k: versions.append(k['expected']) or (None if k['expected']==c.SOURCE else (_ for _ in ()).throw(c.ComponentError('new broken')))):
                with self.assertRaisesRegex(c.ComponentError, 'restored and verified'):
                    c.standard('nl-dr-test','nl-dr-test',source,target,root/'snapshot')
                self.assertEqual(versions,[c.TARGET,c.SOURCE])

    def test_failed_old_restore_is_not_reported_good(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700); source,target=self.fixture(root)
            with patch.object(dr, 'authorize_project'), patch.object(dr, 'compose_states', return_value={
                'postgres':'running','api':'running','admin':'exited','nginx':'running'}), \
                patch.object(dr,'check_restored_backend'), patch.object(dr,'snapshot'), \
                patch.object(dr,'verify_snapshot', return_value={'postgresWalLsn':'0/0'}), patch.object(dr,'assert_quiescent', return_value='0/0'), \
                patch.object(dr,'compose'), \
                patch.object(c,'image_id',side_effect=lambda tag: 'sha256:'+('a' if tag.endswith(c.SOURCE) else 'b')*64), \
                patch.object(c,'restore_service_set',side_effect=c.ComponentError('not ready')):
                with self.assertRaisesRegex(c.ComponentError, 'could not be verified'):
                    c.standard('nl-dr-test','nl-dr-test',source,target,root/'snapshot')


class HAComponentTests(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700)
        return StandardComponentTests().fixture(root)

    def test_ha_requires_stopped_world_snapshots_and_s3(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,target=self.fixture(root)
            with patch.object(dr, 'authorize_project'):
                with self.assertRaisesRegex(c.ComponentError, 'stopped worlds'):
                    c.network_ha('nl-dr-a', 'nl-dr-a', source, target, root/'backup', {}, '', None)

    def test_complete_ha_cutover_keeps_recovery_capable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,target=self.fixture(root)
            world=root/'world'
            world.mkdir()
            original_files=list(dr.COMPOSE_FILES)
            original_profiles=list(dr.COMPOSE_PROFILES)
            with patch.object(dr,'authorize_project'), patch.object(dr,'compose_states', return_value={
                'postgres':'running', 'redis':'running', 'api':'running', 'api-b':'running',
                'worker-a':'running', 'worker-b':'running', 'admin':'running', 'nginx':'running'}), \
                patch.object(dr,'check_restored_backend'), patch.object(dr,'check_restored_worker_0455'), \
                patch.object(dr,'snapshot') as snap, patch.object(dr,'verify_snapshot', return_value={'postgresWalLsn':'0/0'}), \
                patch.object(dr,'assert_quiescent', return_value='0/0'), patch.object(dr,'compose'), \
                patch.object(c,'image_id',side_effect=lambda tag: 'sha256:'+('a' if tag.endswith(c.SOURCE) else 'b')*64), \
                patch.object(c,'restore_ha_roles') as roles:
                result=c.network_ha('nl-dr-a','nl-dr-a',source,target,root/'backup',{'world':world},'bucket',None)
                self.assertEqual(result['mode'],'network-ha')
                self.assertEqual(roles.call_args.kwargs['expected'],c.TARGET)
                self.assertEqual(snap.call_args.kwargs['world_backups'],{'world':world})
                self.assertFalse(snap.call_args.kwargs['resume_after'])
                self.assertEqual(dr.COMPOSE_PROFILES,original_profiles)
                self.assertEqual(dr.COMPOSE_FILES,original_files)

    def test_failed_ha_reverts_all_roles_and_compose_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,target=self.fixture(root)
            with patch.object(dr,'authorize_project'), patch.object(dr,'compose_states',return_value={
                'postgres':'running','redis':'running','api':'running','api-b':'running',
                'worker-a':'running','worker-b':'running','admin':'running','nginx':'running'}), \
                patch.object(dr,'check_restored_backend'), patch.object(dr,'check_restored_worker_0455'), \
                patch.object(dr,'snapshot'), patch.object(dr,'verify_snapshot', return_value={'postgresWalLsn':'0/0'}), patch.object(dr,'assert_quiescent', return_value='0/0'), \
                patch.object(dr,'compose'), \
                patch.object(c,'image_id',side_effect=lambda tag: 'sha256:'+('a' if tag.endswith(c.SOURCE) else 'b')*64), \
                patch.object(c,'restore_ha_roles',side_effect=[c.ComponentError('failed'),None]) as roles:
                with self.assertRaisesRegex(c.ComponentError,'original binaries restored'):
                    c.network_ha('nl-dr-a','nl-dr-a',source,target,root/'backup',{'world':root},'bucket',None)
                self.assertEqual([x.kwargs['expected'] for x in roles.call_args_list],[c.TARGET,c.SOURCE])
                self.assertEqual(dr.COMPOSE_PROFILES,[])


class HostBinaryTests(unittest.TestCase):
    def fixture(self, root):
        old = root / 'launcher'
        new = root / 'target'
        old.write_text('#!/bin/sh\necho "Launcher CLI 0.45.7"\n')
        new.write_text('#!/bin/sh\necho "Launcher CLI 0.45.8"\n')
        old.chmod(0o755);new.chmod(0o755)
        return old,new,hashlib.sha256(new.read_bytes()).hexdigest()

    def test_replaces_actual_executable_and_preserves_previous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            result=c.host_binary('cli',new,old,sha)
            self.assertEqual(result['status'],'upgraded')
            self.assertIn('0.45.8',c.run([str(old),'version']).decode())
            self.assertIn('0.45.7',c.run([result['rollbackExecutable'],'version']).decode())
            self.assertEqual(c.digest(old),sha)

    def test_explicit_host_rollback_restores_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            original=old.read_bytes(); old_sha=c.digest(old)
            c.host_binary('cli',new,old,sha)
            result=c.rollback_linux_host('cli',old,old_sha)
            self.assertEqual(result['status'],'rolled-back')
            self.assertEqual(old.read_bytes(),original)
            self.assertEqual((root/'launcher.failed-0458').read_bytes(),new.read_bytes())

    def test_explicit_rollback_requires_old_pinned_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            c.host_binary('cli',new,old,sha)
            with self.assertRaisesRegex(c.ComponentError,'Контрольная сумма SHA-256 не совпадает'):
                c.rollback_linux_host('cli',old,'0'*64)
            self.assertEqual(old.read_bytes(),new.read_bytes())

    def test_failing_component_is_rolled_back_byte_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            previous=old.read_bytes()
            new.write_text('#!/bin/sh\necho broken\n');sha=c.digest(new)
            with self.assertRaisesRegex(c.ComponentError,'old binary restored'):
                c.host_binary('cli',new,old,sha)
            self.assertEqual(old.read_bytes(),previous)
            self.assertFalse((root/'launcher.previous-0458').exists())

    def test_invalid_hash_refused_before_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            with self.assertRaisesRegex(c.ComponentError,'Контрольная сумма SHA-256 не совпадает'):
                c.host_binary('cli',new,old,'0'*64)
            self.assertIn('0.45.7',old.read_text())

    def test_managed_minimal_api_verifies_real_ready_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            with patch.object(c,'systemctl_is_active',return_value=True), \
                 patch.object(c,'run',return_value=b''), \
                 patch.object(c.database,'wait_loopback_ready',return_value=c.TARGET) as readiness:
                result=c.host_binary('api',new,old,sha,service='launcher.service')
                self.assertTrue(result['serviceVerified'])
                self.assertEqual(readiness.call_args.kwargs['expected_version'],c.TARGET)

    def test_active_service_restarted_after_upgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,new,sha=self.fixture(root)
            actions=[]
            with patch.object(c,'systemctl_is_active',return_value=True), \
                 patch.object(c,'run',side_effect=lambda args,**k: actions.append(args[:2]) or (b'Launcher CLI 0.45.8' if args[1]=='version' else b'')):
                c.host_binary('bridge',new,old,sha,service='launcher-bridge.service')
                self.assertIn(['systemctl','stop'],actions)
                self.assertIn(['systemctl','start'],actions)


class ClientExtensionTests(unittest.TestCase):
    def test_native_client_update_uses_pinned_package_without_dev_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cli=root/'nl';pkg=root/'signed.zip';delivery=root/'delivery.json'
            cli.write_bytes(b'cli');pkg.write_bytes(b'payload');delivery.write_bytes(b'production')
            sha=c.digest(pkg)
            with patch.object(c,'run',return_value=json.dumps({'status':'committed','toVersion':'0.45.8'}).encode()) as called:
                result=c.client_package(cli,pkg,sha,delivery,root)
                args=called.call_args.args[0]
                self.assertEqual(args[:3],[str(cli),'update','components'])
                self.assertIn('--delivery-manifest',args)
                self.assertNotIn('--allow-unpinned-development',args)
                self.assertEqual(result['nativeReport']['status'],'committed')
            with self.assertRaisesRegex(c.ComponentError,'Контрольная сумма SHA-256 не совпадает'):
                c.client_package(cli,pkg,'0'*64,delivery,root)

    def test_extension_transaction_requires_committed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli=Path(tmp)/'nl';cli.write_bytes(b'x')
            plan={'data': {'plan': {'items': []}}}
            good={'data': {'transaction': {'status': 'succeeded','id':'tx1'}}}
            with patch.dict(os.environ,{'LAUNCHER_TOKEN':'private'},clear=False), \
                 patch.object(c,'run',side_effect=[json.dumps(plan).encode(),json.dumps(good).encode()]) as cmd:
                result=c.extensions(cli,'https://example.org',['my.ext@0.45.8'],'stable')
                self.assertEqual(result['transactionId'],'tx1')
                self.assertIn('apply',cmd.call_args.args[0])
            with patch.dict(os.environ,{'LAUNCHER_TOKEN':'private'},clear=False), \
                 patch.object(c,'run',side_effect=[json.dumps(plan).encode(),json.dumps({'data':{'transaction':{'status':'rolled_back'}}}).encode()]):
                with self.assertRaisesRegex(c.ComponentError,'did not commit'):
                    c.extensions(cli,'https://example.org',['my.ext@0.45.8'],'stable')
            with self.assertRaisesRegex(c.ComponentError,'HTTPS origin'):
                c.extensions(cli,'http://example.org',['my.ext@0.45.8'],'stable')


if __name__ == '__main__':
    unittest.main()
