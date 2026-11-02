"""Real filesystem regression tests for the 0.47.6 in-place upgrade operator."""
import argparse
import json
import zipfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import legacy_upgrade_0476 as u


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'existing'
        self.root.mkdir()
        self.backups = self.base / 'backups'
        self.backups.mkdir(mode=0o700)
        (self.root / 'profiles' / 'prod-profile').mkdir(parents=True)
        (self.root / 'profiles' / 'prod-profile' / 'saves.dat').write_bytes(b'\x00user-save\xff')
        (self.root / 'settings').mkdir()
        (self.root / 'settings' / 'preferences.json').write_text('{"channel":"stable","projectId":"real-project"}')

    def args(self, mode='client', **overrides):
        kwargs = dict(mode=mode, root=str(self.root), backup=str(self.backups / 'run'),
                      data=['profiles', 'settings'], from_version=None, cli='launcher', cli_sha256='a'*64,
                      package='pkg', sha256='a'*64, delivery_manifest='delivery', installer='neverinstaller', installer_sha256='a'*64,
                      bundle=str(self.root), component='cli', executable='new', install=str(self.root / 'launcher'),
                      service=None, ready_url='http://127.0.0.1:8080/ready', project=None, confirm=None,
                      source_env=None, target_env=None, production_source=False, maintenance_approved=False)
        return argparse.Namespace(**(kwargs | overrides))

    def client_state(self, version='0.47.5'):
        p = self.root / '.launcher' / 'component-update-state.json'
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps({'schemaVersion':'1.0','version':version,'components':[{}, {}, {}]}))
        return p

    def prestarter_state(self, generation=2):
        p = self.root / '.launcher-installer' / f'active-{generation%2}.json'
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps({'generation': generation, 'release':'b'*64+'-linux-amd64',
                                 'configHash':'c'*64, 'binaryHash':'d'*64}))
        return p

    def test_verified_backup_is_independent_exact_copy(self):
        data = u.enumerate_data(self.root, ['profiles', 'settings'])
        b = self.backups / 'safecopy'
        u.create_backup(self.root, b, data, '0.47.5', 'client', ['profiles', 'settings'])
        self.assertEqual((b / 'user-data' / 'profiles' / 'prod-profile' / 'saves.dat').read_bytes(), b'\x00user-save\xff')
        self.assertEqual(json.loads((b / 'inventory.json').read_text())['files'], data)
        (self.root / 'profiles' / 'prod-profile' / 'saves.dat').write_bytes(b'corrupted')
        self.assertEqual((b / 'user-data' / 'profiles' / 'prod-profile' / 'saves.dat').read_bytes(), b'\x00user-save\xff')
        with self.assertRaisesRegex(u.LegacyUpgradeError, 'altered'):
            u.verify_preservation(self.root, data, ['profiles', 'settings'])

    def test_client_real_native_path_preserves_files_and_advances_version(self):
        state = self.client_state()
        def apply(*args, **kwargs):
            state.write_text(json.dumps({'schemaVersion':'1.0','version':u.TARGET,'components':[{}, {}, {}]}))
            return {'nativeReport': {'status': 'committed', 'toVersion': u.TARGET}}
        with patch.object(u.native, 'checked_file'), patch.object(u.native,'client_package',side_effect=apply) as invoked:
            result = u.execute(self.args())
        self.assertEqual(result['status'], 'upgraded')
        self.assertEqual(result['protectedEntries'], 5)
        self.assertEqual(json.loads((self.backups / 'run' / 'journal.json').read_text())['phase'], 'verified')
        self.assertEqual(invoked.call_args.kwargs['target_version'], u.TARGET)
        with self.assertRaisesRegex(u.LegacyUpgradeError, 'already exists'):
            u.execute(self.args())

    def test_failing_updater_keeps_recovery_journal_and_backup(self):
        self.client_state()
        with patch.object(u.native, 'checked_file'), patch.object(u.native,'client_package',side_effect=u.native.ComponentError('bad signature')):
            with self.assertRaisesRegex(u.native.ComponentError, 'signature'):
                u.execute(self.args())
        b = self.backups / 'run'
        self.assertEqual(json.loads((b / 'journal.json').read_text())['phase'], 'manual-reconciliation-required')
        self.assertEqual((b / 'user-data' / 'profiles' / 'prod-profile' / 'saves.dat').read_bytes(), b'\x00user-save\xff')

    def test_client_mutation_after_commit_is_detected_and_preserved(self):
        state = self.client_state()
        def apply(*args, **kwargs):
            state.write_text(json.dumps({'schemaVersion':'1.0','version':u.TARGET,'components':[{}, {}, {}]}))
            (self.root / 'settings' / 'preferences.json').write_text('{"projectId":"demo"}')
            return {'nativeReport': {'status': 'committed', 'toVersion': u.TARGET}}
        with patch.object(u.native, 'checked_file'), patch.object(u.native,'client_package',side_effect=apply):
            with self.assertRaisesRegex(u.LegacyUpgradeError, 'altered'):
                u.execute(self.args())
        self.assertEqual(json.loads((self.backups / 'run' / 'journal.json').read_text())['phase'], 'manual-reconciliation-required')
        self.assertIn('real-project',(self.backups / 'run' / 'user-data' / 'settings' / 'preferences.json').read_text())

    def test_preinstaller_calls_actual_verified_update(self):
        self.prestarter_state()
        sequence=[]
        def run(command, **kwargs):
            sequence.append(command[1])
            if command[1] == 'update':
                self.prestarter_state(3)
        (self.root / 'neverinstaller').write_bytes(b'installed signer-pinned executable fixture')
        args = self.args(mode='prestarter', from_version='0.47.5', installer=str(self.root / 'neverinstaller'), installer_sha256=u.sha_file(self.root / 'neverinstaller'))
        with patch.object(u, 'run_updater', side_effect=run):
            result = u.execute(args)
        self.assertEqual(sequence, ['verify','verify-installed','update','verify-installed'])
        self.assertEqual(result['newGeneration'], 3)

    def test_bad_version_symlink_and_overlap_rejected_without_mutation(self):
        self.client_state('0.31.1')
        with self.assertRaisesRegex(u.LegacyUpgradeError, 'unsupported'):
            u.execute(self.args())
        self.assertFalse((self.backups / 'run').exists())
        (self.root / 'profiles' / 'fake').symlink_to('/tmp')
        with self.assertRaisesRegex(u.LegacyUpgradeError, 'symlink'):
            u.enumerate_data(self.root, ['profiles'])
        with self.assertRaisesRegex(u.LegacyUpgradeError, 'overlapping'):
            u.enumerate_data(self.root, ['settings', 'settings/preferences.json'])

    def test_backend_routes_to_verified_existing_standard_operator(self):
        args = self.args(mode='backend', project='prod',confirm='prod',source_env='/tmp/old',target_env='/tmp/new')
        with patch.object(u.native, 'read_version',return_value=({},'0.47.5')) as detect, \
             patch.object(u.native, 'assert_same_config'), \
             patch.object(u.native, 'standard',return_value={'status':'upgraded','backendVerified':True}) as op:
            result = u.execute(args)
        self.assertEqual(result['mode'], 'backend')
        self.assertEqual(op.call_args.kwargs['target_version'],u.TARGET)
        self.assertTrue(detect.called)

    def test_java_bridge_plugin_cold_swap_with_pinned_full_release_manifest(self):
        def jar(path, version):
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('plugin.yml', f'name: LauncherPaperBridge\nversion: {version}\n')
        plugin_dir = self.root / 'plugins'
        plugin_dir.mkdir()
        old = plugin_dir / 'launcher-paper-bridge.jar'
        new = self.base / f'launcher-paper-bridge-{u.TARGET}.jar'
        jar(old, '0.47.5'); jar(new, u.TARGET)
        rows = [{'id': kind, 'file': f'launcher-{kind}-bridge-{u.TARGET}.jar',
                 'sha256': u.sha_file(new)} for kind in sorted(u.BRIDGE_TARGETS)]
        manifest = self.base / 'PLUGIN_MANIFEST.json'
        manifest.write_text(json.dumps({'toolVersion':u.TARGET, 'artifacts':rows}))
        args = self.args(mode='bridge-jar', executable=str(new), install=str(old),
                         plugin_type='paper', release_manifest=str(manifest),
                         manifest_sha256=u.sha_file(manifest), service='paper.service')
        calls=[]
        with patch.object(u.os,'geteuid',return_value=0), \
             patch.object(u.native,'systemctl_is_active',return_value=True), \
             patch.object(u.native,'run',side_effect=lambda a,**k: calls.append(a) or b''):
            result = u.execute(args)
        self.assertEqual(result['pluginType'], 'paper')
        self.assertFalse(result['runtimeJoinVerified'])
        self.assertEqual(u.jar_metadata_version(old),u.TARGET)
        self.assertEqual(u.jar_metadata_version(plugin_dir / 'launcher-paper-bridge.jar.previous-0476'),'0.47.5')
        self.assertEqual([x[1] for x in calls],['stop','start'])
        self.assertEqual(json.loads((self.backups / 'run' / 'journal.json').read_text())['phase'],'verified')

    def test_java_bridge_manifest_tamper_is_blocked_pre_stop(self):
        plugin_dir = self.root / 'plugins'
        plugin_dir.mkdir()
        old = plugin_dir / 'launcher-paper-bridge.jar'
        with zipfile.ZipFile(old,'w') as z: z.writestr('plugin.yml','version: 0.47.5\n')
        new = self.base / f'launcher-paper-bridge-{u.TARGET}.jar'
        with zipfile.ZipFile(new,'w') as z: z.writestr('plugin.yml',f'version: {u.TARGET}\n')
        manifest = self.base / 'PLUGIN_MANIFEST.json'
        manifest.write_text(json.dumps({'toolVersion':u.TARGET,'artifacts':[]}))
        args = self.args(mode='bridge-jar', executable=str(new), install=str(old),
                         plugin_type='paper', release_manifest=str(manifest),
                         manifest_sha256='0'*64, service='paper.service')
        with patch.object(u.os,'geteuid',return_value=0), patch.object(u.native,'run') as run:
            with self.assertRaisesRegex(u.LegacyUpgradeError,'manifest hash mismatch'):
                u.execute(args)
            run.assert_not_called()
        self.assertEqual(u.jar_metadata_version(old),'0.47.5')

    def test_actual_legacy_host_upgrade_and_explicit_verified_rollback(self):
        old = self.root / 'launcher'
        new = self.base / 'signed-launcher'
        old.write_text('#!/bin/sh\necho "Launcher CLI 0.47.5"\n')
        new.write_text('#!/bin/sh\necho "Launcher CLI 0.47.6"\n')
        old.chmod(0o755); new.chmod(0o755)
        original = old.read_bytes()
        args = self.args(mode='host', component='cli', install=str(old), executable=str(new), sha256=u.sha_file(new))
        result = u.execute(args)
        self.assertEqual(result['status'], 'upgraded')
        self.assertIn(b'0.47.6',old.read_bytes())
        self.assertEqual((self.root / 'launcher.previous-0476').read_bytes(),original)
        rollback = self.args(mode='rollback-host', component='cli', install=str(old))
        restored = u.execute(rollback)
        self.assertTrue(restored['userDataVerified'])
        self.assertEqual(old.read_bytes(), original)
        self.assertIn(b'0.47.6',(self.root / 'launcher.failed-0476').read_bytes())
        self.assertEqual(json.loads((self.backups / 'run' / 'journal.json').read_text())['phase'], 'reverted-and-verified')

    def test_installed_version_mismatch_blocks_before_native_update(self):
        self.client_state('0.47.4')
        with patch.object(u.native, 'checked_file'), patch.object(u.native, 'client_package') as call:
            with self.assertRaisesRegex(u.LegacyUpgradeError, 'differs'):
                u.execute(self.args(from_version='0.47.5'))
            call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
