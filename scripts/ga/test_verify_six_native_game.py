"""Враждебные фикстуры для агрегирования результатов нативной игры; НЕ сертификация."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_six_native_game_0440 import TARGETS, verify
from run_native_validation_03410 import requires_adversarial_acceptance


class NativeGameIntegrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.package = 'immutable-native-package-0440'
        self.version = '0.44.0'
        self.commit = 'c' * 40
        self.run = '3456789'
        self.directories = {}
        for target, (osname, arch) in TARGETS.items():
            folder = self.root / f'v10-native-{osname}-{arch}-gui-{self.run}'
            folder.mkdir()
            self.directories[target] = folder
            self.write(folder / 'host-capabilities.json',
                       {'os': osname, 'arch': arch, 'status': 'ready'})
            self.write(folder / 'staged-execution.json', {
                'schemaVersion': 'test fixture', 'runId': 'staged-' + target,
                'packageId': self.package,
                'manifestSha256': '1' * 64, 'artifactSha256': '2' * 64,
                'stages': {name: {'status': 'passed'} for name in (
                    'manifest-files', 'materialization', 'startup', 'loader-readiness',
                    'authentication', 'server-readiness', 'matching-server',
                    'gameplay-smoke', 'update-recovery')},
            })
            neg = {'schemaVersion': 'launcher.adversarial-gameplay.04314.v1',
                   'manifestTamper': {'status': 'denied'},
                   'installedFileTamper': {'status': 'denied-and-restored',
                                           'baselineSha256': '3' * 64,
                                           'restoredFileSha256': '3' * 64}}
            self.write(folder / 'adversarial-gameplay-04314.json', neg)
            sha = hashlib.sha256((folder / 'adversarial-gameplay-04314.json').read_bytes()).hexdigest()
            self.write(folder / 'gameplay-smoke.json', {'adversarialGameplay04314': {
                'status': 'passed', 'evidenceSha256': sha,
                'manifestTamperDenied': True,
                'installedFileTamperDeniedAndRestored': True}})

    @staticmethod
    def write(path, payload):
        path.write_text(json.dumps(payload, sort_keys=True), encoding='utf-8')

    def check(self):
        return verify(self.root, self.package, self.version, self.commit, self.run)

    def test_six_actual_positive_negative_records_produce_observational_result(self):
        result = self.check()
        self.assertEqual(len(result['targets']), 6)
        self.assertEqual(result['status'], 'observed-not-independently-certified')
        self.assertEqual({t['target'] for t in result['targets']}, set(TARGETS))

    def test_missing_arm64_report_denied(self):
        (self.directories['windows-arm64'] / 'gameplay-smoke.json').unlink()
        with self.assertRaises(ValueError): self.check()

    def test_wrong_package_denied(self):
        path = self.directories['linux-x64'] / 'staged-execution.json'
        doc = json.loads(path.read_text()); doc['packageId'] = 'different'
        self.write(path, doc)
        with self.assertRaisesRegex(ValueError, 'another staged package'): self.check()

    def test_partial_matrix_denied(self):
        self.directories['darwin-arm64'].rename(self.root / 'orphan')
        with self.assertRaisesRegex(ValueError, 'six native GUI artifact'): self.check()

    def test_extra_target_denied(self):
        (self.root / 'v10-native-linux-riscv64-gui-3456789').mkdir()
        with self.assertRaisesRegex(ValueError, 'six native GUI artifact'): self.check()

    def test_simulated_negative_denied(self):
        path = self.directories['darwin-x64'] / 'adversarial-gameplay-04314.json'
        doc = json.loads(path.read_text()); doc['manifestTamper']['status'] = 'skipped'
        self.write(path, doc)
        with self.assertRaisesRegex(ValueError, 'negative game outcomes'): self.check()

    def test_wrong_host_architecture_denied(self):
        path = self.directories['linux-arm64'] / 'host-capabilities.json'
        doc = json.loads(path.read_text()); doc['arch'] = 'amd64'
        self.write(path, doc)
        with self.assertRaisesRegex(ValueError, 'host identity'): self.check()

    def test_invalid_binary_digest_denied(self):
        path = self.directories['windows-x64'] / 'staged-execution.json'
        doc = json.loads(path.read_text()); doc['artifactSha256'] = 'bad'
        self.write(path, doc)
        with self.assertRaisesRegex(ValueError, 'exact executable'): self.check()

    def test_future_stable_ga_uses_the_same_six_native_gate(self):
        result = verify(self.root, self.package, '1.0.0', self.commit, self.run)
        self.assertEqual(len(result['targets']), 6)

    def test_prerelease_cannot_claim_final_six_target_ga(self):
        with self.assertRaises(ValueError):
            verify(self.root, self.package, '0.44.0-rc.1', self.commit, self.run)

    def test_future_versions_keep_adversarial_requirements(self):
        self.assertTrue(requires_adversarial_acceptance('0.44.0'))
        self.assertTrue(requires_adversarial_acceptance('1.0.0'))
        self.assertTrue(requires_adversarial_acceptance('0.43.15'))
        self.assertFalse(requires_adversarial_acceptance('0.43.13'))
        with self.assertRaises(ValueError): requires_adversarial_acceptance('not-a-version')


if __name__ == '__main__':
    unittest.main()
