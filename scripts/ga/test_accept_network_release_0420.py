"""Negative regressions for exact-byte final package and Go crash evidence.

These deliberately synthetic fixtures are local tests; they cannot count as
real Minecraft/JVM/Proxy certification for a release.
"""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name('accept_network_release_0420.py')
FAULT_SOURCE = Path(__file__).with_name('record_network_faults_0420.py')
spec = importlib.util.spec_from_file_location('accept_network_release_0420', SOURCE)
accept = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accept)
spec2 = importlib.util.spec_from_file_location('record_network_faults_0420', FAULT_SOURCE)
fault = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(fault)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / 'final'
        self.release.mkdir()
        (self.root / 'artifacts/plugins').mkdir(parents=True)
        self.rows = []
        for index, target in enumerate(accept.TARGETS):
            name = f'neverlauncher-{target}-bridge-0.42.0.jar'
            payload = bytes([index + 1]) * 2048
            actual = self.root / 'artifacts/plugins' / name
            shipped = self.release / name
            actual.write_bytes(payload)
            shipped.write_bytes(payload)
            self.rows.append({'id': target, 'file': name, 'sha256': hashlib.sha256(payload).hexdigest()})
        (self.release / 'BRIDGE_PLUGIN_MANIFEST.json').write_text(json.dumps({
            'toolVersion': '0.42.0', 'artifacts': self.rows,
        }))
        for name in ('BRIDGE_RELEASE_ALLOWLIST.json', 'SERVERBRIDGE3_CERTIFICATION.json'):
            (self.release / name).write_text('{}')

    def test_actual_final_jar_hashes_match(self):
        self.assertEqual(len(accept.verify_final_jars(self.root, self.release, '0.42.0')), 14)

    def test_modified_shipped_jar_is_rejected(self):
        (self.release / 'neverlauncher-paper-bridge-0.42.0.jar').write_bytes(b'changed')
        with self.assertRaises(accept.ReleaseBlocked):
            accept.verify_final_jars(self.root, self.release, '0.42.0')

    def test_missing_fourteenth_adapter_is_rejected(self):
        (self.release / 'neverlauncher-vanilla-bridge-0.42.0.jar').unlink()
        with self.assertRaises(accept.ReleaseBlocked):
            accept.verify_final_jars(self.root, self.release, '0.42.0')

    def test_duplicated_artifact_hash_is_rejected(self):
        a = self.release / 'neverlauncher-quilt-bridge-0.42.0.jar'
        b = self.release / 'neverlauncher-fabric-bridge-0.42.0.jar'
        a.write_bytes(b.read_bytes())
        self.rows[9]['sha256'] = self.rows[8]['sha256']
        (self.root / 'artifacts/plugins' / a.name).write_bytes(a.read_bytes())
        (self.release / 'BRIDGE_PLUGIN_MANIFEST.json').write_text(json.dumps({
            'toolVersion': '0.42.0', 'artifacts': self.rows,
        }))
        with self.assertRaisesRegex(accept.ReleaseBlocked, 'duplicate byte-identical'):
            accept.verify_final_jars(self.root, self.release, '0.42.0')

    def test_symlinked_artifact_is_rejected(self):
        jar = self.release / 'neverlauncher-sponge-bridge-0.42.0.jar'
        jar.unlink()
        jar.symlink_to(self.root / 'artifacts/plugins' / jar.name)
        with self.assertRaises(accept.ReleaseBlocked):
            accept.verify_final_jars(self.root, self.release, '0.42.0')

    def write_go_log(self, missing=None, skipped=None):
        log = self.root / 'network-faults-0420.go-test.jsonl'
        package = 'gitflic.ru/skif4er/neverlauncher/cli/cmd/neverlauncher'
        lines = []
        for name in fault.REQUIRED:
            if name == missing:
                continue
            lines.append({'Package': package, 'Test': name, 'Action': 'run'})
            lines.append({'Package': package, 'Test': name, 'Action': 'skip' if name == skipped else 'pass'})
        lines.append({'Package': package, 'Action': 'pass'})
        log.write_text('\n'.join(map(json.dumps, lines)) + '\n')
        return log

    def test_covered_faults_only_pass_with_complete_go_events(self):
        report = fault.validate(self.write_go_log(), 'a'*40, '0.42.0')
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(report['tests']), len(fault.REQUIRED))

    def test_missing_fault_result_rejected(self):
        with self.assertRaisesRegex(ValueError, 'not all completed'):
            fault.validate(self.write_go_log(missing=fault.REQUIRED[0]), 'a'*40, '0.42.0')

    def test_skipped_fault_rejected(self):
        with self.assertRaisesRegex(ValueError, 'skipped'):
            fault.validate(self.write_go_log(skipped=fault.REQUIRED[-1]), 'a'*40, '0.42.0')

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, 'commit'):
            fault.validate(self.write_go_log(), '', '0.42.0')

    def test_no_release_acceptance_without_live_evidence(self):
        (self.root / 'VERSION').write_text('0.42.0')
        (self.root / 'serverbridge').mkdir()
        (self.root / 'serverbridge/targets.json').write_text(json.dumps({
            'productVersion': '0.42.0', 'targets': [{'id': name} for name in accept.TARGETS],
        }))
        runtime = self.root / 'runtime'
        runtime.mkdir()
        with self.assertRaises(accept.ReleaseBlocked):
            accept.accept(self.root, self.release, runtime, 'a'*40)


if __name__ == '__main__':
    unittest.main()
