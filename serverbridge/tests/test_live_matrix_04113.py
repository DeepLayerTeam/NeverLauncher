"""Strict offline regression tests for the live evidence verifier (not game tests)."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'live_matrix_04113.py'
spec = importlib.util.spec_from_file_location('live_matrix_04113', SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
VERSION = '0.41.13'


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        (self.root / 'serverbridge').mkdir()
        (self.root / 'VERSION').write_text(VERSION)
        targets = list(mod.CORE) + ['bukkit', 'quilt', 'sponge', 'vanilla']
        (self.root / 'serverbridge/targets.json').write_text(json.dumps({
            'productVersion': VERSION,
            'targets': [{'id': i, 'minecraft': '1.21.1'} for i in targets],
        }))
        (self.runtime / 'result.json').write_text(json.dumps({
            'version': VERSION, 'status': 'passed', 'mode': 'full',
        }))
        (self.root / 'artifacts/plugins').mkdir(parents=True)
        for service, (node, port) in mod.CORE.items():
            jar = self.root / 'artifacts/plugins' / f'neverlauncher-{service}-bridge-{VERSION}.jar'
            jar.write_bytes(f'real-test-artifact-{service}'.encode())
            log_file = self.runtime / f'live-{service}-04113.log'
            content = (f'NeverLauncher {service} Bridge v3 heartbeat=true\n'
                       'E2EPlayer joined the game\n'
                       'neverlauncher.join.allowed username=E2EPlayer\n'
                       'neverlauncher.join.denied username=E2EPlayer\n')
            log_file.write_text(content)
            proof = {
                'schemaVersion': '1.0', 'productVersion': VERSION, 'service': service,
                'nodeId': node, 'minecraftPort': port,
                'bridgeJarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
                'runtime': {'containerId': 'a' * 64, 'imageId': 'sha256:' + 'b'*64,
                            'hostJavaPid': 22, 'javaMajor': 21, 'startedAt': '2026-10-31T01:00:00Z',
                            'health': 'healthy'},
                'observations': {'signedBridgeHeartbeat': True, 'allowAfterNetworkProbe': True,
                                 'denyAfterRevocation': True, 'actualClientJoin': service == 'paper'},
                'probes': {}, 'log': {'path': log_file.name,
                                     'sha256': hashlib.sha256(log_file.read_bytes()).hexdigest()},
            }
            for kind in ('allow', 'deny'):
                if service == 'paper' and kind == 'allow':
                    name = 'runtime-launch-minecraft.json'
                    payload = '{"success":true}'
                else:
                    name = ('probe-paper-deny.txt' if service == 'paper'
                            else f'probe-{node}-{kind}.txt')
                    payload = f'probe host=127.0.0.1 port={port} username=E2EPlayer terminal=reset'
                path = self.runtime / name
                path.write_text(payload)
                proof['probes'][kind] = {'path': name,
                                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            (self.runtime / f'live-{service}-04113.json').write_text(json.dumps(proof))

    def test_core_evidence_passes_but_full_matrix_does_not(self):
        core = mod.certify(self.root, self.runtime, 'core')
        self.assertEqual(core['status'], 'core-passed-not-full-matrix')
        self.assertEqual(core['passedCount'], 10)
        full = mod.certify(self.root, self.runtime)
        self.assertEqual(full['status'], 'incomplete')
        self.assertEqual(full['passedCount'], 10)
        for target in ('quilt', 'bukkit', 'sponge', 'vanilla'):
            self.assertEqual(full['cases'][target]['status'], 'not-certified')

    def test_missing_result_fails(self):
        (self.runtime / 'result.json').unlink()
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['status'], 'incomplete')

    def test_client_only_status_is_not_live(self):
        (self.runtime / 'result.json').write_text(json.dumps({
            'version': VERSION, 'status': 'passed', 'mode': 'compatibility'}))
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['status'], 'incomplete')

    def test_log_tampering_fails(self):
        (self.runtime / 'live-velocity-04113.log').write_text('fake')
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['velocity']['status'],
                         'not-certified')

    def test_probe_tampering_fails(self):
        (self.runtime / 'probe-velocity-e2e-p3-allow.txt').write_text('fake')
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['velocity']['status'],
                         'not-certified')

    def test_tampered_actual_built_jar_fails(self):
        jar = self.root / 'artifacts/plugins' / f'neverlauncher-velocity-bridge-{VERSION}.jar'
        jar.write_bytes(b'different-live-binary')
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['velocity']['status'],
                         'not-certified')

    def test_missing_bridge_digest_fails(self):
        path = self.runtime / 'live-paper-04113.json'
        proof = json.loads(path.read_text())
        proof.pop('bridgeJarSha256')
        path.write_text(json.dumps(proof))
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['paper']['status'],
                         'not-certified')

    def test_no_java_or_wrong_image_does_not_count(self):
        path = self.runtime / 'live-paper-04113.json'
        proof = json.loads(path.read_text())
        proof['runtime']['hostJavaPid'] = 0
        path.write_text(json.dumps(proof))
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['paper']['status'],
                         'not-certified')

    def test_false_result_flags_do_not_count(self):
        path = self.runtime / 'live-folia-04113.json'
        proof = json.loads(path.read_text())
        proof['observations']['denyAfterRevocation'] = False
        path.write_text(json.dumps(proof))
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['cases']['folia']['status'],
                         'not-certified')

    def test_missing_live_service_does_not_count(self):
        (self.runtime / 'live-forge-04113.json').unlink()
        self.assertEqual(mod.certify(self.root, self.runtime, 'core')['status'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
