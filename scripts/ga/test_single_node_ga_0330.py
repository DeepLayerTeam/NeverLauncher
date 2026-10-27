"""Synthetic fixture tests exercise the verifier only; never GA evidence."""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from single_node_ga_0330 import CHECKS, SUITES, TESTED_ARTIFACTS, Blocked, verify, strict_json

COMMIT = 'c' * 40


class SingleNodeGAVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.root / 'independent.pub'
        self.pub.write_bytes(self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex().encode())
        self.rc = {
            'format': 'neverlauncher-03216-rc-test-evidence-v1', 'version': '0.33.0',
            'commit': COMMIT, 'toolchain': 'go version go1.27.3 linux/amd64',
            'suites': [{'suite': name, 'count': count, 'passed': [f'test-{name}-{i}' for i in range(count)]}
                       for name, count in SUITES.items()],
        }
        self.report = {
            'schema': 'neverlauncher-single-node-ga-attestation-v1',
            'version': '0.33.0', 'source_commit': COMMIT,
            'rc_receipt_sha256': '', 'operator': 'CI synthetic fixture (not GA)',
            'environment': {
                'backend_repository': 'sqlite', 'coordinator': 'sqlite',
                'journal_mode': 'wal', 'backend_processes': 1,
                'database_on_local_supported_filesystem': True,
                'postgres_required': False, 'redis_required': False,
                'durable_data_after_restart': True,
            },
            'checks': {c: 'pass' for c in CHECKS},
            'tested_artifacts': {name: 'a'*64 for name in TESTED_ARTIFACTS},
        }
        self.write_fixture()

    def write_fixture(self):
        rc = json.dumps(self.rc, sort_keys=True).encode()
        (self.root / 'SINGLE_NODE_GA_RC.json').write_bytes(rc)
        self.report['rc_receipt_sha256'] = hashlib.sha256(rc).hexdigest()
        att = json.dumps(self.report, sort_keys=True).encode()
        (self.root / 'SINGLE_NODE_GA_ATTESTATION.json').write_bytes(att)
        (self.root / 'SINGLE_NODE_GA_ATTESTATION.sig').write_bytes(
            base64.b64encode(self.key.sign(att)) + b'\n')

    def test_signed_fixture_passes_verifier(self):
        result = verify(self.root, self.pub, COMMIT)
        self.assertEqual(result['checks'], len(CHECKS))
        self.assertEqual(result['status'], 'independently-attested')

    def test_wrong_key_and_tampered_signature_are_rejected(self):
        other = self.root / 'other.pub'
        other.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex().encode())
        with self.assertRaises(Blocked): verify(self.root, other, COMMIT)
        with (self.root / 'SINGLE_NODE_GA_ATTESTATION.sig').open('wb') as fd:
            fd.write(base64.b64encode(b'0'*64))
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_postgres_fallback_is_rejected_even_with_valid_signature(self):
        self.report['environment']['backend_repository'] = 'postgres'
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_redis_fallback_is_rejected_even_with_valid_signature(self):
        self.report['environment']['redis_required'] = True
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_missing_failed_scenarios_are_rejected(self):
        del self.report['checks'][CHECKS[0]]
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)
        self.report['checks'][CHECKS[0]] = 'skip'
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_wrong_commit_and_rc_substitution_are_rejected(self):
        with self.assertRaises(Blocked): verify(self.root, self.pub, 'd'*40)
        self.rc['suites'][0]['passed'].pop()
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_missing_rc_suite_rejected(self):
        self.rc['suites'].pop()
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_missing_tested_artifact_digest_rejected(self):
        del self.report['tested_artifacts'][TESTED_ARTIFACTS[0]]
        self.write_fixture()
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)

    def test_symlink_evidence_and_duplicate_json_key_rejected(self):
        rc = self.root / 'SINGLE_NODE_GA_RC.json'
        rc.unlink()
        rc.symlink_to(self.root / 'SINGLE_NODE_GA_ATTESTATION.json')
        with self.assertRaises(Blocked): verify(self.root, self.pub, COMMIT)
        with self.assertRaises(Blocked): strict_json(b'{"status":true,"status":false}')


if __name__ == '__main__':
    unittest.main()
