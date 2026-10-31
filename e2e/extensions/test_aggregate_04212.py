import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from aggregate_04212 import TARGETS, CASES, validate


class FailClosedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.commit = 'a' * 40
        self.version = '0.43.0'
        self.run_id = '1234567'
        self.run_attempt = '1'
        for target in TARGETS:
            checks = {}
            for case in CASES:
                check = {'runtime': 'pass', 'jarSha256': 'b' * 64}
                if case in ('java-host', 'gravit-port'):
                    check['signing'] = {'sha256': 'c' * 64, 'wrongKeyDenied': True, 'tamperDenied': True}
                checks[case] = check
            source_root = Path(__file__).resolve().parents[2]
            matrix_sha = hashlib.sha256((source_root / 'compatibility/gravit/module-parity-04211.json').read_bytes()).hexdigest()
            self.write(target, {'target': target, 'status': 'pass', 'version': self.version,
                                'sourceCommit': self.commit, 'runId': self.run_id,
                                'runAttempt': self.run_attempt, 'checks': checks,
                                'gravitMatrixAudit': {'status': 'source-verified-not-equivalent',
                                                      'modules': 19, 'sha256': matrix_sha}})

    def write(self, target, body):
        (self.path / f'{target}.json').write_text(json.dumps(body))

    def load(self, target):
        return json.loads((self.path / f'{target}.json').read_text())

    def test_complete(self):
        self.assertEqual(validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)['status'], 'pass')

    def test_missing_target_fails(self):
        (self.path / 'windows-arm64.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_stale_commit_fails(self):
        report = self.load('linux-arm64')
        report['sourceCommit'] = '0' * 40
        self.write('linux-arm64', report)
        with self.assertRaisesRegex(ValueError, 'source commit'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_fake_pass_missing_tests_fails(self):
        report = self.load('macos-x64')
        del report['checks']['gravit-port']
        self.write('macos-x64', report)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_missing_negative_signature_fails(self):
        report = self.load('windows-x64')
        report['checks']['java-host']['signing']['tamperDenied'] = False
        self.write('windows-x64', report)
        with self.assertRaisesRegex(ValueError, 'negative tests'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_blocked_is_not_pass(self):
        report = self.load('macos-arm64')
        report['status'] = 'blocked'
        self.write('macos-arm64', report)
        with self.assertRaisesRegex(ValueError, 'invalid status'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_missing_gravit_audit_fails(self):
        report = self.load('macos-arm64')
        report.pop('gravitMatrixAudit')
        self.write('macos-arm64', report)
        with self.assertRaisesRegex(ValueError, 'Gravit 19-module'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_old_version_fails(self):
        report = self.load('linux-x64')
        report['version'] = '0.42.12'
        self.write('linux-x64', report)
        with self.assertRaisesRegex(ValueError, 'version'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_different_run_fails(self):
        report = self.load('windows-x64')
        report['runId'] = '7654321'
        self.write('windows-x64', report)
        with self.assertRaisesRegex(ValueError, 'run identity'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_different_attempt_fails(self):
        report = self.load('macos-arm64')
        report['runAttempt'] = '2'
        self.write('macos-arm64', report)
        with self.assertRaisesRegex(ValueError, 'run identity'):
            validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)

    def test_certificate_includes_bound_file_hashes(self):
        cert = validate(self.path, self.commit, self.version, self.run_id, self.run_attempt)
        self.assertEqual(cert['runId'], self.run_id)
        self.assertRegex(cert['platforms']['linux-x64']['evidenceSha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(len(cert['platforms']), 6)


if __name__ == '__main__':
    unittest.main()
