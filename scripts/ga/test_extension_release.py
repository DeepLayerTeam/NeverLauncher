import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extension_release_0430 import certify, verify_matrix, PACKAGES, ROOT
sys.path.insert(0, str(ROOT / 'e2e/extensions'))
from aggregate_04212 import TARGETS, CASES, validate


class FinalExtensionReleaseTests(unittest.TestCase):
    """All synthetic records in this test are fixtures, never production evidence."""

    def setUp(self):
        self.scope = tempfile.TemporaryDirectory()
        self.addCleanup(self.scope.cleanup)
        self.base = Path(self.scope.name)
        self.evidence = self.base / 'evidence'
        self.bundle = self.base / 'bundle'
        self.evidence.mkdir()
        self.bundle.mkdir()
        self.commit = 'a' * 40
        self.version = '0.43.0'
        self.run = '10011'
        self.attempt = '1'
        for target in TARGETS:
            checks = {}
            for case in CASES:
                checks[case] = {'runtime': 'pass', 'jarSha256': 'b' * 64}
                if case in ('java-host', 'gravit-port'):
                    checks[case]['signing'] = {'sha256': 'c' * 64,
                                              'wrongKeyDenied': True, 'tamperDenied': True}
            (self.evidence / f'{target}.json').write_text(json.dumps({
                'target': target, 'version': self.version, 'status': 'pass',
                'sourceCommit': self.commit, 'runId': self.run,
                'runAttempt': self.attempt, 'checks': checks,
                'gravitMatrixAudit': {'status': 'source-verified-not-equivalent',
                  'modules': 19, 'sha256': hashlib.sha256(
                    (ROOT / 'compatibility/gravit/module-parity-04211.json').read_bytes()).hexdigest()}}))
        self.certificate = self.evidence / 'extension-acceptance-certificate.json'
        self.certificate.write_text(json.dumps(validate(self.evidence, self.commit,
                                 self.version, self.run, self.attempt)))
        self.cli = self.base / 'nl'
        self.cli.write_text('fixture')
        self.key = self.base / 'pub.pem'
        self.key.write_text('fixture')
        for key, (filename, jar) in PACKAGES.items():
            with zipfile.ZipFile(self.bundle / filename, 'w') as zf:
                zf.writestr('payload/' + jar, 'compiled fixture JAR')

    def check(self):
        with patch('extension_release_0430.subprocess.run') as mock:
            mock.return_value.returncode = 0
            return certify(evidence=self.evidence, bundle=self.bundle, cli=self.cli,
                           publisher_key=self.key, version=self.version, commit=self.commit,
                           run_id=self.run, attempt=self.attempt,
                           matrix=ROOT/'compatibility/gravit/module-parity-04211.json')

    def test_successful_all_six_with_signed_package_verifier(self):
        result = self.check()
        self.assertEqual(result['modulesAudited'], 19)
        self.assertEqual(result['targetCount'], 6)
        self.assertEqual(len(result['signedPackages']), 2)

    def test_missing_target_fails_closed(self):
        (self.evidence / 'macos-arm64.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.check()

    def test_replayed_run_fails_closed(self):
        report = json.loads((self.evidence / 'linux-x64.json').read_text())
        report['runAttempt'] = '9'
        (self.evidence / 'linux-x64.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'run identity'):
            self.check()

    def test_tampered_certificate_fails(self):
        doc = json.loads(self.certificate.read_text())
        doc['platforms']['linux-x64']['evidenceSha256'] = '0'*64
        self.certificate.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.check()

    def test_missing_signed_package_fails(self):
        (self.bundle / PACKAGES['java-host'][0]).unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.check()

    def test_bad_publisher_signature_fails(self):
        with patch('extension_release_0430.subprocess.run') as mock:
            mock.return_value.returncode = 1
            mock.return_value.stderr = 'signature mismatch'
            with self.assertRaisesRegex(ValueError, 'signing check failed'):
                certify(evidence=self.evidence, bundle=self.bundle, cli=self.cli,
                        publisher_key=self.key, version=self.version, commit=self.commit,
                        run_id=self.run, attempt=self.attempt,
                        matrix=ROOT/'compatibility/gravit/module-parity-04211.json')

    def test_binary_parity_cannot_be_falsely_verified(self):
        matrix = ROOT / 'compatibility/gravit/module-parity-04211.json'
        doc = json.loads(matrix.read_text())
        doc['modules'][0]['status'] = 'verified'
        path = self.base / 'fake-matrix.json'
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, 'separate module-specific live proof'):
            verify_matrix(path)

    def test_module_limitations_must_be_explicit(self):
        matrix = ROOT / 'compatibility/gravit/module-parity-04211.json'
        doc = json.loads(matrix.read_text())
        doc['modules'][1]['limitations'] = ''
        path = self.base / 'fake-matrix.json'
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, 'missing explicit outcome'):
            verify_matrix(path)


if __name__ == '__main__':
    unittest.main()
