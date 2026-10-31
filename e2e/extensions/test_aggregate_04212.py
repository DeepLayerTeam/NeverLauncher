import copy
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
        for target in TARGETS:
            checks = {}
            for case in CASES:
                check = {'runtime': 'pass', 'jarSha256': 'b' * 64}
                if case in ('java-host', 'gravit-port'):
                    check['signing'] = {'sha256': 'c' * 64, 'wrongKeyDenied': True, 'tamperDenied': True}
                checks[case] = check
            self.write(target, {'target': target, 'status': 'pass', 'version': '0.42.12',
                                'sourceCommit': self.commit, 'checks': checks})

    def write(self, target, body):
        (self.path / f'{target}.json').write_text(json.dumps(body))

    def load(self, target):
        return json.loads((self.path / f'{target}.json').read_text())

    def test_complete(self):
        self.assertEqual(validate(self.path, self.commit)['status'], 'pass')

    def test_missing_target_fails(self):
        (self.path / 'windows-arm64.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            validate(self.path, self.commit)

    def test_stale_commit_fails(self):
        report = self.load('linux-arm64')
        report['sourceCommit'] = '0' * 40
        self.write('linux-arm64', report)
        with self.assertRaisesRegex(ValueError, 'source commit'):
            validate(self.path, self.commit)

    def test_fake_pass_missing_tests_fails(self):
        report = self.load('macos-x64')
        del report['checks']['gravit-port']
        self.write('macos-x64', report)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            validate(self.path, self.commit)

    def test_missing_negative_signature_fails(self):
        report = self.load('windows-x64')
        report['checks']['java-host']['signing']['tamperDenied'] = False
        self.write('windows-x64', report)
        with self.assertRaisesRegex(ValueError, 'negative tests'):
            validate(self.path, self.commit)

    def test_blocked_is_not_pass(self):
        report = self.load('macos-arm64')
        report['status'] = 'blocked'
        self.write('macos-arm64', report)
        with self.assertRaisesRegex(ValueError, 'invalid status'):
            validate(self.path, self.commit)


if __name__ == '__main__':
    unittest.main()
