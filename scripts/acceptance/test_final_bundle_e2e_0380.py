"""Unit tests of fail-closed exact-binary evidence; not live E2E evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

FILE = Path(__file__).with_name('final_bundle_e2e_0380.py')
spec = importlib.util.spec_from_file_location('final_bundle_e2e_0380', FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
COMMIT = 'a' * 40
VERSION = '0.38.0'


class FinalBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        (self.folder / m.BINARY).write_bytes(b'signed-real-artifact-placeholder-only-for-unit-tests')
        (self.folder / m.BINARY).chmod(0o755)
        (self.folder / 'RELEASE_MANIFEST.json').write_text(json.dumps(
            {'version': VERSION, 'sourceCommit': COMMIT}))
        (self.folder / 'SHA256SUMS.sig').write_text('unit-test-only-signature')
        self.write_sums()

    def write_sums(self):
        (self.folder / 'SHA256SUMS').write_text(m.sha(self.folder / m.BINARY) + '  ' + m.BINARY + '\n')

    def test_exact_final_binary_identity(self):
        identity = m.identity(self.folder, VERSION, COMMIT)
        self.assertEqual(identity['binarySha256'], m.sha(self.folder / m.BINARY))

    def test_wrong_version_commit_or_bytes_refused(self):
        with self.assertRaises(m.Blocked):
            m.identity(self.folder, '0.37.8', COMMIT)
        with self.assertRaises(m.Blocked):
            m.identity(self.folder, VERSION, 'b' * 40)
        (self.folder / m.BINARY).write_bytes(b'changed-after-signing')
        with self.assertRaisesRegex(m.Blocked, 'differs'):
            m.identity(self.folder, VERSION, COMMIT)

    def test_duplicate_unsigned_or_missing_binary_refused(self):
        sums = self.folder / 'SHA256SUMS'
        sums.write_text(sums.read_text() * 2)
        with self.assertRaisesRegex(m.Blocked, 'duplicate'):
            m.identity(self.folder, VERSION, COMMIT)
        sums.write_text('f' * 64 + '  other-file\n')
        with self.assertRaisesRegex(m.Blocked, 'missing'):
            m.identity(self.folder, VERSION, COMMIT)

    def test_all_21_real_execution_steps_required(self):
        expected = {'productVersion': VERSION, 'sourceCommit': COMMIT, 'binarySha256': 'f' * 64}
        report = {'schemaVersion': 1, 'status': 'passed', 'scope': 'minimal-linux-real-process-no-ga-attestation', **expected,
                  'checks': [{'id': name, 'status': 'passed', 'durationMs': 2} for name in sorted(m.REQUIRED_CHECKS)]}
        m.validate_live_report(report, expected)
        report['checks'].pop()
        with self.assertRaises(m.Blocked):
            m.validate_live_report(report, expected)
        report['checks'].append({'id': 'fake', 'status': 'passed', 'durationMs': 3})
        with self.assertRaises(m.Blocked):
            m.validate_live_report(report, expected)

    def test_release_workflow_executes_signed_final_bundle_before_publication(self):
        workflow = FILE.parents[2] / '.github/workflows/production-release-candidate.yml'
        data = workflow.read_text(encoding='utf-8')
        start = data.index('  release-bundle:')
        end = data.index('  required-production-ci:')
        job = data[start:end]
        build = job.index('run: bash scripts/release/build-release.sh')
        e2e = job.index('python3 scripts/acceptance/final_bundle_e2e_0380.py')
        self.assertLess(build, e2e)
        self.assertIn('--bundle "$DIR" --version "$VERSION" --commit "$GITHUB_SHA"', job)
        self.assertIn('path: |\n            ${{ runner.temp }}/nl-final-bundle-e2e-0380.json', job)
        self.assertIn('if-no-files-found: error', job[e2e:])
        self.assertLess(e2e, job.index('Require current source production package rehearsal'))

    def test_status_or_binary_mismatch_refused(self):
        expected = {'productVersion': VERSION, 'sourceCommit': COMMIT, 'binarySha256': 'f' * 64}
        report = {'schemaVersion': 1, 'status': 'blocked', 'scope': 'minimal-linux-real-process-no-ga-attestation', **expected,
                  'checks': [{'id': name, 'status': 'passed', 'durationMs': 2} for name in sorted(m.REQUIRED_CHECKS)]}
        with self.assertRaises(m.Blocked):
            m.validate_live_report(report, expected)
        report['status'] = 'passed'
        report['binarySha256'] = '0' * 64
        with self.assertRaises(m.Blocked):
            m.validate_live_report(report, expected)


if __name__ == '__main__':
    unittest.main()
