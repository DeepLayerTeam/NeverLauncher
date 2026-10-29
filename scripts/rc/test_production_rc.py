import json
import os
import tempfile
import unittest
from pathlib import Path

from production_rc import SUITES, RC_03514_SUITES, suites_for_version, GateError, validate_events, validate_preflight


class TestRCGate(unittest.TestCase):
    def setUp(self):
        self.suite = SUITES[-1]

    def events(self, omit=(), skip=(), fail=()):
        return '\n'.join(json.dumps({'Action': 'skip' if t in skip else 'fail' if t in fail else 'pass',
                                       'Test': t}) for t in self.suite.tests if t not in omit)

    def test_current_version_executes_extra_protected_go_regressions(self):
        active = suites_for_version('0.35.14')
        self.assertEqual(active[-2:], RC_03514_SUITES)
        self.assertGreater(len(active), len(SUITES))
        self.assertEqual(suites_for_version('0.36.0')[-2:], RC_03514_SUITES)
        self.assertEqual(suites_for_version('0.36.1')[-2:], RC_03514_SUITES)
        self.assertEqual(suites_for_version('0.37.0')[-2:], RC_03514_SUITES)
        self.assertEqual(suites_for_version('0.33.0'), SUITES)
        with self.assertRaises(GateError):
            suites_for_version('0.35.13')

    def test_complete_pass_only(self):
        evidence = validate_events(self.events(), self.suite, 0)
        self.assertEqual(evidence['count'], len(self.suite.tests))

    def test_missing_skipped_failed_and_process_error_block(self):
        for kwargs, status in [({'omit': (self.suite.tests[0],)}, 0),
                               ({'skip': (self.suite.tests[0],)}, 0),
                               ({'fail': (self.suite.tests[0],)}, 0),
                               ({}, 1)]:
            with self.subTest(kwargs=kwargs, status=status), self.assertRaises(GateError):
                validate_events(self.events(**kwargs), self.suite, status)

    def test_duplicate_results_and_package_failure_block(self):
        with self.assertRaises(GateError):
            validate_events(self.events() + '\n' + self.events(), self.suite, 0)
        with self.assertRaises(GateError):
            validate_events(self.events() + '\n' + json.dumps({'Action': 'fail', 'Package': 'x'}), self.suite, 0)

    def test_live_dependencies_and_private_volume_required(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'db'
            p.mkdir(mode=0o700)
            env = {k: 'test-value' for k in __import__('production_rc').REQUIRED_ENV}
            env['NEVERLAUNCHER_SQLITE_TEST_ROOT'] = str(p)
            env['NEVERLAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS'] = '1'
            self.assertEqual(validate_preflight(env), str(p.resolve()))
            del env['NEVERLAUNCHER_RC_S3_SECRET_KEY']
            with self.assertRaises(GateError):
                validate_preflight(env)
            env['NEVERLAUNCHER_RC_S3_SECRET_KEY'] = 'test-value'
            env['NEVERLAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS'] = '0'
            with self.assertRaises(GateError):
                validate_preflight(env)


if __name__ == '__main__':
    unittest.main()
