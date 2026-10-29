"""Runner unit tests; these DO NOT count as live API acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

NAME = Path(__file__).with_name('minimal_live_e2e_0378.py')
SPEC = importlib.util.spec_from_file_location('minimal_live_e2e_0378', NAME)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class MinimalRunnerTests(unittest.TestCase):
    def test_report_writer_is_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'nested/report.json'
            mod.encode_report(output, {'status': 'blocked', 'checks': []})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text())['status'], 'blocked')
            mod.encode_report(output, {'status': 'passed', 'checks': [{'id':'x'}]})
            self.assertEqual(json.loads(output.read_text())['checks'][0]['id'], 'x')
            self.assertEqual(len(list(output.parent.iterdir())), 1)

    def test_invalid_binary_fails_closed_and_emits_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            work = base/'work'
            work.mkdir()
            report = base/'evidence/report.json'
            guard = base/'guard.json'
            bridge = base/'bridge.json'
            guard.write_text('{}')
            bridge.write_text('{}')
            process = subprocess.run([sys.executable, str(NAME), '--binary', str(base/'missing-api'),
                                      '--guard-policy', str(guard), '--bridge-policy', str(bridge),
                                      '--work-root', str(work), '--report', str(report)],
                                     capture_output=True, text=True, timeout=15)
            self.assertNotEqual(process.returncode, 0)
            evidence = json.loads(report.read_text())
            self.assertEqual(evidence['status'], 'blocked')
            self.assertEqual(evidence['checks'], [])
            self.assertEqual(evidence['failureType'], 'AcceptanceFailure')

    def test_work_root_must_be_empty_and_binary_secure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base/'api'
            binary.write_text('not executed')
            binary.chmod(0o755)
            (base/'guard').write_text('x')
            (base/'bridge').write_text('x')
            work = base/'work'
            work.mkdir()
            (work/'already').write_text('x')
            with self.assertRaisesRegex(mod.AcceptanceFailure, 'empty'):
                mod.run_acceptance(binary, base/'guard', base/'bridge', work, {'checks': []})
            (work/'already').unlink()
            binary.chmod(0o777)
            with self.assertRaisesRegex(mod.AcceptanceFailure, 'permissions'):
                mod.run_acceptance(binary, base/'guard', base/'bridge', work, {'checks': []})

    def test_command_failure_cannot_be_recorded_as_pass(self):
        report = {'checks': []}
        with self.assertRaises(mod.AcceptanceFailure):
            mod.step(report, 'failing', lambda: mod.command(sys.executable, '-c', 'import sys;sys.exit(7)'))
        self.assertEqual(report['checks'], [])


if __name__ == '__main__':
    unittest.main()
