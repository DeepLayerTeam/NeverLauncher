import json
import tempfile
import unittest
from pathlib import Path

from assert_go_test_0300 import verify


class RealExecutionGate0300Tests(unittest.TestCase):
    def run_events(self, events, mandatory=("TestA",)):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "go-test.json"
            report.write_text("\n".join(json.dumps(e) for e in events))
            verify(report, list(mandatory))

    def test_pass_with_real_package(self):
        self.run_events([
            {"Action": "run", "Package": "p", "Test": "TestA"},
            {"Action": "pass", "Package": "p", "Test": "TestA"},
            {"Action": "pass", "Package": "p"},
        ])

    def test_missing_or_skipped_refused(self):
        for action in ("skip", "fail"):
            with self.assertRaises(ValueError):
                self.run_events([
                    {"Action": action, "Package": "p", "Test": "TestA"},
                    {"Action": "pass", "Package": "p"},
                ])
        with self.assertRaises(ValueError):
            self.run_events([{"Action": "pass", "Package": "p"}])

    def test_package_failure_refused(self):
        with self.assertRaises(ValueError):
            self.run_events([
                {"Action": "pass", "Package": "p", "Test": "TestA"},
                {"Action": "fail", "Package": "p"},
            ])

    def test_tampered_json_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "corrupt.json"
            p.write_text('not-json\n')
            with self.assertRaises(json.JSONDecodeError):
                verify(p, ["TestA"])


if __name__ == "__main__":
    unittest.main()
