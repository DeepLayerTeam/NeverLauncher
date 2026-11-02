"""Regression: later versions cannot disable signed-payload and input gates."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]

class RetentionTests(unittest.TestCase):
    def test_gates_apply_to_0462_and_future_releases(self):
        source = (ROOT / "scripts/release/build-release.sh").read_text()
        match = re.search(r"(?m)^release_from_0462\(\) \{.*?^\}", source, re.S | re.M)
        self.assertIsNotNone(match)
        # The same predicate guards preflight, package verification and signing.
        self.assertEqual(source.count("if release_from_0462; then"), 6)
        for version, expected in (("0.46.1", "excluded"), ("0.46.2", "included"), ("0.46.3", "included"), ("0.47.0", "included")):
            script = match.group() + '\nVERSION=' + version + '\nif release_from_0462; then printf included; else printf excluded; fi\n'
            proc = subprocess.run(["bash", "-c", script], text=True, capture_output=True, check=True)
            self.assertEqual(proc.stdout, expected)

if __name__ == "__main__": unittest.main()
