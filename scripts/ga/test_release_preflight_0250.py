"""The production signer must not remove build output if 0.25.0 GA is absent."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

class GAReleasePreflightTests(unittest.TestCase):
    def test_missing_independent_signed_evidence_fails_before_output_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            output=root/'candidate'
            output.mkdir()
            sentinel=output/'important-test-artifact'
            sentinel.write_text('must not be deleted by failed verification')
            env=os.environ.copy()
            env.pop('NEVERLAUNCHER_COMPONENT_GA_ATTESTATIONS_DIR',None)
            env.pop('NEVERLAUNCHER_COMPONENT_GA_PUBLIC_KEY',None)
            result=subprocess.run(['bash',str(ROOT/'scripts/release/build-release.sh'),
                                   '0.25.0',str(output)],env=env,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('signed evidence',result.stderr)
            self.assertEqual(sentinel.read_text(),'must not be deleted by failed verification')

if __name__=='__main__':unittest.main()
