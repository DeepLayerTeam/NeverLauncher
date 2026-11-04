#!/usr/bin/env python3
"""Verifies actual Go HMAC journaling bytes through the shipping Python reader."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
reader_source = ROOT / 'scripts/guard_ci/adversarial_pilot_05012.py'
spec = importlib.util.spec_from_file_location('reader0529', reader_source)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

class CrossLanguage0529(unittest.TestCase):
    def test_production_go_writer_python_verifier_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, GO111MODULE='off', GOTOOLCHAIN='local', NL0529_SHADOW_TEST_OUTPUT=tmp)
            result = subprocess.run(['go','test','guard_shadow_05012.go','guard_shadow_05012_test.go',
                                     '-run','TestGuardShadow0529WireFixture','-count=1'],
                                    cwd=ROOT/'services/api/internal/httpapi',env=env,
                                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
            folder=Path(tmp)/'journals';key=Path(tmp)/'key.hex'
            report=reader.analyze_shadow(folder,key)
            self.assertEqual(report['totalEvents'],3)
            self.assertEqual(report['revokedEvents'],1)
            self.assertEqual(report['status'],'BLOCKED')
            self.assertFalse(report['playerHoursCertified'])
            file=next(folder.glob('guard-shadow-*.jsonl'))
            raw=file.read_bytes()
            self.assertNotIn(b'node-private',raw)
            self.assertNotIn(b'session-private',raw)
            self.assertIn(b'"version":"0.52.9"',raw)
            file.write_bytes(raw.replace(b'guard_binding_missing',b'guard_build_revoked'))
            with self.assertRaisesRegex(reader.EvidenceError,'failed MAC'):
                reader.analyze_shadow(folder,key)

if __name__ == '__main__':unittest.main(verbosity=2)
