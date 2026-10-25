import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from run_integration_0310 import CASES, run_cases
from review_integration_0310 import REQUIRED, review

SHA = 'a'*40

class IntegrationCertificationTests(unittest.TestCase):
    def test_real_subprocess_and_report(self):
        with tempfile.TemporaryDirectory() as td:
            # The runner really executes a subprocess: no path-based success.
            with patch.dict(CASES, {'check': (("python3", "-c", "print('pass')"),)}):
                report = run_cases(['check'], Path(td)/'report.json', timeout=5, cli='', commit=SHA)
            self.assertTrue(report['passed'])
            self.assertFalse(report['fullyCertified'])
            self.assertEqual(len(report['results'][0]['steps'][0]['outputSha256']),64)

    def test_rejected_failures_timeouts_and_skipped_tests(self):
        with tempfile.TemporaryDirectory() as td:
            for cmd in [
                ("python3", "-c", "raise SystemExit(2)"),
                ("python3", "-c", "import time;time.sleep(3)"),
            ]:
                with patch.dict(CASES, {'failure': (cmd,)}):
                    r = run_cases(['failure'], Path(td)/'report.json', timeout=.4, cli='', commit=SHA)
                    self.assertFalse(r['passed'])
                    self.assertEqual(r['results'][0]['status'],'failed')
            # Simulate a Go suite that exits 0 but silently skips its E2E.
            # It must never be interpreted as a successful certification.
            with patch.dict(CASES, {'skip': (("go", "test", "-v", "./internal/lanmdns"),)}):
                with patch("run_integration_0310.subprocess.Popen") as spawn:
                    child = spawn.return_value
                    child.communicate.return_value = (b"=== RUN   TestReal\n--- SKIP: TestReal (0.00s)\nPASS\n", b"")
                    child.returncode = 0
                    r = run_cases(['skip'], Path(td)/'skip.json', timeout=3, cli='', commit=SHA)
                self.assertFalse(r['passed'])
                self.assertEqual(r['results'][0]['steps'][0]['status'], 'skipped')

    def test_rejected_invalid_case_selection(self):
        with tempfile.TemporaryDirectory() as td:
            for cases in [['none'], ['java-sdk','java-sdk'], []]:
                with self.assertRaises(ValueError):
                    run_cases(cases, Path(td)/'no.json', timeout=10, cli='', commit=SHA)

    def test_review_rejects_missing_os_skips_and_spoofed_revision(self):
        with tempfile.TemporaryDirectory() as td:
            files=[]
            for osname, cases in REQUIRED.items():
                obj={'schemaVersion':'1.0', 'release':'0.31.0', 'platform':osname,
                     'revision':SHA,'passed':True,'fullyCertified':False,
                     'results':[{'case':name,'status':'passed','steps':[
                         {'status':'passed','exitCode':0,'outputSha256':'a'*64, 'command':[str(Path(td)/'artifact') if p in {'{cli}','{root}','{parity}','{maven}'} else p for p in cmd]} for cmd in CASES[name]]} for name in sorted(cases)]}
                path=Path(td)/osname/'integration-0310.json'
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(obj))
                files.append(path)
            self.assertTrue(review(files,SHA)['crossPlatformIntegrationGatesPassed'])
            with self.assertRaisesRegex(ValueError,'missing required operating systems'):
                review(files[:-1],SHA)
            with self.assertRaisesRegex(ValueError,'wrong schema'):
                review(files,'b'*40)
            obj=json.loads(files[0].read_text())
            obj['results'][0]['status']='skipped'
            files[0].write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError,'failed/skipped'):
                review(files,SHA)

if __name__=='__main__':unittest.main()
