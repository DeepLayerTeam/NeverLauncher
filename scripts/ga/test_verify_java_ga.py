"""Exercise the actual Ed25519 operator release approval and fail-closed paths."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from verify_java_ga_0310 import verify
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'certification'))
from review_integration_0310 import REQUIRED, review
from run_integration_0310 import CASES

SHA='d'*40

def run(*argv):
    subprocess.run(argv,check=True,capture_output=True)

class ReleaseApprovalTests(unittest.TestCase):
    def test_signed_complete_review_and_reject_tamper(self):
        with tempfile.TemporaryDirectory(prefix='nl-approval-fixture-') as td:
            base=Path(td); evidence=base/'evidence';evidence.mkdir()
            for platform,cases in REQUIRED.items():
                record={'schemaVersion':'1.0','release':'0.31.0','platform':platform,
                        'revision':SHA,'passed':True,'fullyCertified':False,'results':[]}
                for name in sorted(cases):
                    steps=[]
                    for cmd in CASES[name]:
                        parts=[str(base/'binary') if a in ('{root}','{cli}','{parity}','{maven}') else a for a in cmd]
                        steps.append({'command':parts,'exitCode':0,'status':'passed','outputSha256':'f'*64})
                    record['results'].append({'case':name,'status':'passed','steps':steps})
                destination=evidence/platform/'integration-0310.json'
                destination.parent.mkdir()
                destination.write_text(json.dumps(record))
            pub,priv,sig,receipt=[base/x for x in ('operator.pub','operator.pem','approval.sig','approval.json')]
            run('openssl','genpkey','-algorithm','ed25519','-out',str(priv))
            run('openssl','pkey','-in',str(priv),'-pubout','-out',str(pub))
            summary=review(sorted(evidence.rglob('integration-0310.json')),SHA)
            receipt.write_text(json.dumps(summary,indent=2)+'\n')
            run('openssl','pkeyutl','-sign','-rawin','-inkey',str(priv),'-in',str(receipt),'-out',str(sig))
            # Historical 0.31.0 operator approval must be verified against an
            # isolated 0.31.0 VERSION, not against the current product checkout.
            # Never modify the real VERSION or relax production verify().
            historical=base/'historical-root';historical.mkdir()
            (historical/'VERSION').write_text('0.31.0\n')
            with patch('verify_java_ga_0310.ROOT',historical):
                self.assertTrue(verify(evidence,SHA,pub,sig)['crossPlatformIntegrationGatesPassed'])
                # A different commit, changed case result or signature cannot authorize GA.
                with self.assertRaises(ValueError):verify(evidence,'e'*40,pub,sig)
                p=evidence/'linux'/'integration-0310.json';original=p.read_text()
                parsed=json.loads(original);parsed['results'][0]['steps'][0]['outputSha256']='0'*64
                p.write_text(json.dumps(parsed))
                with self.assertRaises(ValueError):verify(evidence,SHA,pub,sig)
                p.write_text(original)
                sig.write_bytes(b'\x00'*64)
                with self.assertRaises(ValueError):verify(evidence,SHA,pub,sig)
                (evidence/'windows'/'integration-0310.json').unlink()
                with self.assertRaises(ValueError):verify(evidence,SHA,pub,sig)

if __name__=='__main__':unittest.main()
