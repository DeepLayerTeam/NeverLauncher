"""Signed release-policy regression tests. Fixtures test a verifier, not game execution."""
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_verified_targets_0360 import TargetGateTests, COMMIT, NOW, timevalue, digest
from verified_targets import Blocked, approval_data, paths, verify
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
from release_policy import policy, rc_extended, rc_supported

class VersionIndependentGATests(TargetGateTests):
    # Inherit all 15 existing negative tests but convert fixture to v2. The
    # historic tests still run independently with the untouched 0.36.0 domain.
    def setUp(self):
        super().setUp()
        cfg=policy('0.36.1')
        self.approval['schemaVersion']=cfg.approval_schema
        self.approval['version']='0.36.1'
        for row in self.approval['targets']:
            target=row['target']
            previous, old_package=paths('0.36.0',target)
            binary, new_package=paths('0.36.1',target)
            assert binary==previous
            (self.bundle/old_package).rename(self.bundle/new_package)
            for check in row['checks']:
                p=self.evidence/'targets'/target/(check+'.json')
                doc=json.loads(p.read_text())
                doc['schemaVersion']=cfg.execution_schema
                doc['version']='0.36.1'
                raw=json.dumps(doc,sort_keys=True).encode()
                p.write_bytes(raw)
                row['checks'][check]['sha256']=digest(raw)
        self.sign()

    def sign(self):
        cfg=policy(self.approval['version'])
        raw=json.dumps(self.approval,sort_keys=True,separators=(',',':')).encode()
        (self.evidence/'approval.json').write_bytes(raw)
        (self.evidence/'approval.sig').write_text(self.private.sign(cfg.signing_domain+raw).hex())

    def check(self):
        return verify(self.bundle,self.evidence,self.keyfile,'0.36.1',COMMIT,now=NOW)

    def test_reject_changed_package(self):
        _, name=paths('0.36.1','windows-arm64')
        (self.bundle/name).write_bytes(b'different signed installer')
        with self.assertRaises(Blocked):self.check()

    def test_v2_verified_receipt_is_version_bound(self):
        receipt=self.check()
        self.assertEqual(receipt['schemaVersion'],'neverlauncher.ga.verified-targets.v2')
        self.assertEqual(receipt['version'],'0.36.1')

    def test_legacy_0360_signed_approval_cannot_authorize_0361(self):
        self.approval['schemaVersion']='neverlauncher.ga036.targets.v1'
        self.approval['version']='0.36.0'
        raw=json.dumps(self.approval,sort_keys=True,separators=(',',':')).encode()
        (self.evidence/'approval.json').write_bytes(raw)
        (self.evidence/'approval.sig').write_text(self.private.sign(policy('0.36.0').signing_domain+raw).hex())
        with self.assertRaises(Blocked):self.check()

    def test_forged_v2_signature_with_legacy_domain_denied(self):
        raw=(self.evidence/'approval.json').read_bytes()
        (self.evidence/'approval.sig').write_text(self.private.sign(policy('0.36.0').signing_domain+raw).hex())
        with self.assertRaises(Blocked):self.check()

    def test_missing_approval_and_unknown_key_fail(self):
        (self.evidence/'approval.sig').unlink()
        with self.assertRaises((Blocked,OSError)):self.check()
        self.sign()
        self.keyfile.unlink()
        with self.assertRaises((Blocked,OSError)):self.check()

    def test_version_bump_cannot_reuse_0361_approval(self):
        with self.assertRaises(Blocked):
            verify(self.bundle,self.evidence,self.keyfile,'0.36.2',COMMIT,now=NOW)

    def test_preflight_does_not_approve_any_shipping_bytes(self):
        approval_data(self.evidence,self.keyfile,'0.36.1',COMMIT,now=NOW)
        binary,_=paths('0.36.1','linux-x64')
        (self.bundle/binary).unlink()
        with self.assertRaises(Blocked):self.check()

    def test_future_policy_does_not_drop_release_gates(self):
        self.assertEqual(policy('0.36.0').ga_mode,'legacy-ga036')
        self.assertEqual(policy('0.36.1').ga_mode,'signed-ga-v2')
        self.assertEqual(policy('0.37.0').ga_mode,'signed-ga-v2')
        self.assertEqual(policy('1.0.0').ga_mode,'signed-ga-v2')
        self.assertTrue(rc_supported('0.36.1'))
        self.assertTrue(rc_extended('1.0.0'))
        with self.assertRaises(ValueError):policy('0.36.1-rc.1')
        with self.assertRaises(ValueError):policy('0.36.01')

    # This historical test adds a 0.36.0 package; for v2 it must be rejected
    # only if it matches the active version's unapproved target pattern.
    def test_unapproved_new_platform_package_is_blocked(self):
        (self.bundle/'neverlauncher-desktop-0.36.1-windows-riscv64.zip').write_bytes(b'unknown')
        with self.assertRaises(Blocked):self.check()

    def test_legacy_composite_package_not_confused_for_seventh_target(self):
        (self.bundle/'neverlauncher-desktop-0.36.1-windows-amd64.zip').write_bytes(b'legacy composite')
        (self.bundle/'neverlauncher-desktop-0.36.1-macos-universal.zip').write_bytes(b'universal')
        self.assertEqual(len(self.check()['targets']),6)

    def test_reject_duplicate_json_keys(self):
        p=self.evidence/'approval.json'
        p.write_bytes(p.read_bytes().replace(b'"version":',b'"version":"0.36.1","version":',1))
        (self.evidence/'approval.sig').write_text(self.private.sign(policy('0.36.1').signing_domain+p.read_bytes()).hex())
        with self.assertRaises(Blocked):self.check()

    def test_reject_mismatched_commit_with_resign(self):
        self.approval['commit']='f'*40;self.sign()
        with self.assertRaises(Blocked):self.check()

if __name__=='__main__': unittest.main()
