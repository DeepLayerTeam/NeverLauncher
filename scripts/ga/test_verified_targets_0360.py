"""Executable Ed25519 approval and exact-release-byte negative acceptance tests."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parent))
from verified_targets_0360 import Blocked, CHECKS, DOMAIN, TARGETS, paths, verify

COMMIT='a'*40
NOW=datetime(2026,10,28,19,0,tzinfo=timezone.utc)


def timevalue(value): return value.strftime('%Y-%m-%dT%H:%M:%SZ')
def digest(data): return hashlib.sha256(data).hexdigest()

class TargetGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.bundle=base/'release';self.bundle.mkdir()
        self.evidence=base/'evidence';self.evidence.mkdir()
        self.keyfile=base/'trusted.pub'
        self.private=Ed25519PrivateKey.generate()
        self.keyfile.write_text(self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex())
        self.approval={'schemaVersion':'neverlauncher.ga036.targets.v1','version':'0.36.0',
                       'commit':COMMIT,'issuedAtUtc':timevalue(NOW-timedelta(hours=1)),
                       'expiresAtUtc':timevalue(NOW+timedelta(hours=1)),'targets':[]}
        for target in TARGETS:
            bin_name,pkg_name=paths('0.36.0',target)
            binary=(f'{target}:actual-binary').encode()
            package=(f'{target}:actual-package').encode()
            (self.bundle/bin_name).write_bytes(binary)
            (self.bundle/pkg_name).write_bytes(package)
            target_dir=self.evidence/'targets'/target;target_dir.mkdir(parents=True)
            row={'target':target,'status':'certified','binarySha256':digest(binary),
                 'packageSha256':digest(package),'checks':{}}
            for check in CHECKS:
                trace={'schemaVersion':'neverlauncher.ga036.execution.v1','version':'0.36.0',
                       'commit':COMMIT,'target':target,'kind':check,'status':'passed',
                       'actualExecution':True,'simulated':False,
                       'artifactSha256':digest(binary),'executionId':'protected-run-12345'}
                raw=json.dumps(trace,sort_keys=True).encode()
                (target_dir/(check+'.json')).write_bytes(raw)
                row['checks'][check]={'sha256':digest(raw)}
            self.approval['targets'].append(row)
        self.sign()

    def sign(self):
        raw=json.dumps(self.approval,sort_keys=True,separators=(',',':')).encode()
        (self.evidence/'approval.json').write_bytes(raw)
        (self.evidence/'approval.sig').write_text(self.private.sign(DOMAIN+raw).hex())

    def check(self):
        return verify(self.bundle,self.evidence,self.keyfile,'0.36.0',COMMIT,now=NOW)

    def test_real_signature_and_exact_bytes(self):
        report=self.check()
        self.assertEqual(report['status'],'approved-for-release-signing')
        self.assertEqual(len(report['targets']),6)
        self.assertEqual(sum(v['checksPassed'] for v in report['targets']),54)

    def test_reject_changed_binary_even_after_valid_approval(self):
        name,_=paths('0.36.0','linux-x64')
        (self.bundle/name).write_bytes(b'tampered binary')
        with self.assertRaises(Blocked):self.check()

    def test_reject_changed_package(self):
        _,name=paths('0.36.0','windows-arm64')
        (self.bundle/name).write_bytes(b'different signed installer')
        with self.assertRaises(Blocked):self.check()

    def test_reject_unauthorized_added_target(self):
        self.approval['targets'].pop()
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_reject_missing_real_execution(self):
        path=self.evidence/'targets/linux-arm64/minecraftLaunch.json'
        data=json.loads(path.read_text());data['actualExecution']=False
        raw=json.dumps(data).encode();path.write_bytes(raw)
        self.approval['targets'][3]['checks']['minecraftLaunch']['sha256']=digest(raw)
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_reject_skipped_security(self):
        item=self.approval['targets'][0]
        del item['checks']['security']
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_reject_changed_trace(self):
        path=self.evidence/'targets/darwin-x64/serverJoin.json'
        path.write_text('{}')
        with self.assertRaises(Blocked):self.check()

    def test_reject_tampered_approval_signature(self):
        path=self.evidence/'approval.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(Blocked):self.check()

    def test_reject_mismatched_commit_with_resign(self):
        self.approval['commit']='f'*40;self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_reject_expired_operator_approval(self):
        self.approval['expiresAtUtc']=timevalue(NOW-timedelta(minutes=1));self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_reject_symlinked_evidence(self):
        path=self.evidence/'targets/windows-x64/security.json'
        raw=path.read_bytes();path.unlink();(self.evidence/'other.json').write_bytes(raw)
        path.symlink_to(self.evidence/'other.json')
        with self.assertRaises(Blocked):self.check()

    def test_unapproved_new_platform_package_is_blocked(self):
        (self.bundle/'neverlauncher-desktop-0.36.0-windows-riscv64.zip').write_bytes(b'unknown')
        with self.assertRaises(Blocked):self.check()

    def test_legacy_composite_package_not_confused_for_seventh_target(self):
        (self.bundle/'neverlauncher-desktop-0.36.0-windows-amd64.zip').write_bytes(b'legacy composite')
        (self.bundle/'neverlauncher-desktop-0.36.0-macos-universal.zip').write_bytes(b'universal')
        self.assertEqual(len(self.check()['targets']),6)

    def test_reject_wrong_key(self):
        other=Ed25519PrivateKey.generate()
        self.keyfile.write_text(other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex())
        with self.assertRaises(Blocked):self.check()

    def test_reject_duplicate_json_keys(self):
        path=self.evidence/'approval.json'
        path.write_bytes(path.read_bytes().replace(b'"version":',b'"version":"0.36.0","version":',1))
        (self.evidence/'approval.sig').write_text(self.private.sign(DOMAIN+path.read_bytes()).hex())
        with self.assertRaises(Blocked):self.check()

if __name__=='__main__': unittest.main()
