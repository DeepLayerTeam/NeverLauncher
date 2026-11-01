"""Real Ed25519 attestation test and negative scenarios; no fake GA receipts."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime,timezone,timedelta
import operations_ga_0460 as ga

class OperationsGATests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.evidence=self.root/'evidence';self.evidence.mkdir(mode=0o700)
        self.bundle=self.root/'bundle';self.bundle.mkdir()
        self.reports={}
        now=datetime.now(timezone.utc).isoformat()
        base={'schema':1,'status':'passed','release':'0.46.0','startedUtc':now,'completedUtc':now,
              'secondOperator':'operator2','firstOperator':'operator1',
              'machineFingerprint':'a'*64,'scope':'live execution of existing operational commands; no inferred cross-host certification'}
        upgrade={**base,'stage':'upgrade-standard','from':'0.45.14','to':'0.46.0',
                 'backupManifestSha256':'b'*64,'identity':{'oldProjectId':'original','oldAdminLogin':'verified','oldProjectRead':'verified'}}
        install={**base,'stage':'install-standard','installedVersion':'0.46.0'}
        self.put('install-standard',install)
        self.put('upgrade-standard',upgrade)
        restore={**base,'stage':'restore-standard','machineFingerprint':'c'*64,'sourceHostFingerprint':'a'*64,
                 'sourceReceiptSha256':ga.operational.sha(self.reports['upgrade-standard']),
                 'backupManifestSha256':'b'*64,'recoveredVersion':'0.45.14',
                 'identity':{'oldProjectId':'original','oldAdminLogin':'verified','oldProjectRead':'verified'}}
        self.put('restore-standard',restore)
        fail={**base,'stage':'failover-network-ha','faults':sorted(['postgres-stopped','redis-stopped','s3-stopped','api-stopped','worker-a-network-partition']),
              'rpoSecondsObservedCanaries':0}
        self.put('failover-network-ha',fail)
        for os,arch,name in [('windows','x64','windows-x64.zip'),('windows','arm64','windows-arm64.zip'),
                              ('linux','x64','linux-x64.tar.gz'),('linux','arm64','linux-arm64.tar.gz'),
                              ('darwin','x64','macos-x64.zip'),('darwin','arm64','macos-arm64.zip')]:
            # Actual names required by the release contract, bytes supplied by
            # caller; test fixtures are not platform-certified installers.
            if os=='linux': filename=f'launcher-linux-{arch}-0.46.0.tar.gz'
            elif os=='windows':filename=f'launcher-desktop-0.46.0-windows-{arch}.zip'
            else:filename=f'launcher-desktop-0.46.0-macos-{arch}.zip'
            (self.bundle/filename).write_bytes((os+arch).encode())

    def put(self,name,data):
        p=self.evidence/(name+'.json');p.write_text(json.dumps(data));p.chmod(0o600)
        self.reports[name]=p

    def attest(self):
        with patch.object(ga,'ROOT',Path(__file__).resolve().parents[2]):
            return ga.build_attestation(self.bundle,self.reports,'a'*40)

    def test_binds_four_real_receipt_structures_six_actual_package_digests(self):
        result=self.attest()
        self.assertEqual(len(result['targets']),6)
        self.assertEqual(len(result['stageReceipts']),4)
        first=result['targets']['windows-x64']
        self.assertEqual(first['sha256'],ga.operational.sha(self.bundle/first['name']))
        self.assertEqual(result['version'],'0.46.0')

    def test_rejects_missing_package_and_symlink(self):
        target=self.bundle/'launcher-desktop-0.46.0-windows-x64.zip'
        target.unlink()
        with self.assertRaisesRegex(ValueError,'missing or unsafe'):self.attest()
        target.symlink_to(self.bundle/'launcher-desktop-0.46.0-windows-arm64.zip')
        with self.assertRaisesRegex(ValueError,'missing or unsafe'):self.attest()

    def test_rejects_partial_failover(self):
        path=self.reports['failover-network-ha'];doc=json.loads(path.read_text());doc['rpoSecondsObservedCanaries']=5
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,'canaries'):self.attest()

    def test_rejects_missing_restored_account(self):
        path=self.reports['restore-standard'];doc=json.loads(path.read_text());doc['identity']['oldAdminLogin']='unverified'
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,'real account'):self.attest()

    def test_rejects_expired_operational_receipt(self):
        path=self.reports['install-standard'];doc=json.loads(path.read_text());doc['completedUtc']=(datetime.now(timezone.utc)-timedelta(days=15)).isoformat()
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,'expired'):self.attest()

    def test_detects_same_host_forgery(self):
        path=self.reports['restore-standard'];doc=json.loads(path.read_text());doc['machineFingerprint']='a'*64
        path.write_text(json.dumps(doc))
        with self.assertRaises(ga.operational.Rejected):self.attest()

    def test_actual_pem_ed25519_signing_and_signature_verification(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from unittest.mock import patch
        key=Ed25519PrivateKey.generate()
        private=self.evidence/'operator.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        private.chmod(0o600)
        import sys
        args=['operations_ga_0460.py','attest','--bundle',str(self.bundle),
              '--source-commit','a'*40,'--operator-private-key',str(private),
              '--output-dir',str(self.evidence)]
        for stage,filename in [('install','install-standard'),('upgrade','upgrade-standard'),
                               ('restore','restore-standard'),('failover','failover-network-ha')]:
            args.extend(['--'+stage+'-receipt',str(self.reports[filename])])
        with patch.object(sys,'argv',args),patch.object(ga.operational,'actor',return_value='operator2'):
            self.assertEqual(ga.main(),0)
        raw=(self.evidence/'OPERATIONS_GA_0460.json').read_bytes()
        sig=base64.b64decode((self.evidence/'OPERATIONS_GA_0460.sig').read_text().strip())
        key.public_key().verify(sig,ga.DOMAIN+raw)
        version='0.46.0'
        import hashlib
        h=lambda b:hashlib.sha256(b).hexdigest()
        bom={'components':[{'sourceFile':'schemas/openapi.yaml',
                            'sourceSha256':json.loads(raw)['openApiV1Sha256']}]}
        (self.bundle/'RELEASE_BOM.json').write_text(json.dumps(bom))
        names=['OPERATIONS_GA_0460.json','OPERATIONS_GA_0460.sig']
        manifest={'version':version,'sourceCommit':'a'*40,'requiredFiles':names,
                  'artifacts':[{'name':name,'required':True,'status':'present',
                                'sha256':ga.operational.sha(self.evidence/name)} for name in names]}
        (self.bundle/'RELEASE_MANIFEST.json').write_text(json.dumps(manifest))
        import shutil
        for name in names: shutil.copyfile(self.evidence/name,self.bundle/name)
        operator_pub=self.root/'operator.pub'
        operator_pub.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        release_pub=self.root/'release.pub'
        release_pub.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.assertEqual(ga.verify_public(self.bundle,operator_pub,release_pub)['status'],'verified')
        # Tampering with final installer bytes must be a hard rejection.
        pkg=self.bundle/'launcher-desktop-0.46.0-windows-x64.zip'
        pkg.write_bytes(b'different')
        with self.assertRaisesRegex(ValueError,'not independently approved'):
            ga.verify_public(self.bundle,operator_pub,release_pub)
        pkg.write_bytes(b'windowsx64')
        self.assertEqual(json.loads(raw)['operator'],'operator2')
        # Signed bytes must be non-replaceable; the operator must issue a
        # distinct new approval for changed platform packages.
        with patch.object(sys,'argv',args),patch.object(ga.operational,'actor',return_value='operator2'):
            self.assertNotEqual(ga.main(),0)

    def test_refuses_existing_evidence_target(self):
        target=self.evidence/'OPERATIONS_GA_0460.json'
        ga.atomic_private(target,b'signed-content')
        self.assertEqual(target.stat().st_mode & 0o777,0o600)
        with self.assertRaises(ga.operational.Rejected):ga.atomic_private(target,b'overwrite')
        self.assertEqual(target.read_bytes(),b'signed-content')

if __name__=='__main__':unittest.main()

# A real private-key signing operation is required, not a synthetic PASS file.
# Exercise the same CLI entrypoint that the independent operator will use.
