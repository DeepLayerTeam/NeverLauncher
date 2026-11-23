"""Независимый контроль публикации 0.53.0: синтетические артефакты используются только в тестах."""
from __future__ import annotations
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.release import publication_ga as m
from scripts.release.test_defect_rehearsal import index_fixture, COMMIT, PROJECT

class PublishGateTests(unittest.TestCase):
 def setUp(self):
    self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
    self.root=Path(self.temp.name)
    self.packages,self.index,self.index_pin=index_fixture(self.root)
    self.bundle=self.root/'bundle';shutil.copytree(self.packages,self.bundle)
    self.private=Ed25519PrivateKey.generate()
    self.public=self.root/'public.pem'
    pub=self.private.public_key()
    self.public.write_bytes(pub.public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))
    self.pin=hashlib.sha256(pub.public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    frozen=m.ga.rehearsal.package_set(self.packages,self.index,self.index_pin,COMMIT,PROJECT)
    self.doc={'schema':m.ga.FINAL_SCHEMA,'version':m.ga.VERSION,'commit':COMMIT,
              'project':PROJECT,'sourceTree':'d'*40,'sourceIndexSha256':self.index_pin,
              'finalPackages':frozen,'qaSha256':'e'*64,'fullSweepSha256':'f'*64,
              'e2eGroups':list(m.ga.GROUPS),'status':'PASS'}
    self.approval=self.root/'approval.json';self.sig=self.root/'approval.sig'
    self.seal()
 def seal(self):
    self.approval.write_bytes(m.ga.inventory.canonical(self.doc)+b'\n')
    self.sig.write_bytes(self.private.sign(m.ga.FINAL_DOMAIN+m.ga.inventory.canonical(self.doc)))
 def verify(self):
    return m.verify(self.approval,self.sig,self.public,self.pin,self.packages,self.index,
                    self.index_pin,self.bundle,COMMIT,PROJECT)
 def test_exact_signed_final_bytes_replay(self):
    self.assertEqual(self.verify()['authorizedPackages'],8)
 def test_stage_imports_real_exact_final_packages_for_root_signature(self):
    target=self.root/'unsigned-release';target.mkdir()
    report=m.stage(approval=self.approval,signature=self.sig,
      verifier_public=self.public,verifier_pin=self.pin,
      packages=self.packages,index=self.index,index_pin=self.index_pin,
      bundle=target,source_commit=COMMIT,project=PROJECT)
    self.assertEqual(report['version'],'1.0.0')
    self.assertEqual(len(report['packages']),8)
    self.assertEqual(len(list(target.iterdir())),9)
    authorized=m.ga.rehearsal.package_set(self.packages,self.index,self.index_pin,COMMIT,PROJECT)
    m.verify_staged_receipt(target,self.verify(),authorized,COMMIT,PROJECT,self.index_pin)
    for name in authorized:
        self.assertEqual((target/name).read_bytes(),(self.packages/name).read_bytes())
    # Repeating staging is forbidden even with an otherwise valid approval.
    with self.assertRaises(m.Blocked):
        m.stage(approval=self.approval,signature=self.sig,
          verifier_public=self.public,verifier_pin=self.pin,
          packages=self.packages,index=self.index,index_pin=self.index_pin,
          bundle=target,source_commit=COMMIT,project=PROJECT)
 def test_mid_copy_failure_cleans_every_partial_file(self):
    from unittest import mock
    import shutil
    target=self.root/'half-staged';target.mkdir()
    original=shutil.copyfileobj
    called=[0]
    def failing_copy(src,dst,*args,**kwargs):
        called[0]+=1
        if called[0]==2:
            dst.write(b'partial bytes')
            raise OSError('simulated disk full')
        return original(src,dst,*args,**kwargs)
    with mock.patch.object(shutil,'copyfileobj',side_effect=failing_copy):
        with self.assertRaisesRegex(OSError,'simulated disk full'):
            m.stage(approval=self.approval,signature=self.sig,
              verifier_public=self.public,verifier_pin=self.pin,
              packages=self.packages,index=self.index,index_pin=self.index_pin,
              bundle=target,source_commit=COMMIT,project=PROJECT)
    self.assertEqual(list(target.iterdir()),[])
 def test_stage_refuses_invalid_independent_signature_without_partial_output(self):
    target=self.root/'not-staged';target.mkdir()
    self.sig.write_bytes(b'x'*64)
    with self.assertRaises(m.ga.rehearsal.Blocked):
        m.stage(approval=self.approval,signature=self.sig,
          verifier_public=self.public,verifier_pin=self.pin,
          packages=self.packages,index=self.index,index_pin=self.index_pin,
          bundle=target,source_commit=COMMIT,project=PROJECT)
    self.assertEqual(list(target.iterdir()),[])
 def test_stage_stops_mismatched_final_bundle_before_signing(self):
    target=self.root/'wrong-bundle';target.mkdir()
    bad=self.packages/m.ga.rehearsal.native.expected_filename(m.ga.VERSION,PROJECT,'macos','x64')
    bad.write_bytes(bad.read_bytes()+b'tamper')
    with self.assertRaises(m.ga.rehearsal.Blocked):
        m.stage(approval=self.approval,signature=self.sig,
          verifier_public=self.public,verifier_pin=self.pin,
          packages=self.packages,index=self.index,index_pin=self.index_pin,
          bundle=target,source_commit=COMMIT,project=PROJECT)
    self.assertEqual(list(target.iterdir()),[])
 def test_staged_receipt_cannot_be_replaced_by_report_without_approval(self):
    target=self.root/'unsigned-release';target.mkdir()
    m.stage(approval=self.approval,signature=self.sig,
      verifier_public=self.public,verifier_pin=self.pin,
      packages=self.packages,index=self.index,index_pin=self.index_pin,
      bundle=target,source_commit=COMMIT,project=PROJECT)
    path=target/m.RECEIPT
    path.write_bytes(path.read_bytes().replace(b'independently-approved-exact-native-packages',b'self-reported'))
    authorized=m.ga.rehearsal.package_set(self.packages,self.index,self.index_pin,COMMIT,PROJECT)
    with self.assertRaises(m.Blocked):
        m.verify_staged_receipt(target,self.verify(),authorized,COMMIT,PROJECT,self.index_pin)
 def test_unsigned_wrong_project_blocks(self):
    with self.assertRaises(m.Blocked):
        m.verify(self.approval,self.sig,self.public,self.pin,self.packages,self.index,
                 self.index_pin,self.bundle,COMMIT,'other-project')
 def test_missing_package_in_actual_publisher_blocks(self):
    next(self.bundle.glob('*.pkg')).unlink()
    with self.assertRaises(m.Blocked):self.verify()
 def test_mismatch_published_payload_blocks(self):
    binary=next(self.bundle.glob('*.exe'))
    binary.write_bytes(binary.read_bytes()+b'injection')
    with self.assertRaises(m.Blocked):self.verify()
 def test_reused_qa_approval_signature_from_another_release_blocks(self):
    self.doc['version']='0.52.12';self.seal()
    with self.assertRaises(m.Blocked):self.verify()
 def test_tampered_approved_status_invalidates_signature(self):
    self.doc['status']='BLOCKED';self.approval.write_bytes(m.ga.inventory.canonical(self.doc))
    with self.assertRaises(m.ga.rehearsal.Blocked):self.verify()
 def test_self_report_without_full_group_count_blocks(self):
    self.doc['e2eGroups'].pop();self.seal()
    with self.assertRaises(m.Blocked):self.verify()
 def test_different_independent_key_pin_blocks(self):
    with self.assertRaises(m.ga.inventory.Blocked):
        m.verify(self.approval,self.sig,self.public,'0'*64,self.packages,self.index,
                 self.index_pin,self.bundle,COMMIT,PROJECT)
 def test_changed_source_index_blocks(self):
    self.index.write_bytes(self.index.read_bytes()+b' ')
    with self.assertRaises(m.Blocked):self.verify()

if __name__=='__main__':unittest.main()
