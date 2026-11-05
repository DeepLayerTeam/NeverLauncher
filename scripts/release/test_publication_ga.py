"""Независимый контроль публикации 0.53.0: синтетические артефакты используются только в тестах."""
from __future__ import annotations
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.release import publication_ga_0530 as m
from scripts.release.test_defect_rehearsal_05212 import index_fixture, COMMIT, PROJECT

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
