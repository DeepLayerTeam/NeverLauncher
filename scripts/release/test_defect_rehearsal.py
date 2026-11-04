"""Adversarial tests for exact-byte freeze and independently re-run 0.52.12 acceptance."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.release import defect_rehearsal_05212 as m

COMMIT='a'*40
PROJECT='project'


def pair(directory,stem):
    private=Ed25519PrivateKey.generate()
    p=directory/(stem+'.pub')
    der=private.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    p.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo))
    return private,p,hashlib.sha256(der).hexdigest()


def seal(directory,stem,doc,private,domain):
    path=directory/(stem+'.json'); sig=directory/(stem+'.sig')
    path.write_bytes(m.inventory.canonical(doc)+b'\n')
    sig.write_bytes(private.sign(domain+m.inventory.canonical(doc)))
    return path,sig


def index_fixture(root):
    packages=root/'packages';packages.mkdir()
    assets=[]
    for osname in ('windows','linux','macos'):
        for arch in ('x64','arm64'):
            filename=m.native.expected_filename(m.VERSION,PROJECT,osname,arch)
            original=(osname+arch).encode()*100
            (packages/filename).write_bytes(original)
            row={'platform':osname,'architecture':arch,'filename':filename,
                 'url':f'https://release.example.org/{filename}',
                 'sha256':hashlib.sha256(original).hexdigest(),'size':len(original)}
            if osname=='linux':
                signature=b'gpg signature'*20
                (packages/(filename+'.asc')).write_bytes(signature)
                row.update(signatureUrl=f'https://release.example.org/{filename}.asc',
                           signatureSha256=hashlib.sha256(signature).hexdigest(),
                           signatureSize=len(signature))
            assets.append(row)
    doc={'schema':m.native.SCHEMA,'version':m.VERSION,'commit':COMMIT,
         'project':PROJECT,'assets':assets}
    idx=root/'index.json';idx.write_bytes(m.inventory.canonical(doc))
    return packages,idx,m.sha(idx)

class CandidateTests(unittest.TestCase):
    def test_version_is_real_candidate(self):
        self.assertEqual(m.VERSION,'0.53.0')
        self.assertEqual(m.SCHEMA,'neverlauncher.candidate-freeze/0.53.0')

    def test_six_exact_bytes_are_verified(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); packages,index,pin=index_fixture(root)
            files=m.package_set(packages,index,pin,COMMIT,PROJECT)
            self.assertEqual(len(files),8)
            corrupted=packages/m.native.expected_filename(m.VERSION,PROJECT,'windows','x64')
            corrupted.write_bytes(corrupted.read_bytes()+b'changed')
            with self.assertRaises(m.Blocked):
                m.package_set(packages,index,pin,COMMIT,PROJECT)

    def test_missing_signature_and_extra_package_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); packages,index,pin=index_fixture(root)
            (packages/'extra').write_text('surprise')
            with self.assertRaises(m.Blocked):
                m.package_set(packages,index,pin,COMMIT,PROJECT)
            (packages/'extra').unlink()
            signature=next(packages.glob('*.asc'))
            signature.unlink()
            with self.assertRaises(m.Blocked):
                m.package_set(packages,index,pin,COMMIT,PROJECT)

    def test_symlink_to_final_package_cannot_pass(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); packages,index,pin=index_fixture(root)
            asset=packages/m.native.expected_filename(m.VERSION,PROJECT,'linux','x64')
            copy=root/'copy.deb';copy.write_bytes(asset.read_bytes())
            asset.unlink();asset.symlink_to(copy)
            with self.assertRaises(m.Blocked):
                m.package_set(packages,index,pin,COMMIT,PROJECT)

    def test_source_not_clean_fails_closed(self):
        with mock.patch.object(m,'git',side_effect=['a'*40,' M VERSION']):
            with self.assertRaisesRegex(m.Blocked,'dirty'):
                m.source_identity(COMMIT)

    def test_release_signed_freeze_cannot_be_reused_after_byte_change(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); packages,index,pin=index_fixture(root)
            private,pub,kpin=pair(root,'release')
            with mock.patch.object(m,'source_identity',return_value='b'*40):
                frozen=m.freeze(COMMIT,PROJECT,packages,index,pin)
                manifest,sig=seal(root,'freeze',frozen,private,m.FREEZE_DOMAIN)
                self.assertEqual(m.sealed_freeze(manifest,sig,pub,kpin,COMMIT,PROJECT,
                                                  packages,index,pin),frozen)
                data=packages/m.native.expected_filename(m.VERSION,PROJECT,'macos','arm64')
                data.write_bytes(data.read_bytes()+b'tamper')
                with self.assertRaises(m.Blocked):
                    m.sealed_freeze(manifest,sig,pub,kpin,COMMIT,PROJECT,packages,index,pin)
                # Altered signed metadata must also be rejected before comparing bytes.
                frozen['sourceTree']='f'*40
                manifest.write_bytes(m.inventory.canonical(frozen))
                with self.assertRaises(m.Blocked):
                    m.verify_signature(m.read(manifest),sig,pub,kpin,m.FREEZE_DOMAIN)

    def test_signed_defect_export_blocks_open_p0_p1(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); private,pub,pin=pair(root,'issues')
            issue={'id':'NL-105','severity':'P1','status':'open',
                   'regression':m.REGRESSIONS[0]}
            base={'schema':m.ISSUES,'version':m.VERSION,'commit':COMMIT,
                  'scope':'all-open-release-defects','issues':[issue]}
            doc,sig=seal(root,'issues',base,private,m.ISSUE_DOMAIN)
            with self.assertRaisesRegex(m.Blocked,'blocking defect'):
                m.closed_defects(doc,sig,pub,pin,COMMIT)
            issue['status']='closed'
            doc,sig=seal(root,'issues',base,private,m.ISSUE_DOMAIN)
            self.assertEqual(m.closed_defects(doc,sig,pub,pin,COMMIT)['criticalClosed'],1)
            issue['regression']='echo green'
            doc,sig=seal(root,'issues',base,private,m.ISSUE_DOMAIN)
            with self.assertRaisesRegex(m.Blocked,'real mandatory regression'):
                m.closed_defects(doc,sig,pub,pin,COMMIT)

    def test_modified_defect_export_cannot_reuse_signature(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); private,pub,pin=pair(root,'issues')
            base={'schema':m.ISSUES,'version':m.VERSION,'commit':COMMIT,
                  'scope':'all-open-release-defects','issues':[]}
            doc,sig=seal(root,'issues',base,private,m.ISSUE_DOMAIN)
            self.assertEqual(m.closed_defects(doc,sig,pub,pin,COMMIT)['issueCount'],0)
            base['issues']=[{'id':'NL-1','severity':'P0','status':'closed','regression':m.REGRESSIONS[0]}]
            doc.write_bytes(m.inventory.canonical(base))
            with self.assertRaises(m.Blocked):
                m.closed_defects(doc,sig,pub,pin,COMMIT)

    def test_mismatched_external_sweep_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);config=root/'config.json'
            values={k:'/tmp/evidence' for k in m.FULL_PATHS}
            values.update({k:'sample' for k in m.FULL_STRINGS})
            values.update({k:1 for k in m.FULL_INTS})
            config.write_text(json.dumps(values))
            self.assertEqual(m.full_args(config,COMMIT).commit,COMMIT)
            values['compat_results']='../../relative'
            config.write_text(json.dumps(values))
            with self.assertRaises(m.Blocked):
                m.full_args(config,COMMIT)

    def test_rehearsal_cannot_accept_single_pass_or_unsigned_stale_results(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); packages,index,pin=index_fixture(root)
            private,pub,keypin=pair(root,'release')
            _,issue_pub,issue_pin=pair(root,'issues')
            with mock.patch.object(m,'source_identity',return_value='b'*40):
                frozen=m.freeze(COMMIT,PROJECT,packages,index,pin)
                freeze_path,freeze_sig=seal(root,'freeze',frozen,private,m.FREEZE_DOMAIN)
                with mock.patch.object(m,'closed_defects',return_value={'issueCount':0}),\
                     mock.patch.object(m,'run_regressions',return_value=[{'exit':0}]),\
                     mock.patch.object(m,'full_args',return_value=SimpleNamespace(project=PROJECT,index_sha=pin,source_index=index)),\
                     mock.patch.object(m.sweep,'verify_full',side_effect=[{'status':'BLOCKED'}]):
                    with self.assertRaisesRegex(m.Blocked,'not verified'):
                        m.rehearse(freeze_path,freeze_sig,pub,keypin,COMMIT,PROJECT,
                            packages,index,pin,root,root,issue_pub,issue_pin,root,root)

    def test_private_signing_keys_must_be_mode_0600(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);private,pub,pin=pair(root,'reviewer')
            path=root/'reviewer.secret'
            path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            path.chmod(0o644)
            with self.assertRaisesRegex(m.Blocked,'0600'):
                m.private_key(path)
            path.chmod(0o600)
            self.assertIsInstance(m.private_key(path),Ed25519PrivateKey)

if __name__=='__main__':
    unittest.main()
