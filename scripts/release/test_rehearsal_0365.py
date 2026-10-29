#!/usr/bin/env python3
"""Negative/positive tests for actual package inspection and signed GA binding.
Synthetic PE/ELF/Mach-O fixtures exercise parsing; not a platform-signing claim.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from unittest.mock import patch
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parent))
import rehearsal_0365 as r
from release_policy import policy
from verified_targets import CHECKS, TARGETS, paths, Blocked

VER='0.36.5'
COMMIT='a'*40


def digest(raw):return hashlib.sha256(raw).hexdigest()


def fake_elf(arch):
    data=bytearray(64);data[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<H',data,18,62 if arch=='x64' else 183)
    return bytes(data)


def fake_pe(arch):
    data=bytearray(384);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',data,0x84,0x8664 if arch=='x64' else 0xaa64)
    struct.pack_into('<H',data,0x98,0x20b)
    struct.pack_into('<II',data,0x98+112+32,352,16)
    return bytes(data)


def fake_macho(arch):
    data=bytearray(72);data[:4]=b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I',data,4,0x01000007 if arch=='x64' else 0x0100000c)
    struct.pack_into('<II',data,16,1,16)
    struct.pack_into('<IIII',data,32,0x1d,16,48,24)
    return bytes(data)


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        scope=patch.dict(os.environ,{'GITHUB_RUN_ID':'7654321','GITHUB_RUN_ATTEMPT':'1'})
        scope.start();self.addCleanup(scope.stop)
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.bundle=root/'release';self.bundle.mkdir()
        self.evidence=root/'evidence';self.evidence.mkdir()
        self.key=root/'pub'
        self.private=Ed25519PrivateKey.generate()
        self.key.write_text(self.private.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                         format=serialization.PublicFormat.Raw).hex())
        self.now=datetime.now(timezone.utc)
        self.approval={ 'schemaVersion':policy(VER).approval_schema,'version':VER,'commit':COMMIT,
           'issuedAtUtc':(self.now-timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
           'expiresAtUtc':(self.now+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),'targets':[] }
        for target in TARGETS:self.build_target(target)
        self.sign()

    def build_target(self,target):
        system,arch=target.split('-')
        components={'desktop-launcher':'neverlauncher-desktop','guard':'neverguard',
                    'runtime':'neverruntime','cli':'neverlauncher-cli'}
        if system=='linux':components['api']='neverlauncher-api'
        binaries={role:(fake_pe(arch) if system=='windows' else fake_elf(arch) if system=='linux' else fake_macho(arch))
                  +role.encode() for role in components}
        members={}; entries=[]
        for role,name in components.items():
            if system=='windows':
                inner = name+'.exe'
                if role=='desktop-launcher':inner='neverlauncher-desktop.exe'
            elif system=='linux':inner='neverlauncher/'+name
            else:inner='NeverLauncher.app/Contents/'+('MacOS/' if role=='desktop-launcher' else 'Helpers/')+name
            members[inner]=binaries[role]
            row={'component':role,'sha256':digest(binaries[role]),'size':len(binaries[role])}
            if system=='windows':
                row.update(name=inner,authenticodeStatus='Valid',timestamped=True,
                           signtoolVerified=True,signerThumbprint='a'*40)
            elif system=='linux':row['packagePath']=inner
            else:row.update(bundlePath=inner,codeSigned=True,hardenedRuntime=True,teamId='AAAAAAAAAA')
            entries.append(row)
        embedded={'productVersion':VER,'architecture':arch,'artifacts':entries}
        if system=='windows':
            mn='WINDOWS_PACKAGE_MANIFEST_'+arch.upper()+'.json';inside='WINDOWS_PACKAGE_MANIFEST.json'
        elif system=='linux':
            mn='LINUX_PACKAGE_MANIFEST_'+arch.upper()+'.json';inside='neverlauncher/LINUX_PACKAGE_MANIFEST.json'
        else:
            mn='MACOS_PACKAGE_MANIFEST_'+arch.upper()+'.json';inside='NeverLauncher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json'
        raw=json.dumps(embedded).encode();members[inside]=raw
        members['COMPONENT_SET_SIGNATURE.json']=b'{"signed":true}' if system=='windows' else b''
        if system=='linux':members['neverlauncher/COMPONENT_SET_SIGNATURE.json']=members.pop('COMPONENT_SET_SIGNATURE.json')
        if system=='darwin':members.pop('COMPONENT_SET_SIGNATURE.json')
        (self.bundle/mn).write_bytes(raw)
        bn,pn=paths(VER,target)
        (self.bundle/bn).write_bytes(binaries['desktop-launcher'])
        if system=='linux':
            with tarfile.open(self.bundle/pn,mode='w:gz') as tf:
                for name,data in members.items():
                    info=tarfile.TarInfo(name);info.size=len(data)
                    tf.addfile(info,io.BytesIO(data))
        else:
            with zipfile.ZipFile(self.bundle/pn,'w') as z:
                for name,data in members.items():z.writestr(name,data)
        bsha=digest(binaries['desktop-launcher']);psha=r.sha(self.bundle/pn)
        folder=self.evidence/'targets'/target;folder.mkdir(parents=True)
        row={'target':target,'status':'certified','binarySha256':bsha,'packageSha256':psha,'checks':{}}
        for check in CHECKS:
            trace={'schemaVersion':policy(VER).execution_schema,'version':VER,'commit':COMMIT,
                   'target':target,'kind':check,'status':'passed','actualExecution':True,
                   'simulated':False,'artifactSha256':bsha,'executionId':'protected-run-12345'}
            raw=json.dumps(trace,sort_keys=True).encode()
            (folder/(check+'.json')).write_bytes(raw);row['checks'][check]={'sha256':digest(raw)}
        self.approval['targets'].append(row)

    def sign(self):
        raw=json.dumps(self.approval,sort_keys=True,separators=(',',':')).encode()
        (self.evidence/'approval.json').write_bytes(raw)
        (self.evidence/'approval.sig').write_text(self.private.sign(policy(VER).signing_domain+raw).hex())

    def check(self):return r.certify(self.bundle,self.evidence,self.key,VER,COMMIT)

    def test_valid_six_signed_targets_and_package_payloads(self):
        report=self.check()
        self.assertEqual(report['status'],'package-and-ga-verified')
        self.assertEqual(len(report['targets']),6)

    def test_tamper_binary(self):
        b,_=paths(VER,'linux-x64');(self.bundle/b).write_bytes(b'corrupt')
        with self.assertRaises(Blocked):self.check()

    def test_tamper_package(self):
        _,p=paths(VER,'windows-arm64');(self.bundle/p).write_bytes(b'bad archive')
        with self.assertRaises(Blocked):self.check()

    def test_missing_package(self):
        _,p=paths(VER,'darwin-x64');(self.bundle/p).unlink()
        with self.assertRaises(Blocked):self.check()

    def test_expired_approval(self):
        self.approval['expiresAtUtc']=(self.now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_other_commit(self):
        with self.assertRaises(Blocked):r.certify(self.bundle,self.evidence,self.key,VER,'f'*40)

    def test_other_version(self):
        with self.assertRaises(Blocked):r.certify(self.bundle,self.evidence,self.key,'0.36.6',COMMIT)

    def test_seventh_target(self):
        (self.bundle/f'neverlauncher-desktop-{VER}-windows-riscv64.zip').write_bytes(b'garbage')
        with self.assertRaises(Blocked):self.check()

    def test_extra_signed_target_row(self):
        self.approval['targets'].append(dict(self.approval['targets'][0],target='windows-riscv64'))
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_wrong_arch_with_forged_new_operator_signature(self):
        target='linux-arm64'; bn,pn=paths(VER,target)
        (self.bundle/bn).write_bytes(fake_elf('x64')+b'desktop-launcher')
        self.approval['targets'][TARGETS.index(target)]['binarySha256']=r.sha(self.bundle/bn)
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_archive_contains_parent_path_rejected(self):
        _,pn=paths(VER,'windows-x64')
        with zipfile.ZipFile(self.bundle/pn,'a') as z:z.writestr('../escape','bad')
        self.approval['targets'][TARGETS.index('windows-x64')]['packageSha256']=r.sha(self.bundle/pn)
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_package_missing_component(self):
        _,pn=paths(VER,'windows-x64')
        with zipfile.ZipFile(self.bundle/pn,'r') as z:
            entries={name:z.read(name) for name in z.namelist() if name!='neverguard.exe'}
        with zipfile.ZipFile(self.bundle/pn,'w') as z:
            for name,data in entries.items():z.writestr(name,data)
        self.approval['targets'][TARGETS.index('windows-x64')]['packageSha256']=r.sha(self.bundle/pn)
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_invalid_platform_signing_metadata(self):
        _,pn=paths(VER,'windows-x64')
        with zipfile.ZipFile(self.bundle/pn,'r') as z:members={n:z.read(n) for n in z.namelist()}
        data=json.loads(members['WINDOWS_PACKAGE_MANIFEST.json']);data['artifacts'][0]['authenticodeStatus']='NotSigned'
        raw=json.dumps(data).encode();members['WINDOWS_PACKAGE_MANIFEST.json']=raw
        (self.bundle/'WINDOWS_PACKAGE_MANIFEST_X64.json').write_bytes(raw)
        with zipfile.ZipFile(self.bundle/pn,'w') as z:
            for name,content in members.items():z.writestr(name,content)
        self.approval['targets'][TARGETS.index('windows-x64')]['packageSha256']=r.sha(self.bundle/pn)
        self.sign()
        with self.assertRaises(Blocked):self.check()

    def test_no_approval_signature(self):
        (self.evidence/'approval.sig').unlink()
        with self.assertRaises((Blocked,OSError)):self.check()

    def test_missing_os_signature_check(self):
        del self.approval['targets'][0]['checks']['osSignature'];self.sign()
        with self.assertRaises(Blocked):self.check()

    def prepare_dryrun(self):
        # The unit fixture tests copy/checksum mechanics only. Production calls
        # the release CLI from the signed bundle, never this fixture program.
        report=self.check()
        (self.bundle/'RELEASE_REHEARSAL_0365.json').write_text(json.dumps(report))
        cli=self.bundle/'neverlauncher-cli-linux-x64'
        cli.write_text('#!/bin/sh\n[ "$1" = release ] && [ "$2" = publish-check ]\n')
        cli.chmod(0o755)
        sums=[]
        for p in sorted(self.bundle.iterdir()):
            if p.is_file() and p.name not in ('SHA256SUMS','SHA256SUMS.sig'):
                sums.append(r.sha(p)+'  '+p.name)
        (self.bundle/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
        (self.bundle/'SHA256SUMS.sig').write_text('unit-test-only')
        root=Path(self.tmp.name)
        key=root/'release-public.key';key.write_text('unit-test-only')
        policy_file=root/'trust-policy.json';policy_file.write_text('unit-test-only')
        state=root/'trust-state.json';state.write_text('unit-test-only')
        return cli,key,policy_file,state,root/'staging'

    def test_dry_run_copies_exact_files_and_removes_isolated_stage(self):
        cli,key,policy_file,state,stage=self.prepare_dryrun()
        original_state=state.read_bytes()
        result=r.dry_run(self.bundle,cli,key,policy_file,state,self.evidence,
                         self.key,VER,COMMIT,stage)
        self.assertEqual(result['status'],'passed')
        self.assertFalse(result['published'])
        self.assertFalse(stage.exists())
        self.assertEqual(state.read_bytes(),original_state)

    def test_dry_run_rejects_changed_unsigned_bytes(self):
        cli,key,policy_file,state,stage=self.prepare_dryrun()
        (self.bundle/'neverlauncher-cli-linux-x64').write_text('modified')
        with self.assertRaises(Blocked):
            r.dry_run(self.bundle,cli,key,policy_file,state,self.evidence,
                      self.key,VER,COMMIT,stage)

    def test_dry_run_rejects_reused_old_rehearsal_receipt(self):
        cli,key,policy_file,state,stage=self.prepare_dryrun()
        receipt=json.loads((self.bundle/'RELEASE_REHEARSAL_0365.json').read_text())
        receipt['commit']='b'*40
        (self.bundle/'RELEASE_REHEARSAL_0365.json').write_text(json.dumps(receipt))
        with self.assertRaises(Blocked):
            r.dry_run(self.bundle,cli,key,policy_file,state,self.evidence,
                      self.key,VER,COMMIT,stage)

    def test_dry_run_rejects_unlisted_file(self):
        cli,key,policy_file,state,stage=self.prepare_dryrun()
        (self.bundle/'unapproved-extra.jar').write_text('garbage')
        with self.assertRaises(Blocked):
            r.dry_run(self.bundle,cli,key,policy_file,state,self.evidence,
                      self.key,VER,COMMIT,stage)

    def test_stale_other_ci_run_is_rejected(self):
        self.check()
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'7654322'}):
            # In production, a copied old signed receipt fails its run binding.
            cli,key,policy_file,state,stage=self.prepare_dryrun()
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'7654323'}):
                with self.assertRaises(Blocked):
                    r.dry_run(self.bundle,cli,key,policy_file,state,self.evidence,
                              self.key,VER,COMMIT,stage)

    def test_unapproved_linux_architecture(self):
        self.check()
        (self.bundle/f'neverlauncher-desktop-{VER}-linux-riscv64.zip').write_bytes(b'wrong')
        with self.assertRaises(Blocked): self.check()

if __name__=='__main__':unittest.main()
