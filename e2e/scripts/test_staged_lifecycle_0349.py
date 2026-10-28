#!/usr/bin/env python3
"""Actual CLI lifecycle round trips plus fail-closed V09 archive and downloader tests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from staged_lifecycle_0349 import (extract_pinned_prior, interrupted_download, interrupt_and_recover, invoke,
                                   verify_exact, require, digest)
from importlib.machinery import SourceFileLoader
runner=SourceFileLoader('runner_v09',str(Path(__file__).with_name('run-staged-package-0342.py'))).load_module()


def make_pkg(path, ident, version, content):
    (path/'mods').mkdir(parents=True,exist_ok=True)
    value=content
    (path/'mods'/'test.jar').write_bytes(value)
    file={'path':'mods/test.jar','size':len(value),'sha256':hashlib.sha256(value).hexdigest(),
          'required':True,'group':'mods'}
    pkg={'schemaVersion':'1.0','projectId':'project','profileId':'profile','channel':'test',
         'version':version,'packageId':ident,'files':[file]}
    (path/'staged-package-description.json').write_text(json.dumps(pkg))
    signed={**pkg,'signature':{'publicKey':'a'*64}}
    (path/'signed-release-manifest.json').write_text(json.dumps(signed))
    return pkg


class V09Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.old=self.root/'old';self.new=self.root/'new'
        self.prev=make_pkg(self.old,'older','0.34.8',b'previous-release-real-bytes')
        self.next=make_pkg(self.new,'current','0.34.9',b'updated-release-real-bytes')
        self.zip=self.root/'previous.zip'
        with zipfile.ZipFile(self.zip,'w') as z:
            for p in self.old.rglob('*'):
                if p.is_file():z.write(p,p.relative_to(self.old).as_posix())

    def test_previous_bundle_pinning_and_manifest(self):
        out=self.root/'extracted'
        got, signed=extract_pinned_prior(self.zip,digest(self.zip),out,self.next,'a'*64)
        self.assertEqual(got['packageId'],'older')
        self.assertEqual(signed['version'],'0.34.8')
        with self.assertRaisesRegex(ValueError,'host-pinned'):
            extract_pinned_prior(self.zip,'0'*64,self.root/'forged',self.next,'a'*64)

    def test_archive_path_traversal_and_duplicate(self):
        with zipfile.ZipFile(self.zip,'w') as z:z.writestr('../escape',b'bad')
        with self.assertRaisesRegex(ValueError,'unsafe prior-release'):
            extract_pinned_prior(self.zip,digest(self.zip),self.root/'outside',self.next,'a'*64)
        self.assertFalse((self.root/'escape').exists())

    def test_genuine_interrupted_http_then_verified_retry(self):
        scratch=self.root/'scratch';scratch.mkdir()
        evidence=interrupted_download(self.new/'mods'/'test.jar',runner.download_exact,scratch)
        self.assertTrue(evidence['interruptedRejected'])
        self.assertEqual(evidence['artifactSha256'],digest(self.new/'mods'/'test.jar'))

    def test_actual_sigkill_at_staging_and_committing_then_production_recover(self):
        cli=os.environ.get('NL349_CLI')
        if not cli or not Path(cli).is_file():self.skipTest('build real CLI and set NL349_CLI')
        # Large real bytes make prepared/committing journal phases observable
        # without adding ANY test-only sleep or failure hook to the updater.
        for folder,tag in ((self.old,b'A'),(self.new,b'B')):
            data=tag*(24<<20)
            f=folder/'mods'/'test.jar';f.write_bytes(data)
            pkg=json.loads((folder/'staged-package-description.json').read_text())
            pkg['files'][0]['size']=len(data)
            pkg['files'][0]['sha256']=hashlib.sha256(data).hexdigest()
            (folder/'staged-package-description.json').write_text(json.dumps(pkg))
        parent=self.root/'interruptions';parent.mkdir()
        for phase in ('staging','committing'):
            report=interrupt_and_recover(cli,self.old/'staged-package-description.json',
                      self.new/'staged-package-description.json',self.root,parent,os.environ.copy(),phase)
            self.assertTrue(report['previousRestored'])
            self.assertTrue(report['retryVerified'])

    def test_actual_production_updater_install_update_repair_rollback(self):
        cli=os.environ.get('NL349_CLI')
        if not cli or not Path(cli).is_file():self.skipTest('set NL349_CLI to built real NeverLauncher CLI')
        live=self.root/'client';cache=self.root/'cache'
        env=os.environ.copy()
        def call(cmd,pkg,which,expected_success=True):
            return invoke(cli,cmd,['--package',str(pkg/'staged-package-description.json'),
                       '--client-dir',str(live),'--storage-dir',str(cache)],
                       self.root/(which+'.json'),env,expected_success)
        self.assertEqual(call('install',self.old,'initial')['status'],'applied-and-verified')
        verify_exact(live,self.prev)
        # Signed input was deliberately changed; real updater must refuse it and preserve old tree.
        src=self.new/'mods'/'test.jar';orig=src.read_bytes();src.write_bytes(b'broken-source')
        try:call('update',self.new,'invalid-upgrade',False)
        finally:src.write_bytes(orig)
        verify_exact(live,self.prev)
        upgraded=call('update',self.new,'upgrade')
        self.assertEqual(upgraded['status'],'applied-and-verified')
        verify_exact(live,self.next)
        f=live/'mods'/'test.jar';f.write_bytes(b'broken-live')
        call('verify',self.new,'corrupt-verify',False)
        # The preferred cache has precedence over the correct signed input;
        # a poisoned cache must be rejected rather than trusted as a repair.
        prefix=upgraded['apply']['storagePrefix']
        cached=cache/prefix/'mods'/'test.jar'
        cached.parent.mkdir(parents=True,exist_ok=True)
        cached.write_bytes(b'poisoned-cache')
        call('repair',self.new,'poisoned-cache-repair',False)
        self.assertEqual(f.read_bytes(),b'broken-live')
        cached.unlink()
        self.assertEqual(call('repair',self.new,'repaired')['status'],'repaired-and-verified')
        verify_exact(live,self.next)
        restored=invoke(cli,'rollback',['--client-dir',str(live),'--target',upgraded['rollbackSnapshot']],
                        self.root/'rolled-back.json',env)
        self.assertEqual(restored['status'],'rolled-back')
        verify_exact(live,self.prev)

if __name__=='__main__':unittest.main()
