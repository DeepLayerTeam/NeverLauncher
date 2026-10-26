"""Cryptographic gate regression tests; synthetic fixtures NEVER count as live evidence."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

spec = importlib.util.spec_from_file_location("ga_verify_0320", Path(__file__).with_name("ga_verify_0320.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class GAVerification0320(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.commit = 'a'*40
        self.source = 'b'*64
        self.now = dt.datetime.now(dt.timezone.utc)
        self.paths = []
        self.documents = {}
        for tier in sorted(gate.TIERS):
            host = 'Linux'
            if tier == 'windows-live': host = 'Windows'
            if tier == 'macos-live': host = 'Darwin'
            if tier in gate.REQUIRED:
                results = [{'package':pkg,'status':'PASS','exitCode':0,'required':{name:'PASS' for name in gate.EXPECTED_TESTS[tier][pkg]}} for pkg in sorted(gate.REQUIRED[tier])]
            else:
                results = [{'name':name,'status':'PASS','simulated':False,'actualExecution':True,'evidenceSha256':'c'*64} for name in sorted(gate.MANUAL[tier])]
            doc = {'schema':gate.SCHEMA,'tier':tier,'status':'PASS','commit':self.commit, 'productVersion':'0.32.0','sourceSha256':self.source, 'generatedAt':self.now.isoformat(), 'host':{'system':host, 'architecture':'amd64'}, 'results':results}
            self.documents[tier] = doc
            path = self.root / f'{tier}.json'
            self.paths.append(path)
            self.sign(path, doc)

    def sign(self, path, doc):
        raw = json.dumps(doc,sort_keys=True).encode()
        path.write_bytes(raw)
        Path(str(path)+'.sig').write_text(self.key.sign(gate.DOMAIN+raw).hex())

    def verify(self):
        return gate.verify_all(self.paths,self.pub,self.commit,self.source,now=self.now)

    def test_valid_signed_set_accepted(self):
        self.assertEqual(self.verify()['status'],'PASS')

    def test_unsigned_mutation_rejected(self):
        self.paths[0].write_bytes(self.paths[0].read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'signature'):
            self.verify()

    def test_missing_tier_rejected(self):
        with self.assertRaisesRegex(ValueError,'seven independent'):
            gate.verify_all(self.paths[:-1],self.pub,self.commit,self.source,now=self.now)

    def test_wrong_key_rejected(self):
        key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        with self.assertRaisesRegex(ValueError,'signature'):
            gate.verify_all(self.paths,key,self.commit,self.source,now=self.now)

    def test_cross_commit_and_stale_rejected(self):
        tier='linux-live'; path=self.root/f'{tier}.json'
        doc=self.documents[tier]; doc['commit']='f'*40; self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'commit/version'): self.verify()
        doc['commit']=self.commit; doc['generatedAt']=(self.now-dt.timedelta(days=8)).isoformat(); self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'stale'): self.verify()

    def test_skip_fake_live_and_wrong_platform_rejected(self):
        tier='macos-live'; path=self.root/f'{tier}.json'
        doc=self.documents[tier]; doc['results'][0]['simulated']=True; self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'simulated'): self.verify()
        doc['results'][0]['simulated']=False; doc['host']['system']='Linux'; self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'wrong OS'): self.verify()

    def test_missing_hardware_scenario_and_fake_pass_rejected(self):
        tier='hardware-live'; path=self.root/f'{tier}.json'
        doc=self.documents[tier]; doc['results'].pop(); self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'missing live scenarios'): self.verify()
        doc['results'][0]['status']='SKIP'; self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'simulated'): self.verify()

    def test_offline_missing_named_test_rejected(self):
        tier='offline'; path=self.root/f'{tier}.json'
        doc=self.documents[tier]
        test_name = next(iter(doc['results'][0]['required']))
        doc['results'][0]['required'][test_name]='SKIP'
        self.sign(path,doc)
        with self.assertRaisesRegex(ValueError,'passing named tests'): self.verify()

    def test_duplicate_json_field_rejected(self):
        raw=b'{"tier":"offline","tier":"offline"}'
        with self.assertRaisesRegex(ValueError,'duplicate JSON'): gate.unique_json(raw)

if __name__=='__main__': unittest.main()
