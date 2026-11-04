from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest
import json
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
spec=importlib.util.spec_from_file_location('sweep',Path(__file__).parent/'sweep_05211.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class SweepTests(unittest.TestCase):
    def test_required_count_from_real_catalog(self):
        tables=m.inventory.catalogs()
        self.assertEqual(sum(t['required'] for t in tables['minecraft']['rows']),280)
        self.assertEqual(len(m.SOAK_TARGETS),5)
    def test_missing_minecraft_evidence_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(m.inventory.Blocked):
                m.verify_minecraft(Path(temp),'f'*40,'1234',1)
    def test_unsigned_soak_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises((m.inventory.Blocked,OSError)):
                m.signed_soak(Path(temp),Path('/tmp/missing.pem'),'0'*64,'f'*40,'1234',1,'game')
    def test_replay_real_format_https_ledger_and_signature_tamper(self):
        # Синтетические временные измерения — только фикстура верификатора, а не живое GA.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            ledger=root/'requests.bin'
            with ledger.open('wb') as stream:
                for i in range(10000):
                    stream.write(struct.pack('!QdI', 10000000000+i*360010000, 25.0,8))
            row={'schema':'neverlauncher.real-soak/0.53.0',
                 'status':'OBSERVED_NOT_GA','version':'0.53.0',
                 'commit':'a'*40,'runId':'1234','attempt':1,'mode':'https',
                 'seconds':3601.0,'requests':10000,'failed':0,'concurrency':8,
                 'p95Ms':25.0,'responseBytes':80000,
                 'requestsSha256':m.inventory.digest(ledger)}
            (root/'soak.json').write_text(json.dumps(row))
            key=Ed25519PrivateKey.generate()
            public=key.public_key()
            pem=public.public_bytes(serialization.Encoding.PEM,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
            der=public.public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
            pubpath=root/'reviewer.pub';pubpath.write_bytes(pem)
            pin=hashlib.sha256(der).hexdigest()
            (root/'soak.sig').write_bytes(key.sign(b'neverlauncher.soak.real.0.53.0\x00'+m.inventory.canonical(row)))
            self.assertEqual(m.signed_soak(root,pubpath,pin,'a'*40,'1234',1,'https')['requests'],10000)
            with ledger.open('r+b') as handle:
                handle.seek(2)
                handle.write(b'X')
            with self.assertRaises(m.Blocked):
                m.signed_soak(root,pubpath,pin,'a'*40,'1234',1,'https')
            with self.assertRaises((m.Blocked,m.inventory.Blocked)):
                m.signed_soak(root,pubpath,'0'*64,'a'*40,'1234',1,'https')

    def test_duplicate_native_or_loader_cannot_pass(self):
        self.assertNotEqual(len(m.SOAK_TARGETS),6)
        self.assertEqual(len(set(m.SOAK_TARGETS.values())),5)

if __name__=='__main__':unittest.main()
