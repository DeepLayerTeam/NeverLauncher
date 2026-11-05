"""Проверки подделки подписи и привязки точных байтов. Синтетические фикстуры никогда не служат GA-свидетельствами."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts.release import ga_gate_0480 as gate


class GATests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.evidence=self.root/'evidence'
        self.evidence.mkdir()
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.root/'trusted.key'
        self.pub.write_bytes(self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        self.sig=self.root/'approval.sig'
        self.approval=self.root/'approval.json'
        self.commit='a'*40
        for rel in gate.REQUIRED.values():
            path=self.evidence/rel
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'actual external artifact placeholder; insufficient for GA')

    def seal(self):
        hashes={p.relative_to(self.evidence).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.evidence.rglob('*') if p.is_file()}
        doc={'schema':'neverlauncher.ga0480.independent-operator.v1', 'version':'0.48.0','commit':self.commit, 'files':hashes}
        raw=json.dumps(doc,sort_keys=True).encode()
        self.approval.write_bytes(raw)
        self.sig.write_bytes(self.key.sign(gate.DOMAIN+raw))

    def test_independent_ed25519_exact_bytes_valid(self):
        self.seal()
        gate.validate_signed_attestation(self.evidence,self.approval,self.sig,self.pub,self.commit)

    def test_unpinned_extra_file_is_rejected(self):
        self.seal()
        (self.evidence/'signed'/'extra-package').write_bytes(b'unsigned-extra')
        with self.assertRaisesRegex(gate.GateError,'every evidence'):
            gate.validate_signed_attestation(self.evidence,self.approval,self.sig,self.pub,self.commit)

    def test_tampered_package_rejected_even_with_valid_manifest_signature(self):
        self.seal()
        (self.evidence/'signed'/'RELEASE_MANIFEST.json').write_bytes(b'tampered')
        with self.assertRaisesRegex(gate.GateError,'bytes mismatch'):
            gate.validate_signed_attestation(self.evidence,self.approval,self.sig,self.pub,self.commit)

    def test_signature_or_key_swap_refused(self):
        self.seal()
        self.sig.write_bytes(b'\0'*64)
        with self.assertRaisesRegex(gate.GateError,'signature rejected'):
            gate.validate_signed_attestation(self.evidence,self.approval,self.sig,self.pub,self.commit)

    def test_cross_commit_replay_refused(self):
        self.seal()
        with self.assertRaisesRegex(gate.GateError,'commit'):
            gate.validate_signed_attestation(self.evidence,self.approval,self.sig,self.pub,'b'*40)

    def test_pass_flag_not_a_live_migration(self):
        (self.evidence/'live.json').write_text(json.dumps({'status':'passed', 'version':'0.48.0'}))
        with self.assertRaisesRegex(gate.GateError, 'no real independent upgrade'):
            gate.inspect_live(self.evidence)

    def test_unsigned_local_fixture_can_never_pass_release_gate(self):
        self.seal()
        with self.assertRaises((ValueError,OSError)):
            gate.gate(self.evidence,self.approval,self.sig,self.pub,self.commit)


if __name__=='__main__':
    unittest.main()
