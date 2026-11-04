import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ga_gate_0260 import DOMAIN, TARGETS, REQUIRED_REPORTS, GateError, verify

COMMIT = "a" * 40


class TextureGAGate0260Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = Ed25519PrivateKey.generate()
        self.public = (
            self.private.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
        )
        self.make_evidence()

    def write_json(self, path, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def sign(self, folder):
        raw = (folder / "attestation.json").read_bytes()
        (folder / "attestation.sig").write_text(self.private.sign(DOMAIN + raw).hex())

    def make_evidence(self):
        for target in TARGETS:
            folder = self.root / target
            folder.mkdir()
            reports = {}
            for name, required in REQUIRED_REPORTS.items():
                report = dict(
                    schemaVersion=f"launcher.textures.ga.{name}.v1",
                    productVersion="0.26.0",
                    commit=COMMIT,
                    target=target,
                    status="passed",
                    actualExecution=True,
                    mocked=False,
                    simulated=False,
                )
                report.update({k: True for k in required})
                if name == "gameplay":
                    report["loaders"] = ["vanilla", "fabric", "neoforge"]
                if name == "installer":
                    report["trustedOSSigner"] = "Independent verified publisher"
                filename = name + ".json"
                reports[name] = {
                    "file": filename,
                    "sha256": self.write_json(folder / filename, report),
                }
            binary = (
                b"fake executable bytes; used ONLY by the signature verifier unit test"
            )
            (folder / "installer.bin").write_bytes(binary)
            signed = dict(
                schemaVersion="launcher.textures.ga.v1",
                productVersion="0.26.0",
                commit=COMMIT,
                target=target,
                status="passed",
                actualExecution=True,
                sourceTreeClean=True,
                recordedAt=datetime.now(timezone.utc).isoformat(),
                reports=reports,
                releaseArtifact={
                    "file": "installer.bin",
                    "sha256": hashlib.sha256(binary).hexdigest(),
                },
            )
            self.write_json(folder / "attestation.json", signed)
            self.sign(folder)

    def test_valid_signature_and_all_six_targets(self):
        verdict = verify(self.root, COMMIT, self.public)
        self.assertEqual(verdict["status"], "passed")
        self.assertEqual(len(verdict["targets"]), 6)

    def test_invalid_signature_rejected(self):
        folder = self.root / "linux-amd64"
        attestation = json.loads((folder / "attestation.json").read_text())
        attestation["actualExecution"] = False
        self.write_json(folder / "attestation.json", attestation)
        with self.assertRaisesRegex(GateError, "signed attestation"):
            verify(self.root, COMMIT, self.public)

    def test_changed_evidence_content_rejected(self):
        folder = self.root / "linux-amd64"
        report = folder / "gameplay.json"
        report.write_bytes(report.read_bytes() + b" ")
        with self.assertRaisesRegex(GateError, "SHA-256 mismatch"):
            verify(self.root, COMMIT, self.public)

    def test_missing_real_platform_rejected(self):
        import shutil

        shutil.rmtree(self.root / "windows-arm64")
        with self.assertRaisesRegex(GateError, "exactly six"):
            verify(self.root, COMMIT, self.public)

    def test_signed_but_mocked_report_rejected(self):
        folder = self.root / "darwin-arm64"
        report = json.loads((folder / "official.json").read_text())
        report["mocked"] = True
        attestation = json.loads((folder / "attestation.json").read_text())
        attestation["reports"]["official"]["sha256"] = self.write_json(
            folder / "official.json", report
        )
        self.write_json(folder / "attestation.json", attestation)
        self.sign(folder)
        with self.assertRaisesRegex(GateError, "not a matching real"):
            verify(self.root, COMMIT, self.public)

    def test_signed_but_skipped_gameplay_rejected(self):
        folder = self.root / "windows-amd64"
        report = json.loads((folder / "gameplay.json").read_text())
        report["remoteObserverSawSkin"] = False
        attestation = json.loads((folder / "attestation.json").read_text())
        attestation["reports"]["gameplay"]["sha256"] = self.write_json(
            folder / "gameplay.json", report
        )
        self.write_json(folder / "attestation.json", attestation)
        self.sign(folder)
        with self.assertRaisesRegex(GateError, "remoteObserverSawSkin"):
            verify(self.root, COMMIT, self.public)

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(GateError, "release identity/status"):
            verify(self.root, "b" * 40, self.public)

    def test_installer_tampering_rejected(self):
        with (self.root / "linux-amd64" / "installer.bin").open("ab") as f:
            f.write(b"tamper")
        with self.assertRaisesRegex(GateError, "SHA-256 mismatch"):
            verify(self.root, COMMIT, self.public)

    def test_symlinked_report_rejected(self):
        folder = self.root / "linux-arm64"
        report = folder / "backend.json"
        outside = folder / "backend-original.json"
        report.rename(outside)
        try:
            report.symlink_to(outside)
        except OSError as err:
            self.skipTest(str(err))
        with self.assertRaisesRegex(GateError, "unsafe evidence file"):
            verify(self.root, COMMIT, self.public)

    def test_duplicate_json_key_rejected(self):
        folder = self.root / "windows-amd64"
        report = folder / "official.json"
        raw = report.read_bytes()
        # Signed hashes must match any change; also test the duplicate-key parser
        # by re-signing the altered content as if a signer had made a mistake.
        report.write_bytes(raw[:-1] + b',"actualExecution":true}')
        attestation = json.loads((folder / "attestation.json").read_text())
        attestation["reports"]["official"]["sha256"] = hashlib.sha256(
            report.read_bytes()
        ).hexdigest()
        self.write_json(folder / "attestation.json", attestation)
        self.sign(folder)
        with self.assertRaisesRegex(GateError, "duplicate JSON key"):
            verify(self.root, COMMIT, self.public)


if __name__ == "__main__":
    unittest.main()
