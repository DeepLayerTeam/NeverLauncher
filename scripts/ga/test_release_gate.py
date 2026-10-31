"""Security regression tests for release attestations; fixtures are NOT GA evidence."""

from pathlib import Path
import hashlib
import json
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from release_gate import DOMAIN, TARGETS, COMMON_CHECKS, verify_all, verify_target

SHA = "a" * 40


class ReleaseGateTests(unittest.TestCase):
    def setup_fixtures(self, path):
        secret = Ed25519PrivateKey.generate()
        pub = (
            secret.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        for platform, arch in TARGETS:
            folder = path / f"{platform}-{arch}"
            folder.mkdir()
            objects = {}
            for name in (
                "installer",
                "osSignature",
                "cleanMachine",
                "certification",
                "benchmark",
            ):
                proof = {
                    "commit": SHA,
                    "productVersion": "0.24.0",
                    "status": "passed",
                    "simulated": False,
                }
                artifact_sha = hashlib.sha256(b"unsigned fixture only").hexdigest()
                os_label = {"windows": "Windows", "linux": "Linux", "darwin": "Darwin"}[
                    platform
                ]
                if name == "osSignature":
                    proof.update(
                        signatureVerified=True,
                        trustedSigner="test-signer",
                        artifactSha256=artifact_sha,
                        platform=os_label,
                    )
                elif name == "cleanMachine":
                    proof.update(
                        schemaVersion="launcher.ga.clean-machine.v1",
                        javaSha256="1" * 64,
                        logSha256="2" * 64,
                        minecraftVersion="1.21.1",
                        installerSha256=artifact_sha,
                        platform=os_label,
                    )
                elif name == "certification":
                    proof.update(
                        gitTreeClean=True, unmetGates=[], suites=[{"status": "passed"}]
                    )
                elif name == "benchmark":
                    proof.update(
                        runs=[
                            {"implementation": v} for v in ["baseline", "candidate"] * 3
                        ],
                        speedup=1.2,
                        baselineExecutableSha256="3" * 64,
                        candidateExecutableSha256="4" * 64,
                    )
                payload = (
                    b"unsigned fixture only"
                    if name == "installer"
                    else json.dumps(proof).encode()
                )
                fname = name + ".bin"
                (folder / fname).write_bytes(payload)
                objects[name] = {
                    "file": fname,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            doc = {
                "schemaVersion": "launcher.ga.attestation.v1",
                "productVersion": "0.24.0",
                "status": "passed",
                "commit": SHA,
                "gitTreeClean": True,
                "platform": platform,
                "architecture": arch,
                "checks": {
                    v: "passed"
                    for v in COMMON_CHECKS
                    | ({"windows-executable-lock"} if platform == "windows" else set())
                },
                "objects": objects,
            }
            data = json.dumps(doc).encode()
            (folder / "attestation.json").write_bytes(data)
            (folder / "attestation.sig").write_text(secret.sign(DOMAIN + data).hex())
        return pub

    def test_complete_attested_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            report = verify_all(root, pub, SHA)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(len(report["artifacts"]), 6)

    def test_unsigned_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            (root / "windows-amd64" / "attestation.json").write_text("{}")
            with self.assertRaises(Exception):
                verify_all(root, pub, SHA)

    def test_artifact_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            (root / "linux-amd64" / "installer.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "content digest mismatch"):
                verify_all(root, pub, SHA)

    def test_cross_commit_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            with self.assertRaisesRegex(ValueError, "commit/version mismatch"):
                verify_all(root, pub, "b" * 40)

    def test_missing_architecture_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            (root / "darwin-arm64" / "attestation.json").unlink()
            with self.assertRaises(FileNotFoundError):
                verify_all(root, pub, SHA)

    def test_symlinked_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            path = root / "linux-arm64" / "installer.bin"
            path.unlink()
            path.symlink_to(root / "linux-amd64" / "installer.bin")
            with self.assertRaisesRegex(ValueError, "symlinked"):
                verify_all(root, pub, SHA)

    def test_attested_report_marked_mocked_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pub = self.setup_fixtures(root)
            path = root / "linux-arm64" / "cleanMachine.bin"
            # Verify checks fail closed even before attestation's SHA-256 is updated.
            path.write_text(
                json.dumps(
                    {
                        "commit": SHA,
                        "productVersion": "0.24.0",
                        "status": "passed",
                        "mocked": True,
                    }
                )
            )
            with self.assertRaises(ValueError):
                verify_all(root, pub, SHA)


if __name__ == "__main__":
    unittest.main()
