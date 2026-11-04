import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from verify_client_factory_0280 import verify


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, indent=2).encode() + b"\n"
    path.write_bytes(raw)
    return raw


def pubkey(key):
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def sign(key, data, hashed):
    compact = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
    signature = key.sign(hashlib.sha256(compact).digest() if hashed else compact)
    data["signature"] = base64.b64encode(signature).decode()


class VerifyClientFactoryGA0280(unittest.TestCase):
    def test_five_signed_fixture_certificates_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launch_key, join_key = (
                Ed25519PrivateKey.generate(),
                Ed25519PrivateKey.generate(),
            )
            runtime_pub, join_pub = pubkey(launch_key), pubkey(join_key)
            commit = "a" * 40
            join = {
                "status": "passed",
                "minecraftVersion": "1.17.1",
                "clientVersion": "1.17.1",
                "serverVersion": "1.17.1",
                "serverHost": "127.0.0.1",
                "serverProcessAlive": True,
                "serverVersionMatched": True,
                "clientJoinedServer": True,
                "actualClient": True,
            }
            raw_join = dump(root / "matching-server.json", join)
            att = {
                "schema": "launcher.factory.ga-join-attestation.v1",
                "version": "0.28.0",
                "commit": commit,
                "evidenceSha256": hashlib.sha256(raw_join).hexdigest(),
                "createdAt": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "publicKey": join_pub,
                "signature": "",
            }
            sign(join_key, att, False)
            dump(root / "join-attestation.json", att)
            for index, loader in enumerate(
                sorted(("vanilla", "fabric", "quilt", "forge", "neoforge"))
            ):
                folder = root / loader
                log = b"--- process output ---\nMinecraft client initialized LWJGL\n"
                probe = {
                    "status": "passed",
                    "minecraftVersion": "fixture-1",
                    "detectedJavaMajor": 21,
                    "classpathEntries": 2,
                    "timedOut": True,
                }
                raw_probe = dump(folder / "runtime-certificate.probe.json", probe)
                (folder / "runtime-certificate.runtime.log").write_bytes(log)
                cert = {
                    "schema": "launcher.factory.runtime-certificate.v1",
                    "status": "certified",
                    "minecraftVersion": "1.21.1",
                    "loader": loader,
                    "profileId": "fixture-1",
                    "target": {"os": "linux", "arch": "x86_64"},
                    "javaMajor": 21,
                    "planSha256": f"{index + 1:064x}",
                    "javaSha256": "b" * 64,
                    "runtimeSha256": "c" * 64,
                    "probeSha256": hashlib.sha256(raw_probe).hexdigest(),
                    "probeFile": "runtime-certificate.probe.json",
                    "logSha256": hashlib.sha256(log).hexdigest(),
                    "logFile": "runtime-certificate.runtime.log",
                    "publicKey": runtime_pub,
                    "signature": "",
                }
                sign(launch_key, cert, True)
                dump(folder / "runtime-certificate.json", cert)
            dump(
                root / "ga-report.json",
                {
                    "schema": "launcher.factory.ga-report.v1",
                    "status": "passed",
                    "version": "0.28.0",
                    "commit": commit,
                    "certifiedTargets": 5,
                    "certifiedFamilies": 5,
                    "joinEvidenceSha256": hashlib.sha256(raw_join).hexdigest(),
                },
            )
            report = verify(root, runtime_pub, join_pub, "0.28.0", commit)
            self.assertEqual(report["status"], "passed")
            with self.assertRaises(Exception):
                verify(root, runtime_pub, join_pub, "0.28.0", "b" * 40)
            with self.assertRaises(Exception):
                verify(root, join_pub, join_pub, "0.28.0", commit)
            (root / "fabric" / "runtime-certificate.runtime.log").write_bytes(b"fake")
            with self.assertRaises(Exception):
                verify(root, runtime_pub, join_pub, "0.28.0", commit)


if __name__ == "__main__":
    unittest.main()
