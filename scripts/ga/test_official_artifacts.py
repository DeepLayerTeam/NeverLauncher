import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

folder = Path(__file__).parent
sys.path.insert(0, str(folder))
from verify_official_artifacts_0270 import PACKAGES, verify_shipped, GateError


class ExactPackagesTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.bundle = Path(self.dir.name)
        self.receipt = self.bundle / "OFFICIAL_MINECRAFT_GA_CERTIFICATION.json"
        targets = []
        for target, name in PACKAGES.items():
            data = f"synthetic-{target}-package".encode()
            (self.bundle / name).write_bytes(data)
            targets.append(
                {
                    "target": target,
                    "status": "passed",
                    "signedArtifactSha256": hashlib.sha256(data).hexdigest(),
                }
            )
        self.data = {
            "schemaVersion": "launcher.official-minecraft.ga-receipt.v1",
            "productVersion": "0.27.0",
            "status": "passed",
            "targets": targets,
        }
        self.save()

    def save(self):
        self.receipt.write_text(json.dumps(self.data))

    def test_all_exact_files(self):
        self.assertEqual(len(verify_shipped(self.bundle, self.receipt)), 6)

    def test_altered_package_rejected(self):
        with (self.bundle / PACKAGES["windows-amd64"]).open("ab") as f:
            f.write(b"modified after approval")
        with self.assertRaisesRegex(GateError, "differs"):
            verify_shipped(self.bundle, self.receipt)

    def test_missing_and_symlinked_package_rejected(self):
        path = self.bundle / PACKAGES["linux-arm64"]
        path.unlink()
        with self.assertRaisesRegex(GateError, "missing"):
            verify_shipped(self.bundle, self.receipt)
        path.symlink_to(self.bundle / PACKAGES["linux-amd64"])
        with self.assertRaisesRegex(GateError, "missing"):
            verify_shipped(self.bundle, self.receipt)

    def test_incomplete_signed_set_rejected(self):
        self.data["targets"].pop()
        self.save()
        with self.assertRaisesRegex(GateError, "six certified"):
            verify_shipped(self.bundle, self.receipt)

    def test_duplicate_target_rejected(self):
        self.data["targets"][-1] = self.data["targets"][0]
        self.save()
        with self.assertRaisesRegex(GateError, "duplicate"):
            verify_shipped(self.bundle, self.receipt)


if __name__ == "__main__":
    unittest.main()
