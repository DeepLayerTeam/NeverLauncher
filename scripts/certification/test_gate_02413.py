import copy
import json
from pathlib import Path
import tempfile
import unittest
from gate_02413 import aggregate, REQUIRED_TARGETS, REQUIRED_CHECKS

SHA = "a" * 40


def sample(target):
    return {
        "schemaVersion": "1.0",
        "version": "0.24.13",
        "commit": SHA,
        "gitTreeClean": True,
        "target": target,
        "nativeComponents": {
            "status": "passed",
            "target": target,
            "signedManifestVersion": "3.0",
            "catalogSchema": "5.0",
            "httpRequests": 7,
            "tests": list(REQUIRED_CHECKS),
        },
        "checks": {
            x: "passed"
            for x in (
                "rustUnitTests",
                "goModelTests",
                "faultInjection",
                "Guard",
                "serverBridgePolicy",
            )
        },
        "minecraft": {
            "status": "passed",
            "target": target,
            "actualClient": True,
            "loader": "vanilla",
            "evidenceSha256": "f" * 64,
        },
    }


class Gate02413Tests(unittest.TestCase):
    def files(self, tmp, reports):
        paths = []
        for n, report in enumerate(reports):
            path = Path(tmp) / f"{n}.json"
            path.write_text(json.dumps(report))
            paths.append(path)
        return paths

    def test_all_six_real_gates_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = [sample(target) for target in sorted(REQUIRED_TARGETS)]
            self.assertEqual(
                aggregate(self.files(tmp, docs), expected_commit=SHA)["status"],
                "passed",
            )
            self.assertEqual(
                aggregate(self.files(tmp, docs[:3]), expected_commit=SHA)["status"],
                "incomplete",
            )

    def test_missing_minecraft_never_certifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = [sample(t) for t in sorted(REQUIRED_TARGETS)]
            docs[0]["minecraft"]["actualClient"] = False
            result = aggregate(self.files(tmp, docs), expected_commit=SHA)
            self.assertIn("Minecraft", " ".join(result["unmetGates"]))

    def test_skipped_fault_injection_never_certifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = [sample(t) for t in sorted(REQUIRED_TARGETS)]
            docs[0]["checks"]["faultInjection"] = "skipped"
            self.assertNotEqual(
                aggregate(self.files(tmp, docs), expected_commit=SHA)["status"],
                "passed",
            )

    def test_duplicate_and_commit_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = sorted(REQUIRED_TARGETS)[0]
            with self.assertRaises(ValueError):
                aggregate(
                    self.files(tmp, [sample(target), sample(target)]),
                    expected_commit=SHA,
                )
            wrong = sample(target)
            wrong["commit"] = "b" * 40
            self.assertIn(
                "clean source",
                " ".join(
                    aggregate(self.files(tmp, [wrong]), expected_commit=SHA)[
                        "unmetGates"
                    ]
                ),
            )

    def test_invalid_manifest_report_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = [sample(t) for t in sorted(REQUIRED_TARGETS)]
            docs[2]["nativeComponents"]["catalogSchema"] = "2.0"
            self.assertNotEqual(
                aggregate(self.files(tmp, docs), expected_commit=SHA)["status"],
                "passed",
            )


if __name__ == "__main__":
    unittest.main()
