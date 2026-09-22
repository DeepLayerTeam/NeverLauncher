#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts/device_trust/matrix.py"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(TOOL), *args], text=True, capture_output=True, cwd=ROOT)


class DeviceTrustMatrixTests(unittest.TestCase):
    def target_doc(self) -> dict:
        return {
            "schemaVersion": "1.0",
            "productVersion": VERSION,
            "targets": [
                {
                    "id": "native-linux",
                    "kind": "native-tests",
                    "runner": "ubuntu-24.04",
                    "os": "linux",
                    "arch": "runner-native",
                    "required": True,
                    "requiredChecks": [
                        "tauriCompile",
                        "deviceKeyUnitTests",
                        "generationScopedHardwareLabels",
                        "replacementPayloadValidation",
                        "refreshPayloadBinding",
                        "attestationPayloadValidation",
                    ],
                }
            ],
        }

    def passing_result(self) -> dict:
        return {
            "schemaVersion": "1.0",
            "productVersion": VERSION,
            "targetId": "native-linux",
            "kind": "native-tests",
            "os": "linux",
            "arch": "runner-native",
            "runtimeArch": "x86_64",
            "commit": "abc123",
            "runId": "77",
            "status": "passed",
            "exitCode": 0,
            "checks": {
                "tauriCompile": True,
                "deviceKeyUnitTests": True,
                "generationScopedHardwareLabels": True,
                "replacementPayloadValidation": True,
                "refreshPayloadBinding": True,
                "attestationPayloadValidation": True,
            },
            "evidence": {"files": ["native-cargo-test.txt"], "sha256": {"native-cargo-test.txt": "0" * 64}},
            "limitations": ["headless-ci-does-not-prove-os-secure-storage-runtime"],
        }


    def write_result(self, result_dir: Path, payload: dict, *, evidence_name: str = "native-cargo-test.txt", content: bytes = b"device trust evidence\n") -> None:
        evidence_path = result_dir / evidence_name
        evidence_path.write_bytes(content)
        payload["evidence"] = {
            "files": [evidence_name],
            "sha256": {evidence_name: hashlib.sha256(content).hexdigest()},
        }
        (result_dir / "device-trust-result.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_validate_rejects_manual_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"][0]["status"] = "passed"
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("unknown fields", proc.stderr + proc.stdout)

    def test_validate_rejects_weakened_required_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"][0]["requiredChecks"].remove("replacementPayloadValidation")
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("weaken", proc.stderr + proc.stdout)

    def test_aggregate_accepts_exact_commit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            result_dir = tmp / "results" / "native-linux"
            result_dir.mkdir(parents=True)
            self.write_result(result_dir, self.passing_result())
            out = tmp / "out"
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(out), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            matrix = json.loads((out / "matrix.json").read_text(encoding="utf-8"))
            self.assertEqual(matrix["status"], "passed")
            self.assertRegex(matrix["targets"][0]["evidenceSha256"], r"^[0-9a-f]{64}$")

    def test_aggregate_rejects_commit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            result_dir = tmp / "results" / "native-linux"
            result_dir.mkdir(parents=True)
            bad = self.passing_result()
            bad["commit"] = "other"
            self.write_result(result_dir, bad)
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("commit", proc.stderr + proc.stdout)

    def test_aggregate_rejects_false_required_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            result_dir = tmp / "results" / "native-linux"
            result_dir.mkdir(parents=True)
            bad = self.passing_result()
            bad["checks"]["tauriCompile"] = False
            self.write_result(result_dir, bad)
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("tauriCompile", proc.stderr + proc.stdout)

    def test_aggregate_rejects_tampered_evidence_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            result_dir = tmp / "results" / "native-linux"
            result_dir.mkdir(parents=True)
            self.write_result(result_dir, self.passing_result())
            (result_dir / "native-cargo-test.txt").write_text("tampered\n", encoding="utf-8")
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SHA-256 mismatch", proc.stderr + proc.stdout)

    def test_aggregate_rejects_path_traversal_evidence_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            result_dir = tmp / "results" / "native-linux"
            result_dir.mkdir(parents=True)
            payload = self.passing_result()
            payload["evidence"] = {"files": ["../outside.txt"], "sha256": {"../outside.txt": "0" * 64}}
            (result_dir / "device-trust-result.json").write_text(json.dumps(payload), encoding="utf-8")
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("safe-basename", proc.stderr + proc.stdout)

    def test_protocol_result_cannot_claim_vendor_hardware_provenance(self) -> None:
        doc = {
            "schemaVersion": "1.0",
            "productVersion": VERSION,
            "targets": [{
                "id": "postgres-protocol-linux-x64",
                "kind": "protocol-e2e",
                "runner": "ubuntu-24.04",
                "os": "linux",
                "arch": "x86_64",
                "required": True,
                "requiredChecks": sorted([
                    "postgresRepository", "registrationReplayDenied", "sessionBindingEpoch", "boundRefreshProof",
                    "rotationDualProof", "oldKeyTombstone", "serverBridgeBindingDeny", "revocationCascade",
                    "riskStepUp", "p256AttestationProtocol", "attestationReplayDenied",
                    "recoveryRequiresPhishingResistantStepUp", "recoveryPhishingResistantEndToEnd",
                ]),
            }],
        }
        result = {
            "schemaVersion": "1.0", "productVersion": VERSION, "targetId": "postgres-protocol-linux-x64",
            "kind": "protocol-e2e", "os": "linux", "arch": "x86_64", "runtimeArch": "x86_64",
            "commit": "abc123", "runId": "77", "status": "passed", "exitCode": 0,
            "checks": {name: True for name in doc["targets"][0]["requiredChecks"]},
            "evidence": {"files": ["protocol-checks.json"]},
            "claims": {"repository": "postgresql", "vendorHardwareProvenance": "verified", "privateKeyServerExposed": False},
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(doc), encoding="utf-8")
            result_dir = tmp / "results" / "protocol"
            result_dir.mkdir(parents=True)
            self.write_result(result_dir, result, evidence_name="protocol-checks.json", content=b"protocol evidence\n")
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("vendor hardware provenance", (proc.stderr + proc.stdout).lower())


if __name__ == "__main__":
    unittest.main()
