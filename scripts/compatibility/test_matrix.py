#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "compatibility" / "matrix.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["python3", str(TOOL), *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class MatrixToolTests(unittest.TestCase):
    def target_doc(self) -> dict:
        return {
            "schemaVersion": "1.0",
            "productVersion": "0.10.6",
            "targets": [{
                "id": "fabric-1.21.1-linux-x64",
                "minecraft": "1.21.1",
                "loader": "fabric",
                "loaderVersion": "latest-stable",
                "os": "linux",
                "arch": "x86_64",
                "required": True,
            }],
        }

    def passing_result(self) -> dict:
        return {
            "schemaVersion": "1.0",
            "productVersion": "0.10.6",
            "targetId": "fabric-1.21.1-linux-x64",
            "status": "passed",
            "minecraftVersion": "1.21.1",
            "loader": "fabric",
            "loaderSelector": "latest-stable",
            "resolvedLoaderVersion": "0.16.14",
            "os": "linux",
            "arch": "x86_64",
            "commit": "abc123",
            "runId": "77",
            "checks": {
                "actualClient": True,
                "packageVerified": True,
                "signedManifest": True,
                "cleanSync": True,
                "paperJoin": True,
                "sessionRevokeDeny": True,
            },
        }

    def test_validate_rejects_manual_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"][0]["status"] = "passed"
            path.write_text(json.dumps(doc))
            proc = run("plan", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("unknown fields", proc.stderr)

    def test_aggregate_accepts_only_bound_real_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()))
            results = tmp / "results" / "case"
            results.mkdir(parents=True)
            (results / "compatibility-result.json").write_text(json.dumps(self.passing_result()))
            out = tmp / "out"
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(out), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            matrix = json.loads((out / "matrix.json").read_text())
            self.assertEqual(matrix["status"], "passed")
            self.assertEqual(matrix["targets"][0]["status"], "passed")
            self.assertRegex(matrix["targets"][0]["evidenceSha256"], r"^[0-9a-f]{64}$")

    def test_aggregate_rejects_mutable_resolved_loader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()))
            results = tmp / "results" / "case"
            results.mkdir(parents=True)
            bad = self.passing_result()
            bad["resolvedLoaderVersion"] = "latest-stable"
            (results / "compatibility-result.json").write_text(json.dumps(bad))
            out = tmp / "out"
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(out), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            matrix = json.loads((out / "matrix.json").read_text())
            self.assertEqual(matrix["status"], "failed")
            self.assertEqual(matrix["targets"][0]["status"], "invalid")

    def test_aggregate_rejects_commit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            targets = tmp / "targets.json"
            targets.write_text(json.dumps(self.target_doc()))
            results = tmp / "results" / "case"
            results.mkdir(parents=True)
            bad = self.passing_result()
            bad["commit"] = "other"
            (results / "compatibility-result.json").write_text(json.dumps(bad))
            proc = run("aggregate", "--targets", str(targets), "--results-root", str(tmp / "results"), "--output-dir", str(tmp / "out"), "--commit", "abc123", "--run-id", "77", "--repository", "DeepLayerTeam/NeverLauncher")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("commit", proc.stderr)


if __name__ == "__main__":
    unittest.main()
