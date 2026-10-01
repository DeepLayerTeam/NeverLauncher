#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "compatibility" / "matrix.py"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
REPOSITORY_TARGETS = json.loads((ROOT / "compatibility" / "targets.json").read_text(encoding="utf-8"))


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["python3", str(TOOL), *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class MatrixToolTests(unittest.TestCase):
    def target_doc(self) -> dict:
        doc = copy.deepcopy(REPOSITORY_TARGETS)
        doc["productVersion"] = VERSION
        return doc

    def passing_result(self, target: dict, *, commit: str = "abc123") -> dict:
        client_scope = target["scope"] == "client"
        if client_scope:
            checks = {
                "materialized": True,
                "packageVerified": True,
                "runtimeResolved": True,
                "javaMatched": True,
                "actualClient": True,
            }
            files = [
                "client-package.json",
                "materialized-client-verify.json",
                "vanilla-install.json",
                "vanilla-certification.json",
                "result.json",
            ]
        else:
            checks = {
                "actualClient": True,
                "packageVerified": True,
                "signedManifest": True,
                "cleanSync": True,
                "paperJoin": True,
                "sessionRevokeDeny": True,
                "paperHealthy": True,
                "javaMatched": True,
            }
            files = [
                "result.json",
                "materialized-client-verify.json",
                "manifest.json",
                "runtime-verify.json",
                "runtime-sync.json",
                "runtime-launch-minecraft.json",
                "health-paper.json",
                "bridge-diagnostics.json",
            ]
        return {
            "schemaVersion": "1.0",
            "productVersion": VERSION,
            "targetId": target["id"],
            "status": "passed",
            "minecraftVersion": target["minecraft"],
            "loader": target["loader"],
            "loaderSelector": target["loaderVersion"],
            "resolvedLoaderVersion": "" if target["loader"] == "vanilla" else "0.16.14",
            "os": target["os"],
            "arch": target["arch"],
            "javaMajor": target["javaMajor"],
            "detectedJavaMajor": target["javaMajor"],
            "scope": target["scope"],
            "commit": commit,
            "runId": "77",
            "exitCode": 0,
            "checks": checks,
            "evidence": {
                "manifestLoader": target["loader"],
                "javaRuntime": {
                    "expectedMajor": target["javaMajor"],
                    "detectedMajor": target["javaMajor"],
                    "matched": True,
                },
                "files": files,
            },
        }

    def write_results(self, root: Path, doc: dict, mutate=None) -> None:
        for target in doc["targets"]:
            result = self.passing_result(target)
            if mutate is not None:
                mutate(target, result)
            case = root / target["id"]
            case.mkdir(parents=True, exist_ok=True)
            (case / "compatibility-result.json").write_text(json.dumps(result), encoding="utf-8")

    def aggregate(self, tmp: Path, doc: dict, mutate=None) -> subprocess.CompletedProcess[str]:
        targets = tmp / "targets.json"
        targets.write_text(json.dumps(doc), encoding="utf-8")
        results = tmp / "results"
        self.write_results(results, doc, mutate)
        return run(
            "aggregate",
            "--targets", str(targets),
            "--results-root", str(results),
            "--output-dir", str(tmp / "out"),
            "--commit", "abc123",
            "--run-id", "77",
            "--repository", "DeepLayerTeam/NeverLauncher",
        )

    def test_validate_rejects_manual_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"][0]["status"] = "passed"
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("plan", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("unknown fields", proc.stderr)

    def test_validate_rejects_missing_vanilla_baseline_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if target["minecraft"] != "1.17.1"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Baseline II", proc.stderr)

    def test_validate_rejects_missing_legacy_release_line_0163(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if target["minecraft"] != "1.8.9"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Legacy Vanilla 0.16.3", proc.stderr)

    def test_validate_rejects_missing_pre17_release_line_0164(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if target["minecraft"] != "1.2.5"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Legacy Vanilla 0.16.4", proc.stderr)

    def test_validate_rejects_missing_java16_17_release_line_0166(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if target["minecraft"] != "1.20.2"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Java 16/17 Vanilla 0.16.6", proc.stderr)

    def test_validate_rejects_wrong_java16_17_major_0166(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            for target in doc["targets"]:
                if target["minecraft"] == "1.19.4" and target["loader"] == "vanilla":
                    target["javaMajor"] = 16
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("requires Java 17", proc.stderr)


    def test_validate_rejects_missing_java21_release_line_0167(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if not (target["loader"] == "vanilla" and target["minecraft"] == "1.21.10")]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Java 21 Vanilla 0.16.7", proc.stderr)

    def test_validate_rejects_wrong_java21_major_0167(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            for target in doc["targets"]:
                if target["minecraft"] == "1.21.9" and target["loader"] == "vanilla":
                    target["javaMajor"] = 17
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("requires Java 21", proc.stderr)

    def test_validate_rejects_missing_java25_release_line_0168(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [target for target in doc["targets"] if not (target["loader"] == "vanilla" and target["minecraft"] == "26.3")]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Java 25 Vanilla 0.16.8", proc.stderr)

    def test_validate_rejects_wrong_java25_major_0168(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            for target in doc["targets"]:
                if target["minecraft"] == "26.1.2" and target["loader"] == "vanilla":
                    target["javaMajor"] = 21
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("requires Java 25", proc.stderr)

    def test_aggregate_accepts_bound_multiversion_java_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()
            proc = self.aggregate(tmp, doc)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            matrix = json.loads((tmp / "out" / "matrix.json").read_text(encoding="utf-8"))
            self.assertEqual(matrix["status"], "passed")
            self.assertEqual(len(matrix["targets"]), len(doc["targets"]))
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", row["evidenceSha256"]) for row in matrix["targets"]))

    def test_aggregate_rejects_mutable_resolved_loader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()

            def mutate(target: dict, result: dict) -> None:
                if target["loader"] == "fabric":
                    result["resolvedLoaderVersion"] = "latest-stable"

            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("immutable version", proc.stderr)

    def test_aggregate_rejects_commit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()

            def mutate(target: dict, result: dict) -> None:
                if target["minecraft"] == "1.12.2" and target["loader"] == "vanilla":
                    result["commit"] = "other"

            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("commit", proc.stderr)

    def test_aggregate_rejects_java_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()

            def mutate(target: dict, result: dict) -> None:
                if target["minecraft"] == "1.17.1" and target["loader"] == "vanilla":
                    result["detectedJavaMajor"] = 17
                    result["checks"]["javaMatched"] = False
                    result["evidence"]["javaRuntime"]["detectedMajor"] = 17
                    result["evidence"]["javaRuntime"]["matched"] = False

            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Java", proc.stderr)

    def test_aggregate_rejects_failed_health_even_with_pass_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()

            def mutate(target: dict, result: dict) -> None:
                if target["loader"] == "fabric":
                    result["checks"]["paperHealthy"] = False

            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("paperHealthy", proc.stderr)


if __name__ == "__main__":
    unittest.main()
