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
                "platformMatched": True,
                "jreCertified": True,
            }
            files = [
                "client-package.json",
                "materialized-client-verify.json",
                "vanilla-install.json",
                "vanilla-certification.json",
                "platform-runtime.json",
                "java-runtime.json",
                "result.json",
            ]
            if target.get("matchingServer") is True:
                checks.update({"matchingServer": True, "serverVersionMatched": True, "serverHealthy": True, "clientJoinedServer": True})
                files.extend(["vanilla-server-install.json", "matching-server.json", "matching-server.log"])
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
                "platformMatched": True,
                "jreCertified": True,
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
                "platform-runtime.json",
                "java-runtime.json",
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
            "jreVendor": "Eclipse Adoptium",
            "jreRuntimeVersion": f"{target['javaMajor']}.0.0+ga",
            "jreExecutableSha256": "a" * 64,
            "scope": target["scope"],
            "matchingServer": target.get("matchingServer", False),
            "commit": commit,
            "runId": "77",
            "exitCode": 0,
            "checks": checks,
            "evidence": {
                "manifestLoader": target["loader"],
                "javaRuntime": {
                    "expectedMajor": target["javaMajor"],
                    "detectedMajor": target["javaMajor"],
                    "expectedOS": target["os"],
                    "detectedOS": target["os"],
                    "expectedArch": target["arch"],
                    "detectedArch": target["arch"],
                    "matched": True,
                    "certified": True,
                    "vendor": "Eclipse Adoptium",
                    "runtimeVersion": f"{target['javaMajor']}.0.0+ga",
                    "vmName": "OpenJDK 64-Bit Server VM",
                    "javaHome": "/opt/java",
                    "executableSha256": "a" * 64,
                },
                "platformRuntime": {
                    "expectedOS": target["os"],
                    "expectedArch": target["arch"],
                    "detectedOS": target["os"],
                    "detectedArch": target["arch"],
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

    def test_validate_rejects_missing_cross_platform_0169(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            doc["targets"] = [t for t in doc["targets"] if t["id"] != "vanilla-26.3-windows-arm64"]
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Cross-platform Vanilla 0.16.9", proc.stderr)


    def test_validate_rejects_missing_matching_server_target_01610(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            doc = self.target_doc()
            for target in doc["targets"]:
                if target["id"] == "vanilla-1.20.4-linux-x64":
                    target["matchingServer"] = False
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = run("validate", "--targets", str(path))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Actual Client E2E II 0.16.10", proc.stderr)

    def test_aggregate_rejects_matching_server_without_real_join_01610(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()
            def mutate(target: dict, result: dict) -> None:
                if target.get("matchingServer") is True and target["minecraft"] == "1.17.1":
                    result["checks"]["clientJoinedServer"] = False
            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("clientJoinedServer", proc.stderr)

    def test_plan_binds_hosted_runner_and_java_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.json"
            path.write_text(json.dumps(self.target_doc()), encoding="utf-8")
            proc = run("plan", "--targets", str(path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = {row["id"]: row for row in json.loads(proc.stdout)["include"]}
            self.assertEqual(rows["vanilla-26.3-linux-arm64"]["runner"], "ubuntu-24.04-arm")
            self.assertEqual(rows["vanilla-26.3-windows-arm64"]["runner"], "windows-11-arm")
            self.assertEqual(rows["vanilla-26.3-windows-arm64"]["javaDistribution"], "microsoft")
            self.assertEqual(rows["vanilla-26.3-macos-x64"]["runner"], "macos-15-intel")
            self.assertEqual(rows["vanilla-26.3-macos-arm64"]["runner"], "macos-15")

    def test_aggregate_rejects_platform_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()
            def mutate(target: dict, result: dict) -> None:
                if target["id"] == "vanilla-26.3-macos-arm64":
                    result["checks"]["platformMatched"] = False
                    result["evidence"]["platformRuntime"]["matched"] = False
            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("platformMatched", proc.stderr)

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

    def test_ga_aggregate_rejects_missing_jre_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()
            def mutate(target: dict, result: dict) -> None:
                if target["id"] == "vanilla-1.20.4-linux-x64":
                    result["checks"]["jreCertified"] = False
                    result["evidence"]["javaRuntime"]["certified"] = False
            proc = self.aggregate(tmp, doc, mutate)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("jreCertified", proc.stderr)

    def test_ga_matrix_contains_certified_jre_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = self.target_doc()
            proc = self.aggregate(tmp, doc)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            matrix = json.loads((tmp / "out" / "matrix.json").read_text(encoding="utf-8"))
            self.assertTrue(matrix["jreBase"])
            self.assertEqual({row["javaMajor"] for row in matrix["jreBase"]}, {8, 16, 17, 21, 25})
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", row["executableSha256"]) for row in matrix["jreBase"]))

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
