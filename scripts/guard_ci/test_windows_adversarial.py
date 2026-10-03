#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import sys
from types import SimpleNamespace
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("windows_adversarial.py")
spec = importlib.util.spec_from_file_location("windows_adversarial", MODULE_PATH)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def synthetic_result(java_major: int, repository: str = "DeepLayerTeam/NeverLauncher", commit: str = "a" * 40, run_id: str = "123"):
    artifacts = {}
    for name in ["sensor", "memoryProbe", "threadProbe", "debugProbe", "jvmProbe"]:
        artifacts[name] = {"name": name, "size": 1, "sha256": "1" * 64}
    scenarios = []
    for scenario in mod.SCENARIOS:
        scenarios.append({
            "id": scenario.id,
            "kind": scenario.kind,
            "test": scenario.test_name,
            "description": scenario.description,
            "status": "passed",
            "exitCode": 0,
            "timedOut": False,
            "durationMs": 1,
            "outputSha256": "2" * 64,
            "outputBytes": 1,
        })
    payload = {
        "schemaVersion": mod.SCHEMA_VERSION,
        "kind": "neverlauncher-windows-adversarial-result",
        "productVersion": mod.PRODUCT_VERSION,
        "javaMajor": java_major,
        "runtimeArch": "amd64",
        "repository": repository,
        "commit": commit,
        "runId": run_id,
        "javaVersionOutputSha256": "3" * 64,
        "rustcVersionOutputSha256": "4" * 64,
        "artifacts": artifacts,
        "scenarios": scenarios,
        "compatibilityScenarioCount": sum(1 for row in scenarios if row["kind"] == "compatibility"),
        "adversarialScenarioCount": sum(1 for row in scenarios if row["kind"] == "adversarial"),
        "allRequiredScenariosPassed": True,
        "status": "passed",
    }
    payload["evidenceRootSha256"] = mod.result_evidence_root(payload)
    return payload


class WindowsAdversarialTests(unittest.TestCase):
    def test_valid_result_is_accepted(self):
        payload = synthetic_result(21)
        self.assertEqual([], mod.validate_result(payload, repository=payload["repository"], commit=payload["commit"], run_id=payload["runId"]))

    def test_tampered_scenario_is_rejected(self):
        payload = synthetic_result(21)
        payload["scenarios"][5]["status"] = "failed"
        errors = mod.validate_result(payload, repository=payload["repository"], commit=payload["commit"], run_id=payload["runId"])
        self.assertTrue(any("scenario failed" in err for err in errors))
        self.assertTrue(any("evidenceRootSha256 mismatch" in err for err in errors))

    def test_aggregate_requires_every_certified_java_major(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for major in mod.CERTIFIED_JAVA_MAJORS[:-1]:
                directory = root / f"java-{major}"
                directory.mkdir()
                (directory / "windows-adversarial-result.json").write_text(json.dumps(synthetic_result(major)), encoding="utf-8")
            found, errors = mod.discover_results(root)
            self.assertEqual([], errors)
            self.assertNotIn(mod.CERTIFIED_JAVA_MAJORS[-1], found)

    def test_aggregate_emits_machine_certificate_for_exact_five_java_cohort(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            results = root / "results"
            output = root / "certificate"
            repository = "DeepLayerTeam/NeverLauncher"
            commit = "b" * 40
            run_id = "456"
            for major in mod.CERTIFIED_JAVA_MAJORS:
                directory = results / f"java-{major}"
                directory.mkdir(parents=True)
                (directory / "windows-adversarial-result.json").write_text(
                    json.dumps(synthetic_result(major, repository, commit, run_id)), encoding="utf-8"
                )
            args = SimpleNamespace(results_root=results, repository=repository, commit=commit, run_id=run_id, output_dir=output)
            self.assertEqual(0, mod.cmd_aggregate(args))
            certificate = json.loads((output / "WINDOWS_ADVERSARIAL_CERTIFICATE.json").read_text(encoding="utf-8"))
            self.assertEqual(list(mod.CERTIFIED_JAVA_MAJORS), certificate["javaMajors"])
            self.assertEqual(len(mod.SCENARIOS) * len(mod.CERTIFIED_JAVA_MAJORS), certificate["scenarioExecutions"])
            self.assertTrue(certificate["invariants"]["allAdversarialScenariosDetected"])
            self.assertTrue(certificate["invariants"]["sensorAndFixtureHashesBound"])


if __name__ == "__main__":
    unittest.main()
