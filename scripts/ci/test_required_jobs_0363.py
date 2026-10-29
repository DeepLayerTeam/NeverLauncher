#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("required_jobs_0363", HERE / "required_jobs_0363.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SHA = "a" * 40


class RequiredJobsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workflow = Path(self.tmp.name) / "pipeline.yml"
        self.workflow.write_text("name: CI\non:\n  workflow_dispatch:\njobs:\n  go:\n    runs-on: ubuntu-24.04\n  rust:\n    runs-on: ubuntu-24.04\n  gate:\n    if: ${{ always() }}\n    needs: [go, rust]\n    runs-on: ubuntu-24.04\n", encoding="utf-8")

    def verify(self, needs=None, **overrides):
        p = dict(workflow=str(self.workflow), gate="gate", needs={"go": {"result": "success"}, "rust": {"result": "success"}} if needs is None else needs, source_sha=SHA, checked_out_sha=SHA, run_id="1234", run_attempt="1", version="0.36.3")
        p.update(overrides)
        return mod.verify(**p)

    def test_valid_same_sha_and_run(self):
        result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["expectedJobCount"], 2)
        self.assertEqual(result["runAttempt"], 1)
        self.assertEqual(result["productVersion"], "0.36.3")

    def test_skipped_cancelled_absent_and_failed_are_blocked(self):
        for status in ("skipped", "cancelled", "failure", "timed_out", "neutral", ""):
            with self.subTest(status=status):
                report = self.verify({"go": {"result": "success"}, "rust": {"result": status}})
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["nonSuccessJobs"]["rust"], status)
        report = self.verify({"go": {"result": "success"}})
        self.assertEqual(report["missingJobs"], ["rust"])
        self.assertEqual(report["status"], "blocked")

    def test_unexpected_results_are_blocked(self):
        needs = {"go": {"result": "success"}, "rust": {"result": "success"}, "rogue": {"result": "success"}}
        self.assertEqual(self.verify(needs)["unexpectedJobs"], ["rogue"])

    def test_missing_or_malformed_conclusion_is_not_success(self):
        with self.assertRaises(mod.GateFailure):
            self.verify({"go": {"result": "success"}, "rust": {}})

    def test_wrong_sha_or_missing_ci_run_rejected(self):
        for overrides in ({"checked_out_sha": "b" * 40}, {"run_id": ""}, {"run_attempt": "0"}, {"source_sha": "fake"}, {"version": ""}):
            with self.subTest(overrides=overrides), self.assertRaises(mod.GateFailure):
                self.verify(**overrides)

    def test_declared_new_job_is_not_silently_ignored(self):
        with self.workflow.open("a", encoding="utf-8") as f:
            f.write("  security:\n    runs-on: ubuntu-24.04\n")
        self.assertEqual(self.verify()["missingJobs"], ["security"])

    def test_quoted_or_unknown_job_declaration_fails_closed(self):
        with self.workflow.open("a", encoding="utf-8") as file:
            file.write("  'new-security-job':\n    runs-on: ubuntu-24.04\n")
        with self.assertRaises(mod.GateFailure):
            self.verify()


    def test_gate_cli_enforces_real_git_source_and_fails_closed(self):
        repo = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(repo)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Never CI", "-c", "user.email=ci@invalid.example", "commit", "--allow-empty", "-m", "CI fixture", "-q"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        (repo / "VERSION").write_text("0.36.3\n", encoding="utf-8")
        needs_file = repo / "needs.json"
        output = repo / "result.json"
        command = [sys.executable, str(HERE / "required_jobs_0363.py"), "--workflow", str(self.workflow), "--gate", "gate", "--needs-json", str(needs_file), "--source-sha", commit, "--version-file", "VERSION", "--run-id", "23", "--run-attempt", "2", "--output", str(output)]
        needs_file.write_text(json.dumps({"go": {"result": "success"}, "rust": {"result": "success"}}), encoding="utf-8")
        result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["status"], "passed")
        needs_file.write_text(json.dumps({"go": {"result": "success"}, "rust": {"result": "skipped"}}), encoding="utf-8")
        result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(output.read_text())["status"], "blocked")
        needs_file.write_text(json.dumps({"go": {"result": "success"}, "rust": {"result": "success"}}), encoding="utf-8")
        command[command.index("--source-sha") + 1] = "b" * 40
        result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(output.read_text())["status"], "blocked")

    def test_primary_ci_go_toolchain_does_not_downgrade_backend(self):
        source = (HERE.parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("go-version: '1.23.x'", source)
        self.assertNotIn("go-version-file: cli/go.mod", source)
        self.assertNotIn("continue-on-error: true", source)
        self.assertEqual(source.count("uses: actions/setup-go@"), source.count("go-version-file: services/api/go.mod"))
        self.assertIn("python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v", source)

    def test_real_workflows_include_every_job_in_aggregate(self):
        root = HERE.parents[1]
        import re
        for name, gate in (("ci.yml", "required-ci"), ("production-release-candidate.yml", "required-production-ci")):
            with self.subTest(name=name):
                wf = root / ".github/workflows" / name
                txt = wf.read_text(encoding="utf-8")
                jobs = mod.declared_jobs(str(wf))
                self.assertIn(gate, jobs)
                match = re.search(r"(?ms)^  " + re.escape(gate) + r":\n(.*?)(?=^  [A-Za-z][\w-]*:\s*$|\Z)", txt)
                self.assertIsNotNone(match)
                body = match.group(1)
                self.assertRegex(body, r"if:\s*\$\{\{\s*always\(\)\s*\}\}")
                needs_match = re.search(r"(?m)^    needs:\s*\[([^\]]+)\]", body)
                self.assertIsNotNone(needs_match)
                needs = {v.strip() for v in needs_match.group(1).split(",")}
                self.assertEqual(needs, jobs - {gate})


if __name__ == "__main__":
    unittest.main()
