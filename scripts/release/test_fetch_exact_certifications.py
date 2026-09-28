#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).with_name("fetch-exact-certifications.py")
spec = importlib.util.spec_from_file_location("fetch_exact_certifications", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ExactCertificationTests(unittest.TestCase):
    def test_select_exact_run_never_falls_back_to_other_commit(self) -> None:
        runs = [
            {"id": 1, "head_sha": "b" * 40, "created_at": "2026-09-27T00:00:00Z"},
            {"id": 2, "head_sha": "a" * 40, "created_at": "2026-09-27T00:01:00Z"},
            {"id": 3, "head_sha": "a" * 40, "created_at": "2026-09-27T00:02:00Z"},
        ]
        self.assertEqual(mod.select_exact_run(runs, "a" * 40)["id"], 3)
        self.assertIsNone(mod.select_exact_run(runs, "c" * 40))

    def test_matrix_validation_requires_exact_commit_run_and_pass(self) -> None:
        doc = {
            "repository": "DeepLayerTeam/NeverLauncher",
            "commit": "a" * 40,
            "productVersion": "0.16.1",
            "runId": "123",
            "status": "passed",
            "targets": [{"id": "required"}],
            "errors": [],
        }
        mod.validate_matrix_document(doc, repository=doc["repository"], commit=doc["commit"], version="0.16.1", run_id=123, label="compatibility")
        bad = dict(doc, commit="b" * 40)
        with self.assertRaises(RuntimeError):
            mod.validate_matrix_document(bad, repository=doc["repository"], commit=doc["commit"], version="0.16.1", run_id=123, label="compatibility")
        bad = dict(doc, status="failed")
        with self.assertRaises(RuntimeError):
            mod.validate_matrix_document(bad, repository=doc["repository"], commit=doc["commit"], version="0.16.1", run_id=123, label="compatibility")


    def test_artifact_redirect_strips_github_authorization(self) -> None:
        req = mod.urllib.request.Request(
            "https://api.github.com/repos/DeepLayerTeam/NeverLauncher/actions/artifacts/123/zip",
            headers={"Authorization": "Bearer secret", "User-Agent": mod.USER_AGENT},
        )
        redirected = mod._artifact_redirect_request(
            req,
            "https://productionresultssa8.blob.core.windows.net/actions-results/test.zip?sig=abc",
        )
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertEqual(redirected.get_header("User-agent"), mod.USER_AGENT)
        self.assertEqual(redirected.full_url, "https://productionresultssa8.blob.core.windows.net/actions-results/test.zip?sig=abc")

    def test_artifact_redirect_rejects_untrusted_or_insecure_target(self) -> None:
        req = mod.urllib.request.Request("https://api.github.com/repos/x/y/actions/artifacts/1/zip")
        with self.assertRaises(RuntimeError):
            mod._artifact_redirect_request(req, "https://evil.example/artifact.zip")
        with self.assertRaises(RuntimeError):
            mod._artifact_redirect_request(req, "http://productionresultssa8.blob.core.windows.net/artifact.zip")

    def test_matrix_zip_accepts_single_matrix_only(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("matrix.json", json.dumps({"status": "passed"}))
            zf.writestr("matrix.md", "ok")
        self.assertEqual(json.loads(mod.matrix_from_zip(buf.getvalue(), label="compatibility"))["status"], "passed")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a/matrix.json", "{}")
            zf.writestr("b/matrix.json", "{}")
        with self.assertRaises(RuntimeError):
            mod.matrix_from_zip(buf.getvalue(), label="compatibility")


if __name__ == "__main__":
    unittest.main()
