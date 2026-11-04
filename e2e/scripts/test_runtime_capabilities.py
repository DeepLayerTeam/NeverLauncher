import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from runtime_capabilities_03410 import host_identity, evaluate
from run_native_validation_03410 import export_reports
from process_group_03410 import group_flags


class Capabilities(unittest.TestCase):
    def test_supported_architectures_are_normalized(self):
        for system in ("linux", "darwin", "win32"):
            for arch in ("amd64", "x86_64", "arm64", "aarch64"):
                result = host_identity(system, arch)
                self.assertTrue(result["supported"])
                self.assertIn(result["arch"], ("amd64", "arm64"))
        self.assertFalse(host_identity("freebsd", "amd64")["supported"])
        self.assertFalse(host_identity("win32", "i386")["supported"])

    def test_headless_capability_claims_gui(self):
        with patch(
            "runtime_capabilities_03410._probe_java",
            return_value={"available": True, "sha256": "a" * 64},
        ):
            result = evaluate("headless", "/java")
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["headless"])
        self.assertFalse(result["gui"])
        self.assertIsNone(result["renderer"])

    def test_no_renderer_is_blocked_not_failed(self):
        with (
            patch(
                "runtime_capabilities_03410.host_identity",
                return_value={"os": "linux", "arch": "amd64", "supported": True},
            ),
            patch(
                "runtime_capabilities_03410._probe_java",
                return_value={"available": True},
            ),
            patch(
                "runtime_capabilities_03410._linux_gui",
                return_value=(False, "missing usable renderer", None),
            ),
        ):
            result = evaluate("gui", "/java")
        self.assertEqual(result["status"], "blocked")
        self.assertIn("missing usable renderer", result["blockers"])

    def test_missing_java_also_blocks_before_game(self):
        with patch(
            "runtime_capabilities_03410._probe_java",
            return_value={"available": False, "reason": "invalid Java"},
        ):
            result = evaluate("headless", "/java")
        self.assertEqual(result["status"], "blocked")
        self.assertIn("invalid Java", result["blockers"])

    def test_gui_ready_requires_real_renderer(self):
        with (
            patch(
                "runtime_capabilities_03410.host_identity",
                return_value={"os": "linux", "arch": "amd64", "supported": True},
            ),
            patch(
                "runtime_capabilities_03410._probe_java",
                return_value={"available": True},
            ),
            patch(
                "runtime_capabilities_03410._linux_gui",
                return_value=(True, "", {"renderer": "llvmpipe", "version": "4.5"}),
            ),
        ):
            result = evaluate("gui", "/java")
        self.assertTrue(result["gui"])
        self.assertEqual(result["status"], "ready")

    def test_only_allowed_redacted_files_are_exported(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            work = root / "worker"
            work.mkdir()
            (work / "staged-execution.json").write_text(
                json.dumps(
                    {
                        "stages": {
                            "startup": {
                                "status": "blocked",
                                "detail": "no renderer",
                                "private": "token",
                            }
                        },
                        "token": "secret",
                    }
                )
            )
            (work / "credentials.json").write_text("secret")
            export_reports(work, root / "public")
            report = json.loads((root / "public" / "staged-execution.json").read_text())
            self.assertNotIn("token", report)
            self.assertNotIn("private", report["stages"]["startup"])
            self.assertFalse((root / "public" / "credentials.json").exists())

    def test_process_group_is_portable(self):
        self.assertTrue(
            "creationflags" in group_flags() or "start_new_session" in group_flags()
        )


if __name__ == "__main__":
    unittest.main()
