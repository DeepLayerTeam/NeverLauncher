#!/usr/bin/env python3
"""Native SDL 3 startup retry eligibility must remain narrowly fail-closed."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).with_name("retry-macos-sdl3.py")
SPEC = importlib.util.spec_from_file_location("retry_macos_sdl3", SRC)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class MacOSSDL3RetryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "materialized-client"
        self.logs = self.root / "logs"
        self.logs.mkdir(parents=True)
        self.log = self.logs / "neverruntime-vanilla-certification-fabric-26.3.log"
        self.report = Path(self.temp.name) / "fabric-certification.json"
        self.payload = {
            "status": "failed", "success": False, "timedOut": False,
            "exitCode": None, "detectedJavaMajor": 25, "logPath": str(self.log),
        }
        self.log.write_text("SDL revision: SDL-3.4.14-62f10da\n--- runtime exit --- code=None signal=Some(6)\n")
        self.save()

    def save(self) -> None:
        self.report.write_text(json.dumps(self.payload), encoding="utf-8")

    def test_specific_native_abort_can_retry(self) -> None:
        self.assertTrue(MOD.is_retryable(self.report, self.root))

    def test_never_retry_passed_or_normal_crash(self) -> None:
        for k, v in (("status", "passed"), ("success", True),
                     ("timedOut", True), ("exitCode", 255),
                     ("detectedJavaMajor", 21)):
            original = self.payload[k]
            self.payload[k] = v
            self.save()
            self.assertFalse(MOD.is_retryable(self.report, self.root), k)
            self.payload[k] = original
        self.save()

    def test_reject_wrong_signal_and_security_abort(self) -> None:
        self.log.write_text("SDL revision: SDL-3.4\n--- runtime exit --- code=None signal=Some(11)\n")
        self.assertFalse(MOD.is_retryable(self.report, self.root))
        self.log.write_text("SDL revision: SDL-3.4\nNeverGuard fail-closed\n--- runtime exit --- code=None signal=Some(6)\n")
        self.assertFalse(MOD.is_retryable(self.report, self.root))

    def test_path_escape_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            outside_log = Path(outside) / "java.log"
            outside_log.write_text(self.log.read_text())
            self.payload["logPath"] = str(outside_log)
            self.save()
            self.assertFalse(MOD.is_retryable(self.report, self.root))
            symlink = self.logs / "symlink.log"
            symlink.symlink_to(outside_log)
            self.payload["logPath"] = str(symlink)
            self.save()
            self.assertFalse(MOD.is_retryable(self.report, self.root))

    def test_missing_or_malformed_report_is_not_retryable(self) -> None:
        self.report.write_text("{invalid")
        self.assertFalse(MOD.is_retryable(self.report, self.root))
        self.report.unlink()
        self.assertFalse(MOD.is_retryable(self.report, self.root))


if __name__ == "__main__":
    unittest.main()
