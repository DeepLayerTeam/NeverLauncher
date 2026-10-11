#!/usr/bin/env python3
"""Regressions for bounded and secret-redacted Minecraft CI diagnostics."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("export-client-diagnostics.py")
SPEC = importlib.util.spec_from_file_location("export_client_diagnostics", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClientDiagnosticsTest(unittest.TestCase):
    def test_extract_bounded_logs_and_redact_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            logs = runtime / "materialized-client" / "logs"
            logs.mkdir(parents=True)
            (logs / "neverruntime-vanilla-certification-1.12.2-1.log").write_text(
                'exception sample\nBearer ABC.def/ghi\n--accessToken SECRET_TOKEN\n'
                '{"accessToken":"JSON_SECRET", "password":"PASSWORD_SECRET"}\n',
                encoding="utf-8",
            )
            out = runtime / "client-diagnostics.txt"
            MODULE.export(runtime, out)
            data = out.read_text(encoding="utf-8")
            self.assertIn("exception sample", data)
            for secret in ("ABC.def/ghi", "SECRET_TOKEN", "JSON_SECRET", "PASSWORD_SECRET"):
                self.assertNotIn(secret, data)
            self.assertIn("[REDACTED]", data)

    def test_missing_log_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            out = runtime / "client-diagnostics.txt"
            MODULE.export(runtime, out)
            self.assertIn("No certification log", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
