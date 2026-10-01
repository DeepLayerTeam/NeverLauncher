#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import platform
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "compatibility" / "certify-jre.py"
spec = importlib.util.spec_from_file_location("certify_jre", TOOL)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CertifyJRETests(unittest.TestCase):
    def test_normalization(self) -> None:
        self.assertEqual(mod.normalize_os("Mac OS X"), "macos")
        self.assertEqual(mod.normalize_os("Windows 11"), "windows")
        self.assertEqual(mod.normalize_arch("amd64"), "x86_64")
        self.assertEqual(mod.normalize_arch("arm64"), "aarch64")

    def test_parse_major(self) -> None:
        self.assertEqual(mod.parse_major("1.8.0_442"), 8)
        self.assertEqual(mod.parse_major("17.0.15+6"), 17)
        self.assertEqual(mod.parse_major("25"), 25)
        self.assertIsNone(mod.parse_major("bad"))

    @unittest.skipIf(os.name == "nt", "POSIX fake executable fixture")
    def test_certify_binds_binary_hash_and_runtime_identity(self) -> None:
        os_name = {"Linux": "linux", "Darwin": "macos"}.get(platform.system(), platform.system().lower())
        arch = mod.normalize_arch(platform.machine())
        if os_name not in {"linux", "macos"} or arch not in {"x86_64", "aarch64"}:
            self.skipTest("unsupported test host")
        with tempfile.TemporaryDirectory() as tmp:
            java_home = Path(tmp) / "jdk"
            java = java_home / "bin" / "java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "#!/bin/sh\n"
                "cat >&2 <<'EOF'\n"
                "Property settings:\n"
                f"    java.home = {java_home}\n"
                "    java.runtime.version = 21.0.8+9-LTS\n"
                "    java.vendor = Test Vendor\n"
                "    java.vm.name = Test OpenJDK VM\n"
                f"    os.name = {'Linux' if os_name == 'linux' else 'Mac OS X'}\n"
                f"    os.arch = {'amd64' if arch == 'x86_64' else 'aarch64'}\n"
                "openjdk version \"21.0.8\" 2026-07-15\n"
                "EOF\n"
                "exit 0\n",
                encoding="utf-8",
            )
            java.chmod(java.stat().st_mode | stat.S_IXUSR)
            result = mod.certify(str(java), 21, os_name, arch)
            self.assertTrue(result["certified"], result)
            self.assertEqual(result["vendor"], "Test Vendor")
            self.assertEqual(result["runtimeVersion"], "21.0.8+9-LTS")
            self.assertRegex(result["executableSha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(result["executableSize"], 0)

    @unittest.skipIf(os.name == "nt", "POSIX fake executable fixture")
    def test_certify_rejects_wrong_major(self) -> None:
        os_name = {"Linux": "linux", "Darwin": "macos"}.get(platform.system(), platform.system().lower())
        arch = mod.normalize_arch(platform.machine())
        if os_name not in {"linux", "macos"} or arch not in {"x86_64", "aarch64"}:
            self.skipTest("unsupported test host")
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp) / "java"
            java.write_text(
                "#!/bin/sh\n"
                "cat >&2 <<'EOF'\n"
                "    java.home = /tmp/java\n"
                "    java.runtime.version = 17.0.12+7\n"
                "    java.vendor = Test Vendor\n"
                "    java.vm.name = Test VM\n"
                f"    os.name = {'Linux' if os_name == 'linux' else 'Mac OS X'}\n"
                f"    os.arch = {'amd64' if arch == 'x86_64' else 'aarch64'}\n"
                "openjdk version \"17.0.12\"\n"
                "EOF\n",
                encoding="utf-8",
            )
            java.chmod(java.stat().st_mode | stat.S_IXUSR)
            result = mod.certify(str(java), 21, os_name, arch)
            self.assertFalse(result["certified"])
            self.assertEqual(result["detectedMajor"], 17)


if __name__ == "__main__":
    unittest.main()
