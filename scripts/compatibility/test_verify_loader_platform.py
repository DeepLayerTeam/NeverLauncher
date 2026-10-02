#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "compatibility" / "verify-loader-platform.py"


class LoaderPlatformVerifierTests(unittest.TestCase):
    def run_case(self, os_name: str = "windows", arch: str = "aarch64", *, native_path: str | None = None, runtime_dir: str | None = None):
        internal_os = "osx" if os_name == "macos" else os_name
        native_path = native_path or f"natives/{internal_os}/{arch}/lwjgl.dll"
        runtime_dir = runtime_dir or f"C:/work/client/natives/{internal_os}/{arch}"
        install = {
            "status": "installed-and-verified",
            "loader": "fabric",
            "minecraftVersion": "26.3",
            "loaderVersion": "0.19.5",
            "vanilla": {
                "status": "installed-and-verified",
                "targets": [{"os": internal_os, "arch": arch}],
                "files": [{"kind": "native", "path": native_path, "size": 12, "sha256": "a" * 64}],
            },
        }
        cert = {
            "status": "passed",
            "nativesDirectory": runtime_dir,
            "classpathEntries": 12,
            "mainClass": "net.fabricmc.loader.impl.launch.knot.KnotClient",
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            install_p, cert_p, out_p = tmp / "install.json", tmp / "cert.json", tmp / "out.json"
            install_p.write_text(json.dumps(install), encoding="utf-8")
            cert_p.write_text(json.dumps(cert), encoding="utf-8")
            proc = subprocess.run([
                "python3", str(TOOL), "--install", str(install_p), "--certification", str(cert_p),
                "--loader", "fabric", "--os", os_name, "--arch", arch, "--output", str(out_p),
            ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            payload = json.loads(out_p.read_text(encoding="utf-8")) if out_p.exists() else None
            return proc, payload

    def test_accepts_exact_windows_arm64_native_tree(self):
        proc, payload = self.run_case()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(payload["targetOS"], "windows")
        self.assertEqual(payload["targetArch"], "aarch64")
        self.assertEqual(payload["nativeFileCount"], 1)
        self.assertRegex(payload["nativeTreeSha256"], r"^[0-9a-f]{64}$")

    def test_maps_macos_to_osx_materializer_tree(self):
        proc, payload = self.run_case("macos", "aarch64", native_path="natives/osx/aarch64/liblwjgl.dylib", runtime_dir="/tmp/client/natives/osx/aarch64")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(payload["materializerOS"], "osx")

    def test_rejects_foreign_arch_native(self):
        proc, _ = self.run_case(native_path="natives/windows/x86_64/lwjgl.dll")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("foreign native path", proc.stderr)

    def test_rejects_runtime_native_directory_mismatch(self):
        proc, _ = self.run_case(runtime_dir="C:/work/client/natives/windows/x86_64")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("nativesDirectory", proc.stderr)


if __name__ == "__main__":
    unittest.main()
