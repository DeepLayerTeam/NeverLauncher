#!/usr/bin/env python3
"""Real Java source-port compiler/package tests; no mocked javac or signing."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gravit_port", Path(__file__).with_name("port.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class SourcePortTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gravit-port-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "src" / "example"
        self.source.mkdir(parents=True)
        self.source.joinpath("Module.java").write_text('''package example;
import pro.gravit.launcher.base.modules.*;
public final class Module extends LauncherModule {
  public void init(LauncherInitContext context) {}
}
''')
        self.manifest = self.base / "manifest.json"
        self.manifest.write_text(json.dumps({"schemaVersion": "2.0", "id": "org.example.source-port", "name": "Source Port", "version": "0.1.0", "publisher": "Example", "api": "1.0", "permissions": [], "targets": [{"kind":"backend", "entrypoint":"backend/gravit-port.jar"}]}))

    def cmd(self, output=None):
        return [sys.executable, str(Path(__file__).with_name("port.py")), "--source", str(self.source.parent), "--module-class", "example.Module", "--manifest", str(self.manifest), "--output", str(output or self.base / "build")]

    def test_real_compile_and_refuse_overwrite(self):
        result = subprocess.run(self.cmd(), cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        location = self.base / "build"
        with zipfile.ZipFile(location / "backend" / "gravit-port.jar") as z:
            self.assertIn("example/Module.class", z.namelist())
            self.assertIn("ru/launcher/sdk/host/JavaExtensionHost.class", z.namelist())
        self.assertEqual((location / "launcher-extension.json").read_bytes(), self.manifest.read_bytes())
        again = subprocess.run(self.cmd(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("destination already exists", again.stderr)

    def test_unsupported_gravit_api_fails_compilation(self):
        self.source.joinpath("Module.java").write_text('''package example;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launcher.base.modules.*;
public final class Module extends LauncherModule {
  public void init(LauncherInitContext ctx){ LaunchServer server = null; }
}
''')
        result = subprocess.run(self.cmd(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "build").exists())

    def test_not_a_module_fails_without_package(self):
        self.source.joinpath("Module.java").write_text("package example; public final class Module {}")
        result = subprocess.run(self.cmd(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must directly extend", result.stderr)
        self.assertFalse((self.base / "build").exists())

    def test_manifest_permissions_and_symlink_fail_closed(self):
        raw = json.loads(self.manifest.read_text())
        raw["targets"][0]["entrypoint"] = "backend/another.jar"
        self.manifest.write_text(json.dumps(raw))
        self.assertNotEqual(subprocess.run(self.cmd(), cwd=ROOT, capture_output=True).returncode, 0)
        raw["targets"][0]["entrypoint"] = "backend/gravit-port.jar"
        self.manifest.write_text(json.dumps(raw))
        (self.source / "Link.java").symlink_to(self.source / "Module.java")
        result = subprocess.run(self.cmd(), cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)

    def test_signing_requires_all_credentials(self):
        result = subprocess.run(self.cmd() + ["--private-key", "arbitrary.pem"], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "build").exists())


if __name__ == "__main__":
    unittest.main()
