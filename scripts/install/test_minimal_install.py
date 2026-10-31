import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

MODULE = Path(__file__).with_name("minimal-install.py")
SPEC = importlib.util.spec_from_file_location("minimal_installer", MODULE)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class NativeMinimalInstallerTests(unittest.TestCase):
    def test_creates_private_persistent_install_and_rejects_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "api"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            guard = root / "guard.json"
            bridge = root / "bridge.json"
            guard.write_text(
                '{"schemaVersion":"2.0","releases":{"real-policy":{"x":1}}}'
            )
            bridge.write_text(
                '{"schemaVersion":"3.0","releases":{"real-policy":{"x":1}}}'
            )
            install = root / "install"
            env_file = installer.generate(
                install,
                "https://api.example.org",
                binary,
                guard,
                bridge,
                "127.0.0.1:8080",
            )
            self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
            env = installer.read_env(env_file)
            self.assertEqual(env["LAUNCHER_REPOSITORY_DRIVER"], "sqlite")
            self.assertEqual(env["LAUNCHER_DEPLOYMENT_MODE"], "single-node")
            self.assertEqual(env["LAUNCHER_PUBLIC_URL"], "https://api.example.org")
            self.assertNotIn("LAUNCHER_REDIS_URL", env)
            self.assertEqual(env["LAUNCHER_SERVERBRIDGE_HA_REQUIRED"], "false")
            self.assertGreater(len(env["LAUNCHER_BOOTSTRAP_TOKEN"]), 32)
            with self.assertRaises(ValueError):
                installer.generate(
                    install,
                    "https://api.example.org",
                    binary,
                    guard,
                    bridge,
                    "127.0.0.1:8080",
                )
            self.assertEqual(
                installer.read_env(env_file)["LAUNCHER_BOOTSTRAP_TOKEN"],
                env["LAUNCHER_BOOTSTRAP_TOKEN"],
            )

    def test_rejects_insecure_setup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "api"
            binary.write_text("binary")
            binary.chmod(0o700)
            guard = root / "guard.json"
            guard.write_text('{"releases":{"real":1}}')
            for url in (
                "http://api.example.org",
                "https://user:pass@api.example.org",
                "https://api.example.org/path",
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    installer.generate(
                        root / "install", url, binary, guard, guard, "127.0.0.1:8080"
                    )
            with self.assertRaises(ValueError):
                installer.generate(
                    root / "install",
                    "https://api.example.org",
                    binary,
                    guard,
                    guard,
                    "0.0.0.0:8080",
                )
