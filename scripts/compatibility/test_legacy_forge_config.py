#!/usr/bin/env python3
"""Regression tests for NightConfig's Forge 1.14.4 first-launch failure."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "e2e/scripts/prepare-legacy-forge-config.py"
spec = importlib.util.spec_from_file_location("prepare_legacy_forge_config", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LegacyForgeConfigTest(unittest.TestCase):
    def test_first_launch_seeds_complete_valid_fml_toml(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertTrue(module.prepare(root, "1.14.4"))
            config = tomllib.loads((root / "config/fml.toml").read_text())
            self.assertEqual(config, {
                "versionCheck": True,
                "splashscreen": True,
                "defaultConfigPath": "defaultconfigs",
                "maxThreads": -1,
            })
            self.assertFalse(module.prepare(root, "1.14.4"))

    def test_existing_player_config_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "config").mkdir()
            existing = root / "config/fml.toml"
            existing.write_text('versionCheck = false\n')
            self.assertFalse(module.prepare(root, "1.14.4"))
            self.assertEqual(existing.read_text(), 'versionCheck = false\n')

    def test_other_forge_versions_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for version in ("1.12.2", "1.13.2", "1.15.2", "26.3"):
                self.assertFalse(module.prepare(root, version))
            self.assertFalse((root / "config").exists())

    def test_rejects_symlink_config_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            outside = root / "outside"
            outside.mkdir()
            (root / "config").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.prepare(root, "1.14.4")
            self.assertFalse((outside / "fml.toml").exists())

    def test_forge_certification_wires_before_launch(self):
        source = (SCRIPT.parent / "run-forge-certification-case.sh").read_text()
        i = source.index("prepare-legacy-forge-config.py")
        self.assertLess(source.index('"$NL_BIN" client verify'), i)
        self.assertLess(i, source.index('certification_run_client "$TARGET_OS"'))


if __name__ == "__main__":
    unittest.main()
