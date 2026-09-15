#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("publish-client-package.py")
spec = importlib.util.spec_from_file_location("publish_client_package", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SafeLocalTests(unittest.TestCase):
    def test_regular_file_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "libraries").mkdir()
            expected = root / "libraries" / "a.jar"
            expected.write_bytes(b"jar")
            self.assertEqual(module.safe_local(root, "libraries/a.jar"), expected.resolve())

    def test_traversal_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                module.safe_local(Path(tmp), "../secret")

    def test_symlink_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.jar"
            target.write_bytes(b"x")
            link = root / "link.jar"
            try:
                link.symlink_to(target.name)
            except OSError:
                self.skipTest("symlink unavailable")
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                module.safe_local(root, "link.jar")

    def test_symlink_directory_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            (real / "a.jar").write_bytes(b"x")
            link = root / "libraries"
            try:
                link.symlink_to(real.name, target_is_directory=True)
            except OSError:
                self.skipTest("symlink unavailable")
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                module.safe_local(root, "libraries/a.jar")


if __name__ == "__main__":
    unittest.main()
