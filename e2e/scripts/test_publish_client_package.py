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


class RetryAfterTests(unittest.TestCase):
    class Response:
        def __init__(self, headers: dict[str, str]):
            self.headers = headers

        def getheader(self, name: str, default: str = "") -> str:
            return self.headers.get(name, default)

    def test_retry_after_prefers_longest_server_reset(self) -> None:
        response = self.Response({"Retry-After": "7", "X-RateLimit-Reset": "11"})
        self.assertEqual(module.APIClient._retry_after_seconds(response), 12)

    def test_retry_after_is_bounded(self) -> None:
        response = self.Response({"Retry-After": "600"})
        self.assertEqual(module.APIClient._retry_after_seconds(response), 65)

    def test_retry_after_defaults_to_short_backoff(self) -> None:
        response = self.Response({})
        self.assertEqual(module.APIClient._retry_after_seconds(response), 2)


if __name__ == "__main__":
    unittest.main()
