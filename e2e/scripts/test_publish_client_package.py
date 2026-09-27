#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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


class PasskeyStepUpTests(unittest.TestCase):
    class Client(module.APIClient):
        def __init__(self) -> None:
            self.token = "old-token"
            self.calls: list[tuple[str, str, object | None]] = []

        def json(self, method: str, path: str, payload: object | None = None) -> object:
            self.calls.append((method, path, payload))
            if path.endswith("/begin"):
                return {"data": {"transactionToken": "tx", "publicKey": {"challenge": "challenge"}}}
            if path.endswith("/complete"):
                return {"data": {"accessToken": "fresh-token", "session": {"authStrength": "phishing-resistant"}}}
            raise AssertionError(path)

    def test_passkey_step_up_refreshes_token_immediately_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "authenticator.py"
            state = Path(tmp) / "state.json"
            helper.write_text("# fixture\n", encoding="utf-8")
            state.write_text("{}\n", encoding="utf-8")
            client = self.Client()
            assertion = '{"transactionToken":"tx","credential":{"type":"public-key"}}'
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=assertion, stderr="")) as run:
                client.passkey_step_up(helper, state, sign_count=3)
            self.assertEqual(client.token, "fresh-token")
            self.assertEqual([path for _, path, _ in client.calls], [
                "/api/v1/auth/passkeys/step-up/begin",
                "/api/v1/auth/passkeys/step-up/complete",
            ])
            self.assertIn("--sign-count", run.call_args.args[0])
            self.assertIn("3", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
