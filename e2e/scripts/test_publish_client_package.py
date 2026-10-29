#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

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


class UploadRecoveryTests(unittest.TestCase):
    class Response:
        def __init__(self, status: int, payload: bytes = b"{}", connection: str = "") -> None:
            self.status = status
            self.payload = payload
            self.connection = connection

        def read(self) -> bytes:
            return self.payload

        def getheader(self, name: str, default: str = "") -> str:
            return self.connection if name == "Connection" else default

    def make_client(self) -> module.APIClient:
        return module.APIClient("http://127.0.0.1:8000", "test-token")

    def test_interrupted_file_upload_retries_exact_body_and_checks_response(self) -> None:
        client = self.make_client()
        conn = Mock()
        attempts = 0
        def transmit(method: str, path: str, **kwargs: object) -> None:
            nonlocal attempts
            attempts += 1
            if attempts <= 2:
                raise BrokenPipeError(32, "Broken pipe")
        conn.request.side_effect = transmit
        conn.getresponse.return_value = self.Response(201, b'{"file":"ok"}')
        # Reconnect to a fresh HTTPConnection on every transport failure.
        with patch.object(client, "_connect", return_value=conn), patch.object(module.time, "sleep") as sleep:
            status, response = client._request("POST", "/api/v1/admin/projects/p/versions/v/files", b"same-body", {"Content-Length": "9"})
        self.assertEqual((status, response), (201, b'{"file":"ok"}'))
        self.assertEqual(attempts, 3)
        self.assertEqual([call.kwargs["body"] for call in conn.request.call_args_list], [b"same-body"] * 3)
        self.assertEqual([call.kwargs["headers"]["Authorization"] for call in conn.request.call_args_list], ["Bearer test-token"] * 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_non_idempotent_post_has_no_extended_retries(self) -> None:
        client = self.make_client()
        conn = Mock()
        conn.request.side_effect = BrokenPipeError(32, "Broken pipe")
        with patch.object(client, "_connect", return_value=conn), patch.object(module.time, "sleep"):
            with self.assertRaises(BrokenPipeError):
                client._request("POST", "/api/v1/packages/id/sign", b"{}", {})
        self.assertEqual(conn.request.call_count, 2)

    def test_temporary_gateway_errors_retry_file_upload_only(self) -> None:
        client = self.make_client()
        conn = Mock()
        conn.getresponse.side_effect = [self.Response(503), self.Response(201, b"success")]
        with patch.object(client, "_connect", return_value=conn), patch.object(module.time, "sleep"):
            self.assertEqual(client._request("POST", "/api/v1/admin/projects/p/versions/v/files", b"body", {}), (201, b"success"))
        self.assertEqual(conn.request.call_count, 2)
        other = self.make_client()
        no_retry = Mock()
        no_retry.getresponse.return_value = self.Response(503)
        with patch.object(other, "_connect", return_value=no_retry):
            self.assertEqual(other._request("POST", "/api/v1/packages/id/sign", b"body", {}), (503, b"{}"))
        self.assertEqual(no_retry.request.call_count, 1)

    def test_connection_close_is_not_reused(self) -> None:
        client = self.make_client()
        conn = Mock()
        conn.getresponse.return_value = self.Response(201, connection="close")
        client.conn = conn
        self.assertEqual(client._request("POST", "/api/v1/admin/projects/p/versions/v/files", b"body", {})[0], 201)
        self.assertIsNone(client.conn)
        conn.close.assert_called_once()


class WebAuthnReplayProtectionTests(unittest.TestCase):
    def test_sign_count_survives_second_production_publish_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            counter = Path(tmp) / "passkey-counter.json"
            first = module.APIClient("http://127.0.0.1:8080", "first")
            first.use_passkey_counter_file(counter)
            first.passkey_sign_count = 4
            first.persist_passkey_counter()
            second = module.APIClient("http://127.0.0.1:8080", "second")
            second.use_passkey_counter_file(counter)
            self.assertEqual(second.passkey_sign_count, 4)
            with self.assertRaisesRegex(RuntimeError, "monotonically"):
                second.passkey_step_up(Path(tmp)/"helper", Path(tmp)/"state", sign_count=3)
            second.passkey_sign_count = 5
            second.persist_passkey_counter()
            self.assertEqual(module.APIClient("http://127.0.0.1:8080", "third").passkey_sign_count, 0)
            self.assertEqual(json.loads(counter.read_text())["signCount"], 5)

    def test_corrupt_or_symlinked_counter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            counter = Path(tmp) / "passkey-counter.json"
            counter.write_text('{"signCount":-1}')
            with self.assertRaisesRegex(RuntimeError, "invalid saved"):
                module.APIClient("http://127.0.0.1:8080", "token").use_passkey_counter_file(counter)
            counter.write_text('{"signCount":1}')
            link = Path(tmp) / "linked-counter.json"
            link.symlink_to(counter.name)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                module.APIClient("http://127.0.0.1:8080", "token").use_passkey_counter_file(link)


class PasskeyStepUpTests(unittest.TestCase):
    class Client(module.APIClient):
        def __init__(self) -> None:
            self.token = "old-token"
            self.passkey_sign_count = 0
            self.passkey_refreshed_at = 0.0
            self.passkey_helper = None
            self.passkey_state = None
            self.calls: list[tuple[str, str, object | None]] = []

        def json(self, method: str, path: str, payload: object | None = None) -> object:
            self.calls.append((method, path, payload))
            if path.endswith("/begin"):
                return {"data": {"transactionToken": "-tx-leading-dash", "publicKey": {"challenge": "-challenge-leading-dash"}}}
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
            assertion = '{"transactionToken":"-tx-leading-dash","credential":{"type":"public-key"}}'
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=assertion, stderr="")) as run:
                client.passkey_step_up(helper, state, sign_count=3)
            self.assertEqual(client.token, "fresh-token")
            self.assertEqual([path for _, path, _ in client.calls], [
                "/api/v1/auth/passkeys/step-up/begin",
                "/api/v1/auth/passkeys/step-up/complete",
            ])
            argv = run.call_args.args[0]
            self.assertIn("--transaction-token=-tx-leading-dash", argv)
            self.assertIn("--challenge=-challenge-leading-dash", argv)
            self.assertIn("--sign-count=3", argv)
            self.assertEqual(client.passkey_sign_count, 3)

    def test_long_upload_renews_at_eight_minutes_and_keeps_monotonic_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper, state = Path(tmp) / "authenticator.py", Path(tmp) / "state.json"
            helper.write_text("# fixture\n", encoding="utf-8")
            state.write_text("{}\n", encoding="utf-8")
            client = self.Client()
            client.set_upload_passkey(helper, state)
            assertion = '{"transactionToken":"x","credential":{"type":"public-key"}}'
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=assertion, stderr="")) as run, patch.object(module.time, "monotonic", side_effect=[100, 200, 581, 582, 583]):
                client.refresh_upload_auth_if_due(force=True)  # количество=1 @100
                client.refresh_upload_auth_if_due()            # через 100 секунд
                client.refresh_upload_auth_if_due()            # ещё через 481 секунду
                client.refresh_upload_auth_if_due()            # ещё через одну секунду
            self.assertEqual(run.call_count, 2)
            self.assertEqual([c.args[0][-1] for c in run.call_args_list], ["--sign-count=1", "--sign-count=2"])
            self.assertEqual(client.passkey_sign_count, 2)
            self.assertEqual(client.token, "fresh-token")

    def test_failed_assertion_does_not_consume_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper, state = Path(tmp) / "authenticator.py", Path(tmp) / "state.json"
            helper.write_text("# fixture\n", encoding="utf-8")
            state.write_text("{}\n", encoding="utf-8")
            client = self.Client()
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="", stderr="rejected")):
                with self.assertRaisesRegex(RuntimeError, "assertion helper failed"):
                    client.passkey_step_up(helper, state)
            self.assertEqual(client.passkey_sign_count, 0)
            self.assertEqual(client.token, "old-token")

    def test_non_increasing_counter_is_rejected(self) -> None:
        client = self.Client()
        client.passkey_sign_count = 2
        with self.assertRaisesRegex(RuntimeError, "monotonically"):
            client.passkey_step_up(Path("missing"), Path("missing"), sign_count=2)


if __name__ == "__main__":
    unittest.main()
