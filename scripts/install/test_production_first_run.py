"""0.45.1: real TLS, one-time admin and verified deployment acceptance tests.

No fake HTTP server is ever accepted as evidence of a real production install.
The network simulation here only tests fail-closed orchestration.
"""
import importlib.util
import json
import os
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "production_deploy_0451", Path(__file__).with_name("production-deploy.py")
)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def env_values():
    return {
        "LAUNCHER_PUBLIC_URL": "https://launcher.example.org",
        "LAUNCHER_AUTH_TOKEN_SECRET": "a" * 64,
        "LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY": "b" * 64,
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON": '{"releases":["real"]}',
        "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON": '{"releases":["real"]}',
        "LAUNCHER_WEBAUTHN_RP_ID": "example.org",
        "LAUNCHER_WEBAUTHN_ORIGINS": "https://launcher.example.org",
        "LAUNCHER_CORS_ALLOWED_ORIGINS": "https://launcher.example.org",
        "POSTGRES_PASSWORD": "c" * 40,
        "LAUNCHER_IMAGE_TAG": "0.45.1",
        "LAUNCHER_BOOTSTRAP_TOKEN": "d" * 64,
        "LAUNCHER_REPOSITORY_DRIVER": "postgres",
        "LAUNCHER_DEPLOYMENT_MODE": "standard",
        "LAUNCHER_TLS_CERT_PATH": "/etc/launcher/tls/fullchain.pem",
        "LAUNCHER_TLS_KEY_PATH": "/etc/launcher/tls/privkey.pem",
    }


class ProductionFirstRunTests(unittest.TestCase):
    def files(self, root):
        env = root / ".env"
        env.write_text("".join(f"{k}={v}\n" for k,v in env_values().items()))
        env.chmod(0o600)
        (root / ".launcher-compose-state.json").write_text(json.dumps({"mode": "standard", "version": "0.45.1"}))
        (root / ".launcher-compose-state.json").chmod(0o600)
        pw = root / "password"
        pw.write_text("Sufficient-Password-For-Initial-Administrator-2026\n")
        pw.chmod(0o600)
        return SimpleNamespace(env=str(env), mode="standard", email="owner@example.org", display_name="Owner", password_file=str(pw))

    def test_real_first_admin_calls_endpoint_and_verifies_durable_state_and_login(self):
        with tempfile.TemporaryDirectory() as path:
            args = self.files(Path(path))
            calls = []
            def fake_api(url, **kwargs):
                calls.append((url, kwargs))
                if url.endswith("/ready"):
                    return {"status":"ready", "version": "0.45.1"}
                if url.endswith("/api/v1/install/readiness"):
                    if len([x for x, _ in calls if x.endswith("/api/v1/install/readiness")]) == 1:
                        return {"data":{"bootstrapTokenConsumed": False, "checks": [{"id":"admin-user","status":"missing"}]}}
                    return {"data":{"bootstrapTokenConsumed": True, "checks": [{"id":"admin-user","status":"ready"}]}}
                if url.endswith("/api/v1/install/bootstrap-admin"):
                    self.assertEqual(kwargs["payload"]["email"], args.email)
                    self.assertEqual(kwargs["headers"]["X-Launcher-Bootstrap-Token"], "d" * 64)
                    return {"data":{"status":"admin-created", "email": args.email}}
                if url.endswith("/api/v1/admin/login"):
                    self.assertEqual(kwargs["expected_status"], 200)
                    return {"token":"live-jwt", "user":{"email":args.email}}
                self.fail(f"unexpected endpoint: {url}")
            with patch.object(deploy, "tls_paths"), patch.object(deploy, "public_json", side_effect=fake_api):
                deploy.bootstrap_first_admin(args)
            self.assertEqual(len(calls), 5)
            self.assertTrue(calls[2][0].endswith("/api/v1/install/bootstrap-admin"))

    def test_admin_exists_refuses_second_bootstrap(self):
        with tempfile.TemporaryDirectory() as path:
            args = self.files(Path(path))
            called = []
            def fake_api(url, **kwargs):
                called.append(url)
                if url.endswith("/ready"):
                    return {"status":"ready", "version":"0.45.1"}
                return {"data":{"bootstrapTokenConsumed": True, "checks":[{"id":"admin-user","status":"ready"}]}}
            with patch.object(deploy, "tls_paths"), patch.object(deploy, "public_json", side_effect=fake_api):
                with self.assertRaisesRegex(RuntimeError, "already"):
                    deploy.bootstrap_first_admin(args)
            self.assertEqual(len(called), 2)

    def test_absent_state_and_unsafe_password_never_contact_backend(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            args = self.files(root)
            with patch.object(deploy, "tls_paths"), patch.object(deploy, "public_json") as request:
                (root / ".launcher-compose-state.json").unlink()
                with self.assertRaises((RuntimeError, OSError)):
                    deploy.bootstrap_first_admin(args)
                request.assert_not_called()
                (root / ".launcher-compose-state.json").write_text(json.dumps({"mode":"standard", "version":"0.45.1"}))
                (root / ".launcher-compose-state.json").chmod(0o600)
                (root / "password").chmod(0o644)
                with self.assertRaises(RuntimeError):
                    deploy.bootstrap_first_admin(args)
                request.assert_not_called()

    def test_tls_rejects_symlinks_and_untrusted_certificates(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "14",
                            "-subj", "/CN=launcher.example.org",
                            "-addext", "subjectAltName=DNS:launcher.example.org"],
                           check=True, capture_output=True)
            key.chmod(0o600)
            values = env_values()
            values["LAUNCHER_TLS_CERT_PATH"] = str(cert)
            values["LAUNCHER_TLS_KEY_PATH"] = str(key)
            with self.assertRaisesRegex(RuntimeError, "invalid|untrusted"):
                deploy.tls_paths(values)
            values["LAUNCHER_TLS_KEY_PATH"] = str(root / "linked-key.pem")
            (root / "linked-key.pem").symlink_to(key)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                deploy.tls_paths(values)
            self.assertIn("ssl_certificate_key", deploy.ROOT.joinpath("deploy/production/nginx.conf").read_text())
            self.assertIn("LAUNCHER_TLS_KEY_PATH", deploy.COMPOSE.read_text())


    def test_host_preflight_refuses_non_linux_and_missing_docker(self):
        with patch.object(deploy.sys, "platform", "win32"):
            with self.assertRaisesRegex(RuntimeError, "Linux"):
                deploy.host_preflight(fresh=True)
        with patch.object(deploy.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Docker"):
                deploy.host_preflight(fresh=True)

    def test_real_https_transport_accepts_trusted_cert_and_rejects_redirect(self):
        # В производстве используются системные корни SSL; этот локальный тест задаёт отдельный
        # одноразовый тестовый CA, не отключая проверку сертификатов.
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "14",
                            "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost"],
                           check=True, capture_output=True)

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *unused):
                    pass
                def do_GET(self):
                    if self.path == "/redirect":
                        self.send_response(302)
                        self.send_header("Location", "/ready")
                        self.end_headers()
                    else:
                        content = b'{"status":"ready","version":"0.45.1"}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
            server = HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            task = threading.Thread(target=server.serve_forever, daemon=True)
            task.start()
            url = "https://localhost:" + str(server.server_port)
            try:
                with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
                    self.assertEqual(deploy.public_json(url + "/ready")["version"], "0.45.1")
                    with self.assertRaisesRegex(RuntimeError, "HTTP 302"):
                        deploy.public_json(url + "/redirect")
                with patch.dict(os.environ, {"SSL_CERT_FILE": str(root / "no-trust.pem")}):
                    with self.assertRaisesRegex(RuntimeError, "unavailable or untrusted"):
                        deploy.public_json(url + "/ready")
            finally:
                server.shutdown()
                task.join(timeout=3)
                server.server_close()

    def test_production_environment_rejects_wrong_host_port_and_short_token(self):
        data = env_values()
        for value in ("https://launcher.example.org:444", "http://launcher.example.org"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    deploy.preflight(dict(data, LAUNCHER_PUBLIC_URL=value), "standard", docker=True)
        with self.assertRaises(RuntimeError):
            deploy.preflight(dict(data, LAUNCHER_TLS_KEY_PATH=""), "standard", docker=True)

    def test_compose_public_check_precedes_writing_accepted_state(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            args = SimpleNamespace(env=str(self.files(root).env), mode="standard", action="up", backup_confirmed=False, purge_data=False, confirm="")
            with patch.object(deploy, "execute"), patch.object(deploy, "tls_paths"), patch.object(deploy, "verify_public_ready", side_effect=RuntimeError("offline")), patch.object(deploy, "host_preflight"):
                with self.assertRaisesRegex(RuntimeError, "offline"):
                    deploy.compose_run(args)
            self.assertEqual(json.loads((root / ".launcher-compose-state.json").read_text())["mode"], "standard")
            # Свежая установка означает отсутствие файла состояния.
            (root / ".launcher-compose-state.json").unlink()
            with patch.object(deploy, "execute"), patch.object(deploy, "tls_paths"), patch.object(deploy, "verify_public_ready", side_effect=RuntimeError("offline")), patch.object(deploy, "host_preflight"):
                with self.assertRaisesRegex(RuntimeError, "offline"):
                    deploy.compose_run(args)
            self.assertFalse((root / ".launcher-compose-state.json").exists())


if __name__ == "__main__":
    unittest.main()
