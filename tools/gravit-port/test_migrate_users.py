"""Сохраняющие состояние тесты миграции пользователей с намеренными сценариями отказов."""
import importlib.util
import json
import hashlib
import http.server
import ssl
import subprocess
import shutil
import threading
from urllib.request import build_opener, HTTPSHandler, ProxyHandler
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("migrate_users_0494", Path(__file__).with_name("migrate_users_0494.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

UUID1 = "11111111-2222-4333-8444-555555555555"
UUID2 = "22222222-2222-4333-8444-555555555555"
RUN = "12345678-abcd"


class Stub:
    def __init__(self, src, manual_reset=0, fail_at=None):
        self.size, self.digest = m.source_hash(src)
        self.fail_at = fail_at
        self.calls = []
        self.user = "gravit-sql-" + UUID1.replace("-", "")
        self.rows = [{"provider": "sql", "sourceId": "1", "username": "PlayerA", "uuid": UUID1, "state": "imported"}]
        if manual_reset:
            self.rows.append({"provider": "sql", "sourceId": "2", "username": "PlayerB", "uuid": UUID2, "state": "manual_reset"})
        self.auth = {"sourceSha256": self.digest, "runId": RUN, "identitySha256": "identitydigest", "rows": self.rows, "imported": 1, "manualReset": manual_reset, "existingUnchanged": 0}

    def request(self, method, path, source=None, headers=None, payload=None):
        self.calls.append((method, path, headers or {}, payload))
        if self.fail_at and self.fail_at in path:
            raise m.MigrationError("injected failure")
        if path.endswith("/inventory"):
            return {"sourceSha256": self.digest, "sourceBytes": self.size}
        if path.endswith("/identities") or path.endswith("/identities/verify"):
            return {"runId": RUN, "sourceSha256": self.digest, "entriesSha256": "identitydigest", "summary": {"blocked": 0, "pending_import": 1}, "rows": list(self.rows)}
        if path.endswith("/credentials/preview"):
            return {**self.auth, "dryRun": True}
        if path.endswith("/credentials/import"):
            return {**self.auth, "dryRun": False}
        if path.endswith("/credentials"):
            return {**self.auth, "dryRun": False}
        if path.endswith("/security/preview"):
            return {"importedAccounts": 1, "appliedAt": None}
        if path.endswith("/security/activate"):
            # Первый реальный COMMIT не отмечается проверенным до следующего GET.
            return {"importedAccounts": 1, "appliedAt": "2026-11-02T16:00:00Z", "verified": False}
        if path.endswith("/security"):
            return {"importedAccounts": 1, "verified": True}
        if path.endswith("/admin/users"):
            return {"items": [{"id": self.user, "roleId": "player", "status": "active", "projectRoles": {}}]}
        if method == "PATCH":
            return {"id": self.user, "projectRoles": payload["projectRoles"]}
        raise AssertionError((method, path))


class MigrationUsersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "source.zip"
        self.path.write_bytes(b"gravit source: a test ZIP stand-in used only with a stub API")

    def test_prepare_does_not_import_or_reset_trust(self):
        api = Stub(self.path)
        receipt = m.migrate(api, RUN, self.path, "prepare", "sha256-hex")
        self.assertEqual(receipt["status"], "prepared")
        self.assertNotIn("/import", " ".join(p for _, p, _, _ in api.calls))
        self.assertNotIn("/activate", " ".join(p for _, p, _, _ in api.calls))

    def test_import_credentials_trust_and_reverify(self):
        api = Stub(self.path)
        receipt = m.migrate(api, RUN, self.path, "import", "")
        self.assertEqual(receipt["status"], "trust_reset_verified")
        self.assertTrue(any(h.get("X-Migration-Import-Confirm") == RUN for _, p, h, _ in api.calls if p.endswith("/credentials/import")))
        self.assertTrue(any(h.get("X-Migration-Fresh-Keys-Confirmed") == "true" for _, p, h, _ in api.calls if p.endswith("/security/activate")))
        self.assertEqual(receipt["credentialCounts"]["imported"], 1)

    def test_manual_resets_default_fail_closed(self):
        api = Stub(self.path, manual_reset=1)
        with self.assertRaises(m.MigrationError):
            m.migrate(api, RUN, self.path, "import", "")
        self.assertFalse(any(p.endswith("/credentials/import") for _, p, _, _ in api.calls))
        receipt = m.migrate(Stub(self.path, manual_reset=1), RUN, self.path, "import", "", allow_resets=True)
        self.assertEqual(receipt["credentialCounts"]["manual_reset"], 1)

    def test_changed_source_and_failed_stage_cannot_reach_activation(self):
        api = Stub(self.path)
        self.path.write_bytes(b"changed")
        with self.assertRaises(m.MigrationError):
            m.migrate(api, RUN, self.path, "import", "")
        self.assertEqual(len(api.calls), 1)
        self.path.write_bytes(b"original")
        api = Stub(self.path, fail_at="/credentials/preview")
        with self.assertRaises(m.MigrationError):
            m.migrate(api, RUN, self.path, "import", "")
        self.assertFalse(any(p.endswith("/credentials/import") for _, p, _, _ in api.calls))

    def test_roles_are_opt_in_and_cas_protected(self):
        role_file = Path(self.tmp.name) / "roles.json"
        role_file.write_text(json.dumps({"projectId": "game", "grants": [{"uuid": UUID1, "roleId": "operator"}]}))
        api = Stub(self.path)
        result = m.migrate(api, RUN, self.path, "import", "", roles_file=role_file)
        self.assertEqual(result["status"], "roles_applied")
        updates = [(h, payload) for method, path, h, payload in api.calls if method == "PATCH"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][1], {"projectRoles": {"game": "operator"}, "expectedProjectRoles": {}})
        role_file.write_text(json.dumps({"projectId": "game", "grants": [{"uuid": UUID2, "roleId": "owner"}]}))
        with self.assertRaises(m.MigrationError):
            m.role_plan(role_file, api.rows, [{"id": api.user, "roleId": "player", "status": "active", "projectRoles": {}}])

    def test_role_duplicate_uuid_and_receipt_no_overwrite(self):
        role_file = Path(self.tmp.name) / "roles.json"
        role_file.write_text(json.dumps({"projectId": "game", "grants": [{"uuid": UUID1, "roleId": "owner"}, {"uuid": UUID1, "roleId": "owner"}]}))
        with self.assertRaises(m.MigrationError):
            m.role_plan(role_file, Stub(self.path).rows, [{"id": "gravit-sql-" + UUID1.replace("-", ""), "roleId": "player", "status": "active", "projectRoles": {}}])
        receipt = Path(self.tmp.name) / "receipt.json"
        m.atomic_receipt(receipt, {"count": 1})
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(m.MigrationError):
            m.atomic_receipt(receipt, {"count": 2})
        self.assertEqual(json.loads(receipt.read_text()), {"count": 1})

    def test_texture_map_for_real_existing_importer(self):
        api = Stub(self.path)
        target = Path(self.tmp.name) / "texture-map.json"
        receipt = m.migrate(api, RUN, self.path, "import", "", texture_mapping_output=target)
        self.assertEqual(receipt["textureMappingEntries"], 1)
        self.assertEqual(json.loads(target.read_text()), [{"source_uuid": UUID1, "target_uuid": UUID1}])
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(shutil.which("openssl"), "openssl unavailable")
    def test_actual_https_stream_and_redirect_is_blocked(self):
        cert = Path(self.tmp.name) / "local.pem"
        key = Path(self.tmp.name) / "local.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        observed = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.headers.get("Authorization"), self.headers.get("Content-Type"), raw))
                body = json.dumps({"data": {"sha": hashlib.sha256(raw).hexdigest()}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://not-our-backend.invalid/steal")
                self.end_headers()
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            backend = m.Backend("https://localhost:%d" % server.server_port, "secret-for-unit-test")
            backend.opener = build_opener(ProxyHandler({}), m.NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))))
            data = backend.request("POST", "/upload", source=self.path)
            self.assertEqual(data["sha"], hashlib.sha256(self.path.read_bytes()).hexdigest())
            self.assertEqual(observed, [("Bearer secret-for-unit-test", "application/zip", self.path.read_bytes())])
            with self.assertRaises(m.MigrationError):
                backend.request("GET", "/redirect")
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()

    def test_https_only_and_environment_token(self):
        with self.assertRaises(m.MigrationError):
            m.Backend("http://localhost:8080", "secret")
        with self.assertRaises(m.MigrationError):
            m.Backend("https://admin:pass@example.com", "secret")
        with self.assertRaises(m.MigrationError):
            m.Backend("https://example.com", "")


if __name__ == "__main__":
    unittest.main()
