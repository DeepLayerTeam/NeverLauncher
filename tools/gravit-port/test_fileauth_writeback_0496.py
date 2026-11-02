import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("fileauth_writeback_0496.py")
spec = importlib.util.spec_from_file_location("writeback", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

UUID = "37a144c1-263e-4e9b-820f-917640f95b2d"
UUID2 = "4eaa8b1a-3456-4de9-8d1d-123d6052489a"


class Writeback0496(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "Database.json"
        self.source.write_text(json.dumps({
            UUID: {"username": "PlayerOne", "uuid": UUID, "password": "a" * 64,
                   "roles": ["ADMIN"], "other": {"nested": "value"}},
            UUID2: {"username": "PlayerTwo", "uuid": UUID2, "password": "b" * 64},
        }))
        self.source.chmod(0o600)
        self.backup = self.source.parent / "backup.json"
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def run_change(self, **opts):
        return module.writeback(source=self.source, backup=self.backup, expected_sha256=self.digest,
                                user_uuid=UUID, stopped_writers=True, **opts)

    def test_rename_commits_backup_and_preserves_unknown_fields(self):
        receipt = self.run_change(operation="rename", username="Renamed_0496")
        now = json.loads(self.source.read_text())
        old = json.loads(self.backup.read_text())
        self.assertEqual(now[UUID]["username"], "Renamed_0496")
        self.assertEqual(now[UUID]["roles"], ["ADMIN"])
        self.assertEqual(now[UUID]["other"], {"nested": "value"})
        self.assertEqual(old[UUID]["username"], "PlayerOne")
        self.assertEqual(receipt["sourceSha256"], self.digest)
        self.assertNotEqual(receipt["updatedSha256"], self.digest)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)

    def test_disabling_account_deletes_only_selected_uuid(self):
        self.run_change(operation="disable")
        data = json.loads(self.source.read_text())
        self.assertNotIn(UUID, data)
        self.assertIn(UUID2, data)

    def test_password_rotation_explicit_legacy_mode(self):
        password = self.source.parent / "pw.secret"
        password.write_bytes(b"new-password")
        password.chmod(0o600)
        with self.assertRaises(module.WritebackError):
            self.run_change(operation="set-password", password_file=password)
        self.run_change(operation="set-password", password_file=password, allow_legacy=True, password_format="sha256-hex")
        data = json.loads(self.source.read_text())
        self.assertEqual(data[UUID]["password"], hashlib.sha256(b"new-password").hexdigest())
        self.assertNotIn(b"new-password", self.source.read_bytes())
        self.assertEqual(data[UUID]["roles"], ["ADMIN"])

    def test_conflicts_and_unsafe_sources_fail_before_write(self):
        for kwargs in [
            {"expected_sha256": "0" * 64}, {"stopped_writers": False},
            {"username": "PlayerTwo"}, {"username": "bad name"},
        ]:
            arguments = dict(source=self.source, backup=self.backup, expected_sha256=self.digest,
                             user_uuid=UUID, operation="rename", username="Renamed", stopped_writers=True)
            arguments.update(kwargs)
            with self.assertRaises(module.WritebackError):
                module.writeback(**arguments)
            self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.digest)
        self.source.chmod(0o644)
        with self.assertRaises(module.WritebackError):
            self.run_change(operation="disable")
        self.source.chmod(0o600)
        self.assertFalse(self.backup.exists())

    def test_duplicate_json_keys_and_symlinks_rejected(self):
        bad = ('{"' + UUID + '":{"username":"PlayerOne","password":"' + 'a'*64 + '"},' +
               '"' + UUID + '":{"username":"PlayerTwo","password":"' + 'b'*64 + '"}}').encode()
        with self.assertRaises(module.WritebackError):
            module.parse_database(bad)
        real = self.source.with_name('target.json')
        self.source.rename(real)
        self.source.symlink_to(real)
        with self.assertRaises(module.WritebackError):
            self.run_change(operation="disable")


if __name__ == "__main__":
    unittest.main()
