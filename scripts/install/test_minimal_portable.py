"""Исполняемые регрессионные тесты восстановления между хостами зашифрованных SQLite, файлов и секретов."""

import importlib.util
import io
import tarfile
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import test_minimal_backup as fixtures

SPEC = importlib.util.spec_from_file_location("minimal_portable_0452", Path(__file__).with_name("minimal_portable.py"))
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


class PortableMinimalTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.MinimalBackupTests(methodName="test_backup_restore_relocation_with_sqlite_wal")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.base = fixture.base
        self.root = fixture.root
        self.secret = self.base / "recovery.key"
        self.secret.write_bytes(os.urandom(48))
        self.secret.chmod(0o600)
        self.output = self.base / "offhost.nmb"
        self.newhost = self.base / "newhost"
        self.newhost.mkdir(mode=0o700)
        self.target = self.newhost / "installation"

    def test_backup_portable_real_relocation_with_credentials_and_wal(self):
        portable.backup_portable(self.root, self.output, self.secret)
        data = self.output.read_bytes()
        self.assertTrue(data.startswith(portable.MAGIC))
        self.assertNotIn(b"server-secret-unchanged", data)
        self.assertEqual(portable.import_and_verify(self.output, self.secret)["status"], "verified")
        self.assertEqual(list(self.root.joinpath("backups").iterdir()), [])
        result = portable.import_and_verify(self.output, self.secret, target_root=self.target)
        self.assertEqual(result["status"], "restored")
        env = portable.core.read_install(self.target)
        self.assertEqual(env["LAUNCHER_AUTH_TOKEN_SECRET"], "server-secret-unchanged")
        self.assertEqual(env["LAUNCHER_DATABASE_DSN"], str(self.target / "db/http.sqlite"))
        import sqlite3
        for index, name in enumerate(portable.core.DB_NAMES):
            with sqlite3.connect(self.target / name) as db:
                self.assertEqual(db.execute("SELECT value FROM durable WHERE id=1").fetchone()[0], f"db-{index}")
        self.assertEqual((self.target / "storage/blobs/data.bin").read_bytes(), (self.root / "storage/blobs/data.bin").read_bytes())
        self.assertEqual((self.target / "extensions/config.json").read_bytes(), b'{"secret":"kept"}')
        with self.assertRaises(portable.core.BackupError):
            portable.import_and_verify(self.output, self.secret, target_root=self.target)

    def test_wrong_key_refuses_to_publish_target(self):
        portable.backup_portable(self.root, self.output, self.secret)
        self.secret.write_bytes(os.urandom(48))
        with self.assertRaisesRegex(portable.core.BackupError, "authentication failed"):
            portable.import_and_verify(self.output, self.secret, target_root=self.target)
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.newhost.iterdir()))

    def test_ciphertext_tamper_refuses_to_publish_target(self):
        portable.backup_portable(self.root, self.output, self.secret)
        with self.output.open("r+b") as f:
            f.seek(portable.HEADER_SIZE + 512)
            value = f.read(1)
            f.seek(portable.HEADER_SIZE + 512)
            f.write(bytes([value[0] ^ 1]))
        with self.assertRaisesRegex(portable.core.BackupError, "authentication failed"):
            portable.import_and_verify(self.output, self.secret, target_root=self.target)
        self.assertFalse(self.target.exists())

    def test_export_from_preexisting_snapshot_and_refuse_overwrite(self):
        source = portable.core.backup(self.root)
        portable.export(source, self.output, self.secret)
        self.assertEqual(portable.import_and_verify(self.output, self.secret)["status"], "verified")
        with self.assertRaises(portable.core.BackupError):
            portable.export(source, self.output, self.secret)

    def test_refuse_loose_secret_permissions_and_invalid_archive(self):
        self.secret.chmod(0o644)
        with self.assertRaises(portable.core.BackupError):
            portable.backup_portable(self.root, self.output, self.secret)
        self.assertFalse(self.output.exists())
        self.secret.chmod(0o600)
        self.output.write_bytes(b"INVALID")
        with self.assertRaises(portable.core.BackupError):
            portable.import_and_verify(self.output, self.secret, target_root=self.target)
        self.assertFalse(self.target.exists())

    def test_refuse_passphrase_inside_backed_up_root(self):
        internal = self.root / "config/recovery.key"
        internal.write_bytes(os.urandom(48))
        internal.chmod(0o600)
        with self.assertRaisesRegex(portable.core.BackupError, "outside"):
            portable.backup_portable(self.root, self.output, internal)
        self.assertFalse(self.output.exists())
        self.assertFalse(list((self.root / "backups").iterdir()))

    def test_authenticated_traversal_member_is_still_refused(self):
        # Даже аутентифицированный архив не вправе писать вне изолированного корня
        # восстановления: универсальный tar.extractall не используется.
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            info = tarfile.TarInfo("snapshot/../../escaped")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"X"))
        salt = os.urandom(portable.SALT_SIZE)
        nonce = os.urandom(portable.NONCE_SIZE)
        header = portable.MAGIC + salt + nonce
        encryptor = portable.Cipher(
            portable.algorithms.AES(portable.derive(portable.passphrase(self.secret), salt)),
            portable.modes.GCM(nonce),
        ).encryptor()
        encryptor.authenticate_additional_data(header)
        self.output.write_bytes(header + encryptor.update(stream.getvalue()) + encryptor.finalize() + encryptor.tag)
        with self.assertRaises(portable.core.BackupError):
            portable.import_and_verify(self.output, self.secret, target_root=self.target)
        self.assertFalse(self.target.exists())
        self.assertFalse((self.base / "escaped").exists())

    def test_minimal_installer_cli_portable_roundtrip(self):
        installer = Path(__file__).with_name("minimal-install.py")
        def call(*args):
            return subprocess.run([sys.executable, str(installer), *map(str, args)], check=True, capture_output=True, text=True)
        call("backup-portable", "--root", self.root, "--output", self.output, "--passphrase-file", self.secret)
        checked = json.loads(call("verify-portable", "--input", self.output, "--passphrase-file", self.secret).stdout)
        self.assertEqual(checked["status"], "ok")
        call("restore-portable", "--input", self.output, "--target-root", self.target, "--passphrase-file", self.secret)
        self.assertTrue((self.target / "db/http.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
