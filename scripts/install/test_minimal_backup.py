import fcntl
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).with_name("minimal_backup.py")
SPEC = importlib.util.spec_from_file_location("minimal_backup_0376", MODULE)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


def database(path, label):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("CREATE TABLE durable (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO durable VALUES(1,?)", (label,))
    conn.commit()
    conn.close()
    os.chmod(path, 0o600)


class MinimalBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "installation"
        self.root.mkdir(mode=0o700)
        for part in ("config", "db", "storage", "extensions", "backups"):
            (self.root / part).mkdir(mode=0o700)
        data = {}
        for key, path in backup.RELOCATED.items():
            data[key] = str(self.root / path)
        data.update(
            LAUNCHER_DEPLOYMENT_MODE="single-node",
            LAUNCHER_REPOSITORY_DRIVER="sqlite",
            LAUNCHER_STORAGE_DRIVER="local",
            LAUNCHER_AUTH_TOKEN_SECRET="server-secret-unchanged",
        )
        config = self.root / "config/backend.env"
        config.write_text("".join(f"{k}={v}\n" for k, v in sorted(data.items())))
        config.chmod(0o600)
        for idx, name in enumerate(backup.DB_NAMES):
            database(self.root / name, f"db-{idx}")
        (self.root / "storage" / "blobs").mkdir(mode=0o700)
        (self.root / "storage" / "blobs" / "data.bin").write_bytes(os.urandom(4096))
        (self.root / "extensions" / "config.json").write_text('{"secret":"kept"}')

    def test_backup_restore_relocation_with_sqlite_wal(self):
        bundle = backup.backup(self.root)
        manifest = backup.verify(bundle)
        self.assertEqual(manifest["format"], backup.FORMAT)
        self.assertEqual(
            len([i for i in manifest["files"] if i["kind"] == "sqlite"]), 2
        )
        # Backup is immutable and includes committed data and extension/blob files.
        self.assertFalse((bundle / "payload" / "db/http.sqlite-wal").exists())
        dest = self.base / "restored"
        backup.restore(bundle, dest)
        self.assertEqual(
            backup.read_install(dest)["LAUNCHER_STORAGE_LOCAL_PATH"],
            str(dest / "storage"),
        )
        self.assertIn(
            "server-secret-unchanged", (dest / "config/backend.env").read_text()
        )
        for idx, name in enumerate(backup.DB_NAMES):
            with sqlite3.connect(dest / name) as conn:
                self.assertEqual(
                    conn.execute("SELECT value FROM durable WHERE id=1").fetchone()[0],
                    f"db-{idx}",
                )
        self.assertEqual(
            (dest / "storage/blobs/data.bin").read_bytes(),
            (self.root / "storage/blobs/data.bin").read_bytes(),
        )
        self.assertEqual(
            (dest / "extensions/config.json").read_bytes(),
            (self.root / "extensions/config.json").read_bytes(),
        )
        self.assertEqual(list((dest / "backups").iterdir()), [])
        with self.assertRaises(backup.BackupError):
            backup.restore(bundle, dest)

    def test_tampered_data_is_rejected_before_creating_target(self):
        bundle = backup.backup(self.root)
        with (bundle / "payload/storage/blobs/data.bin").open("ab") as f:
            f.write(b"tampered")
        with self.assertRaises(backup.BackupError):
            backup.verify(bundle)
        target = self.base / "must_not_exist"
        with self.assertRaises(backup.BackupError):
            backup.restore(bundle, target)
        self.assertFalse(target.exists())

    def test_running_api_lock_refuses_backup(self):
        lock_path = self.root / "storage/.launcher-api.owner.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(backup.BackupError, "running"):
                backup.backup(self.root)
            self.assertEqual(list((self.root / "backups").iterdir()), [])
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_symlink_content_refused_no_bundle_published(self):
        (self.root / "storage/link").symlink_to(self.root / "config/backend.env")
        with self.assertRaises(backup.BackupError):
            backup.backup(self.root)
        self.assertEqual(list((self.root / "backups").iterdir()), [])

    def test_corrupt_sqlite_rejected(self):
        bundle = backup.backup(self.root)
        db = bundle / "payload/db/coordinator.sqlite"
        with db.open("r+b") as f:
            f.write(b"not-sqlite-format")
        with self.assertRaises(backup.BackupError):
            backup.verify(bundle)

    def test_coordinator_owner_lock_refuses_backup(self):
        path = self.root / "db/coordinator.sqlite.owner.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(backup.BackupError, "running"):
                backup.backup(self.root)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_installer_cli_backup_verify_restore(self):
        installer = Path(__file__).with_name("minimal-install.py")
        created = subprocess.run(
            [sys.executable, str(installer), "backup", "--root", str(self.root)],
            text=True,
            capture_output=True,
            check=True,
        )
        bundle = Path(json.loads(created.stdout)["bundle"])
        verified = subprocess.run(
            [sys.executable, str(installer), "backup-verify", "--bundle", str(bundle)],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(verified.stdout)["operation"], "verify")
        dest = self.base / "restored-cli"
        subprocess.run(
            [
                sys.executable,
                str(installer),
                "restore",
                "--bundle",
                str(bundle),
                "--target-root",
                str(dest),
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            backup.read_install(dest)["LAUNCHER_DATABASE_DSN"],
            str(dest / "db/http.sqlite"),
        )

    def test_additional_sqlite_in_storage_captured(self):
        nested = self.root / "storage/asset-index.sqlite"
        database(nested, "optional-db")
        bundle = backup.backup(self.root)
        manifest = backup.verify(bundle)
        entry = next(
            i for i in manifest["files"] if i["path"] == "storage/asset-index.sqlite"
        )
        self.assertEqual(entry["kind"], "sqlite")
        restored = backup.restore(bundle, self.base / "new")
        with sqlite3.connect(restored / "storage/asset-index.sqlite") as conn:
            self.assertEqual(
                conn.execute("SELECT value FROM durable").fetchone()[0], "optional-db"
            )


if __name__ == "__main__":
    unittest.main()
