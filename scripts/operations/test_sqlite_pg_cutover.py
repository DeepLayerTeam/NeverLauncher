"""Безопасное поведение оператора автономного переключения с использованием настоящего SQLite Backup API."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).with_name("sqlite_pg_cutover_0475.py")
spec = importlib.util.spec_from_file_location("cutover0475", MODULE)
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


class Operator0475Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source_env = self.root / "backend.env"
        self.source_env.write_text("LAUNCHER_REPOSITORY_DRIVER=sqlite\nLAUNCHER_DATABASE_DSN=/tmp/http.db\n")
        self.source_env.chmod(0o600)
        self.core = self.root / "core.db"
        self.http = self.root / "http.db"
        for path in (self.core, self.http):
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE marker(id INTEGER PRIMARY KEY, token TEXT)")
                db.execute("INSERT INTO marker(token) VALUES ('old-data')")
            path.chmod(0o600)
        self.opts = ["run", "--work-dir", str(self.root / "journal"),
                     "--source-env", str(self.source_env), "--core-db", str(self.core),
                     "--http-db", "/tmp/http.db", "--storage-source", str(self.root / "old"),
                     "--storage-target", str(self.root / "new"), "--writer-unit", "launcher.service",
                     "--project", "project-old", "--owner-email", "owner@example.invalid"]

    def operator(self):
        p = cutover.argparse.ArgumentParser()
        # Проверяйте парсер через основные аргументы, но создавайте объект оператора
        # с теми же явно определёнными значениями для испытания отдельных этапов.
        args = cutover.argparse.Namespace(
            work_dir=str(self.root / "journal"), launcher_sqlite="launcher-sqlite",
            source_env=str(self.source_env), core_db=str(self.core), http_db="/tmp/http.db",
            coordinator_db="", storage_source=str(self.root / "old"),
            storage_target=str(self.root / "new"), units=["launcher.service"],
            project="project-old", owner_email="owner@example.invalid",
            dsn_env="LAUNCHER_POSTGRES_DSN", mfa_key_file="", pg_secret_env="",
            health_url="http://127.0.0.1:8080/ready")
        return cutover.Operator(args)

    def test_real_sqlite_backup_preserves_rows_and_is_independent(self):
        backup = self.root / "backup.db"
        cutover.sqlite_backup(str(self.core), backup)
        with sqlite3.connect(self.core) as src:
            src.execute("INSERT INTO marker(token) VALUES ('later-write')")
        cutover.validate_sqlite_backup(backup)
        with sqlite3.connect(backup) as restored:
            self.assertEqual(restored.execute("SELECT count(*) FROM marker").fetchone()[0], 1)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        with self.assertRaises(cutover.CutoverError):
            cutover.sqlite_backup(str(self.core), backup)

    def test_wal_is_included_in_snapshot(self):
        backup = self.root / "wal-backup.db"
        with sqlite3.connect(self.core) as src:
            src.execute("PRAGMA journal_mode=WAL")
            src.execute("INSERT INTO marker(token) VALUES ('committed-in-wal')")
            src.commit()
            cutover.sqlite_backup(str(self.core), backup)
        with sqlite3.connect(backup) as restored:
            tokens = [r[0] for r in restored.execute("SELECT token FROM marker ORDER BY id")]
            self.assertEqual(tokens, ["old-data", "committed-in-wal"])

    def test_http_snapshot_digest_and_duplicates_rejected(self):
        from hashlib import sha256
        db_path = self.root / "http-snapshot.db"
        with sqlite3.connect(db_path) as db:
            db.execute("CREATE TABLE http_repository_state_0372(singleton INTEGER,state_version INTEGER,sequence INTEGER,sha256 TEXT,document BLOB)")
            data = b'{"projects":[],"users":[]}'
            db.execute("INSERT INTO http_repository_state_0372 VALUES(1,1,1,?,?)", (sha256(data).hexdigest(), data))
        db_path.chmod(0o600)
        cutover.verify_http_snapshot(db_path)
        with sqlite3.connect(db_path) as db:
            db.execute("UPDATE http_repository_state_0372 SET sha256='bad'")
        with self.assertRaisesRegex(cutover.CutoverError, "SHA-256"):
            cutover.verify_http_snapshot(db_path)
        with sqlite3.connect(db_path) as db:
            data = b'{"projects":[],"projects":[]}'
            db.execute("UPDATE http_repository_state_0372 SET sha256=?,document=?", (sha256(data).hexdigest(), data))
        with self.assertRaisesRegex(cutover.CutoverError, "duplicate"):
            cutover.verify_http_snapshot(db_path)

    def test_bad_sqlite_backup_is_rejected(self):
        bad = self.root / "bad.db"
        bad.write_bytes(b"not a SQLite database")
        bad.chmod(0o600)
        with self.assertRaises(sqlite3.DatabaseError):
            cutover.validate_sqlite_backup(bad)

    def test_private_file_and_symlink_required(self):
        self.core.chmod(0o644)
        with self.assertRaises(cutover.CutoverError):
            cutover.private_file(self.core)
        self.core.chmod(0o600)
        link = self.root / "alias"
        link.symlink_to(self.core)
        with self.assertRaises(cutover.CutoverError):
            cutover.private_file(link)

    def test_reject_duplicate_environment_configuration(self):
        self.source_env.write_text("LAUNCHER_DATABASE_DSN=first\nLAUNCHER_DATABASE_DSN=second\n")
        with self.assertRaises(cutover.CutoverError):
            cutover.parse_env(self.source_env)

    def test_preflight_requires_real_source_database(self):
        op = self.operator()
        op.env[op.a.dsn_env] = "postgres://localhost/test"
        with self.assertRaises(cutover.CutoverError):
            op.preflight()  # /файл tmp/http.db отсутствует

    def test_journal_resume_does_not_repeat_completed_stage(self):
        op = self.operator()
        op.init_workdir()
        invoked = []
        op.stage("preflight", lambda: invoked.append("preflight") or {"verified": True})
        recovered = self.operator()
        recovered.init_workdir()
        recovered.stage("preflight", lambda: invoked.append("re-run"))
        self.assertEqual(invoked, ["preflight"])
        self.assertEqual(recovered.state["completed"], ["preflight"])
        lines = recovered.journal_path.read_text().splitlines()
        self.assertEqual([json.loads(v)["status"] for v in lines], ["started", "completed"])

    def test_ambiguous_import_never_retried_automatically(self):
        op = self.operator()
        op.init_workdir()
        op.state["importOutcomeUnknown"] = True
        op.save()
        with self.assertRaisesRegex(cutover.CutoverError, "unknown"):
            self.operator().run()

    def test_cutover_rejected_without_complete_receipts(self):
        op = self.operator()
        op.init_workdir()
        op.state["cutoverSupported"] = False
        op.state["receipts"] = {"verify": {"readyForBackendCutover": True}}
        op.save()
        with mock.patch.object(op, "inactive"):
            with self.assertRaisesRegex(cutover.CutoverError, "HTTP/Coordinator"):
                op.cutover()
        self.assertEqual(cutover.parse_env(self.source_env)["LAUNCHER_REPOSITORY_DRIVER"], "sqlite")

    def test_rollback_rejected_if_postgres_may_have_accepted_writes(self):
        op = self.operator()
        op.init_workdir()
        op.state["writeBoundaryCrossed"] = True
        op.save()
        with self.assertRaisesRegex(cutover.CutoverError, "automatic rollback forbidden"):
            op.rollback()

    def test_safe_rollback_recovers_env_without_replacing_database(self):
        op = self.operator()
        op.init_workdir()
        op.a.http_db = str(self.http)
        op.state["completed"] = ["preflight", "backup", "freeze"]
        op.save()
        op.original_env.write_bytes(self.source_env.read_bytes())
        op.original_env.chmod(0o600)
        cutover.change_env(self.source_env, "postgres://localhost/example", "postgres", "/tmp/new-storage")
        before = cutover.sha256_file(self.core)
        with mock.patch.object(op, "inactive"), mock.patch.object(op, "service", return_value=(0, b"")):
            result = op.rollback()
        self.assertTrue(result["sourceDatabaseUntouched"])
        self.assertEqual(cutover.sha256_file(self.core), before)
        self.assertEqual(cutover.parse_env(self.source_env)["LAUNCHER_REPOSITORY_DRIVER"], "sqlite")

    def test_config_rewrite_leaves_unrelated_settings(self):
        self.source_env.write_text("# saved comment\nLAUNCHER_REPOSITORY_DRIVER=sqlite\nEXTRA=untouched\n")
        self.source_env.chmod(0o600)
        cutover.change_env(self.source_env, "postgres://localhost/test", "postgres", "/tmp/storage")
        self.assertIn("# saved comment", self.source_env.read_text())
        self.assertEqual(cutover.parse_env(self.source_env)["EXTRA"], "untouched")
        self.assertEqual(stat.S_IMODE(self.source_env.stat().st_mode), 0o600)

    def test_nonexistent_private_workdir_is_initialized(self):
        op = self.operator()
        op.init_workdir()
        self.assertEqual(stat.S_IMODE(op.work.stat().st_mode), 0o700)
        self.assertTrue(op.state_path.exists())


if __name__ == "__main__":
    unittest.main()
