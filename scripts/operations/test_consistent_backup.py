"""Регрессионные тесты 0.51.8. Настоящие pgBackRest, Docker, S3 и Minecraft требуют внешнего испытательного окружения."""
import io
import hashlib
from datetime import datetime, timezone
from argparse import Namespace
from types import SimpleNamespace
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import consistent_backup_0518 as cb
import dr_03512 as dr


class Backup0518Tests(unittest.TestCase):
    def test_private_files_and_atomic_journal(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            src = base / "state.json"
            cb.save_exclusive(src, b"private")
            self.assertEqual(src.read_bytes(), b"private")
            self.assertEqual(stat.S_IMODE(src.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                cb.save_exclusive(src, b"different")
            cb.atomic_replace(src, b"updated")
            self.assertEqual(src.read_bytes(), b"updated")
            os.chmod(src, 0o644)
            with self.assertRaises(cb.BackupError):
                cb.safe_file(src)

    def test_freeze_and_resume_real_compose_commands_and_journal(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            states = {"api": "running", "worker": "running"}
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                if "stop" in args:
                    states.update(api="exited", worker="exited")
                if "up" in args:
                    states.update(api="running", worker="running")
                return b""
            with patch.object(cb.multi, "resolved_compose", return_value={"nodeId": "node-a", "machineIdentity": "machine-a", "sharedEndpoints": {"bucket": "test-bucket"}}), \
                 patch.object(cb, "local_services", side_effect=lambda *a: dict(states)), \
                 patch.object(cb, "execute", side_effect=run):
                run_id = "a" * 32
                result = cb.freeze(directory, "launcher", run_id)
                self.assertEqual(result["status"], "frozen")
                self.assertEqual(cb.assert_frozen(directory, "launcher", run_id)["nodeId"], "node-a")
                with self.assertRaisesRegex(cb.BackupError, "уже заморожен"):
                    cb.freeze(directory, "launcher", run_id)
                self.assertEqual(cb.thaw(directory, "launcher", run_id)["status"], "resumed")
                self.assertFalse((directory / cb.STATE_FILE).exists())
                self.assertTrue(any("stop" in c for c in calls))
                self.assertTrue(any("up" in c for c in calls))

    def test_fail_freeze_keeps_recoverable_journal(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            with patch.object(cb.multi, "resolved_compose", return_value={"nodeId": "node-a", "machineIdentity": "machine-a", "sharedEndpoints": {"bucket": "test-bucket"}}), \
                 patch.object(cb, "local_services", return_value={"api": "running", "worker": "running"}), \
                 patch.object(cb, "execute", side_effect=cb.BackupError("Остановка не удалась")):
                with self.assertRaises(cb.BackupError):
                    cb.freeze(directory, "launcher", "d" * 32)
            self.assertEqual(cb.frozen_record(directory, "launcher", "d" * 32)["phase"], "stopping")
            with self.assertRaisesRegex(cb.BackupError, "другой операции резервного копирования"):
                cb.frozen_record(directory, "launcher", "e" * 32)

    def test_pg_query_refuses_sessions_and_non_primary(self):
        with patch.object(cb.nn, "dsn_environment", return_value={}), \
             patch.object(cb, "execute", return_value=b"1|0|0/AB12\n"):
            self.assertEqual(cb.pg_query(Path("/redacted")), "0/AB12")
        for response in (b"0|0|0/AB12\n", b"1|1|0/AB12\n", b"1|0|unexpected\n"):
            with patch.object(cb.nn, "dsn_environment", return_value={}), \
                 patch.object(cb, "execute", return_value=response):
                with self.assertRaises(cb.BackupError):
                    cb.pg_query(Path("/redacted"))

    def test_real_pgbackrest_backup_metadata_does_not_pass_on_old_label(self):
        first = {"name": "nl", "status": {"code": 0}, "backup": [{"label": "20261102-100000F"}]}
        later = {"name": "nl", "status": {"code": 0}, "backup": [
            {"label": "20261102-100000F"},
            {"label": "20261103-100000F", "type": "full", "timestamp": {"stop": 1793700000},
             "archive": {"start": "000000010000000000000001", "stop": "000000010000000000000002"},
             "lsn": {"start": "0/100", "stop": "0/200"}}
        ]}
        with patch.object(cb, "pgbackrest", return_value=b""), \
             patch.object(cb, "pg_info", side_effect=[first, later]):
            self.assertEqual(cb.backup_physical("nl")["label"], "20261103-100000F")
        with patch.object(cb, "pgbackrest", return_value=b""), \
             patch.object(cb, "pg_info", side_effect=[first, first]):
            with self.assertRaisesRegex(cb.BackupError, "не зарегистрировал"):
                cb.backup_physical("nl")

    def test_s3_version_change_refuses_cohort_and_requires_versioning(self):
        with patch.object(cb, "execute", side_effect=[b'{"Status":"Suspended"}']):
            with self.assertRaisesRegex(cb.BackupError, "версионирование"):
                cb.s3_version_inventory("bucket.example", "https://s3.example")
        with patch.object(cb, "execute", side_effect=[b'{"Status":"Enabled"}',
                                                        b'{"Versions":[{"Key":"abc","VersionId":"2","IsLatest":true,"Size":4}]}']):
            self.assertEqual(cb.s3_version_inventory("bucket.example", "https://s3.example"),
                             [("Versions", "abc", "2", True, 4)])

    def test_safe_tar_refuses_links_and_path_escape(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            tarpath = base / "safe.tar.gz"
            with tarfile.open(tarpath, "w:gz") as output:
                entry = tarfile.TarInfo("abc/")
                entry.type = tarfile.DIRTYPE
                output.addfile(entry)
                data = b"contents"
                item = tarfile.TarInfo("abc/blob")
                item.size = len(data)
                output.addfile(item, io.BytesIO(data))
            cb.unpack_safe_tar(tarpath, base / "unpacked")
            self.assertEqual((base / "unpacked/abc/blob").read_bytes(), b"contents")
            for name,typ in (("../evil", tarfile.REGTYPE), ("bad-link", tarfile.SYMTYPE),
                             ("/abs", tarfile.REGTYPE)):
                with tarfile.open(tarpath, "w:gz") as output:
                    item = tarfile.TarInfo(name)
                    item.type = typ
                    if typ == tarfile.REGTYPE:
                        item.size = 1
                        output.addfile(item, io.BytesIO(b"a"))
                    else:
                        item.linkname = "../x"
                        output.addfile(item)
                with self.assertRaises(cb.BackupError):
                    cb.unpack_safe_tar(tarpath, base / ("bad-" + name.replace("/", "_")))

    def test_backup_verify_detects_incomplete_payload(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / "cohort"
            folder.mkdir()
            (folder / "identity-and-metadata.dump").write_bytes(b"pgdummy")
            manifest = {"schema": cb.SCHEMA, "runId": "a" * 32, "files": cb.tree_files(folder),
                        "postgres": {"backup": {"label": "20261103-100000F"}},
                        "nodes": ["node-a", "node-b"], "worlds": [{"name": "game", "backupId": "a" * 32}]}
            (folder / "manifest.json").write_text(json.dumps(manifest))
            os.chmod(folder / "manifest.json", 0o600)
            with self.assertRaisesRegex(dr.DrillError, "world backup"):
                cb.validate_backup(folder)
            (folder / "identity-and-metadata.dump").write_bytes(b"changed")
            with self.assertRaisesRegex(cb.BackupError, "контрольных сумм"):
                cb.validate_backup(folder)

    def test_pitr_restore_rejects_nonfresh_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            document = {"schema": cb.SCHEMA, "postgres": {"backup": {
                "label": "20261103-100000F", "stanza": "launcher"}}}
            (root / "manifest.json").write_text(json.dumps(document))
            os.chmod(root / "manifest.json", 0o600)
            args = type("Args", (), {"backup": str(root), "pgdata": str(root), "stanza": "launcher",
                                      "confirm": "20261103-100000F"})()
            with self.assertRaisesRegex(cb.BackupError, "чистый узел"):
                cb.restore_pg_fresh(args)

    def test_pgbackrest_restores_real_fresh_pgdata_with_lsn_or_pitr(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "cohort"
            source.mkdir()
            doc = {"schema": cb.SCHEMA, "postgres": {"cohortLsn": "0/12AB",
                "backup": {"label": "20261103-100000F", "stanza": "launcher"}}}
            (source / "manifest.json").write_text(json.dumps(doc))
            os.chmod(source / "manifest.json", 0o600)
            calls = []
            def restore(stanza, *opts):
                self.assertEqual(stanza, "launcher")
                calls.append(opts)
                dest = next(x[len("--pg1-path="):] for x in opts if x.startswith("--pg1-path="))
                Path(dest).mkdir()
                (Path(dest) / "PG_VERSION").write_text("17")
            for mode in ("cohort-pg-restore-fresh", "pitr-restore-fresh"):
                target = root / mode
                args = Namespace(action=mode, backup=str(source), pgdata=str(target), stanza="launcher",
                                 confirm="20261103-100000F", target_time="2026-11-03T12:00:00Z",
                                 pg_only_reconciliation_ack=(mode == "pitr-restore-fresh"))
                with patch.object(cb, "validate_backup", return_value={}), \
                     patch.object(cb, "pgbackrest", side_effect=restore):
                    self.assertEqual(cb.restore_pg_fresh(args)["status"], "restored-not-started")
            self.assertTrue(any("--type=lsn" in x and "--target=0/12AB" in x for x in calls))
            self.assertTrue(any("--type=time" in x for x in calls))
            self.assertTrue(all(any(v.startswith("--tablespace-map-all=") for v in x) for x in calls))

    def test_remote_ssh_rejects_untrusted_target(self):
        with self.assertRaises(cb.BackupError):
            cb.ssh("attacker;echo hi", "/opt/launcher/x.py", "local-freeze")
        command = cb.ssh("deploy@host.example", "/opt/launcher/x.py", "local-freeze", "--run-id", "a" * 32)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)

    def test_full_cohort_execution_with_real_archive_bytes_and_final_verification(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            os.chmod(base, 0o700)
            world_id = "b" * 32
            world_tree = base / "remote-world" / world_id
            (world_tree / "payload" / "world").mkdir(parents=True)
            payload = b"world bytes"
            (world_tree / "payload" / "world" / "level.dat").write_bytes(payload)
            world_manifest = {"schema": "launcher-world-backup/v1", "id": world_id,
                              "consistency": "confirmed-stopped", "worlds": ["world"],
                              "totalBytes": len(payload), "entries": [
                {"path": "world", "type": "dir", "mode": 448},
                {"path": "world/level.dat", "type": "file", "mode": 384,
                 "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}]}
            (world_tree / "manifest.json").write_text(json.dumps(world_manifest))
            worlds = base / "worlds.json"
            worlds.write_text(json.dumps([{"name": "game", "target": "game.example",
                                           "serverRoot": "/srv/game", "backupRoot": "/srv/world-backups",
                                           "world": "world"}]))
            trust = base / "trust.json"
            trust.write_text(json.dumps({"manifest-key": "a" * 64}))
            for f in (worlds, trust):
                os.chmod(f, 0o600)
            fake_archive = base / "world.tgz"
            with tarfile.open(fake_archive, "w:gz") as out:
                out.add(world_tree, arcname=world_id)
            vol_archive = base / "volume.tgz"
            with tarfile.open(vol_archive, "w:gz") as out:
                info = tarfile.TarInfo("local-file")
                info.size = 4
                out.addfile(info, io.BytesIO(b"data"))
            reports = []
            def remote(host, script, action, **kwargs):
                if action == "local-freeze":
                    machine = "machine-a" if host == "host-a.example" else "machine-b"
                    return {"status": "frozen", "runId": kwargs["run_id"],
                            "nodeId": machine, "machineIdentity": machine,
                            "sharedEndpoints": {"bucket": "backup-bucket"}}
                if action == "local-check":
                    return {"status": "frozen"}
                if action == "local-thaw":
                    reports.append(host)
                    return {"status": "resumed"}
                if action == "local-world-release":
                    return {"status": "world-released", "holdId": kwargs["run_id"]}
                if action == "local-world-create":
                    return {"backupId": world_id, "createdAt": datetime.now(timezone.utc).isoformat(),
                            "holdId": kwargs["run_id"]}
                raise AssertionError(action)
            def stream(cmd, target, **kwargs):
                source = fake_archive if ".world-" in target.name else vol_archive
                target.write_bytes(source.read_bytes())
            def download(bucket, dest, endpoint):
                dest.mkdir(parents=True)
                (dest / "blob").write_bytes(b"data")
            def fake_subprocess(args, **kwargs):
                self.assertEqual(args[0], "pg_dump")
                kwargs["stdout"].write(b"pgarchive")
                return SimpleNamespace(returncode=0)
            backup = {"stanza": "nl", "label": "20261103-100000F",
                      "archive": {"start": "A", "stop": "B"}}
            args = Namespace(acknowledge_maintenance=True, run_id="a" * 32,
                             node=["a=host-a.example", "b=host-b.example"], project="launcher",
                             directory="/opt/launcher/deploy/production", tar_image="alpine@sha256:" + "a" * 64,
                             stanza="nl", world_file=str(worlds), trust_file=str(trust),
                             external_auth_policy="none", external_source=[], destination=str(base / "snapshot"),
                             remote_script="/opt/launcher/scripts/operations/consistent_backup_0518.py",
                             pg_dsn_file=str(base / "pg.url"), s3_bucket="backup-bucket",
                             s3_endpoint="https://s3.example", world_cli="/opt/launcher/bin/nl")
            with patch.object(cb, "remote_json", side_effect=remote), \
                 patch.object(cb, "pg_query", return_value="0/100"), \
                 patch.object(cb, "backup_physical", return_value=backup), \
                 patch.object(cb, "stream_command", side_effect=stream), \
                 patch.object(cb, "s3_version_inventory", return_value=[("Versions", "blob", "ver1", True, 4)]), \
                 patch.object(cb.dr, "s3_download", side_effect=download), \
                 patch.object(cb.nn, "dsn_environment", return_value={}), \
                 patch.object(cb.subprocess, "run", side_effect=fake_subprocess), \
                 patch.object(cb, "execute", return_value=b""), \
                 patch.object(cb, "pgbackrest", return_value=b""), \
                 patch.object(cb, "pg_info", return_value={"name": "nl", "status": {"code": 0},
                            "backup": [{"label": backup["label"], "archive": backup["archive"]}]}):
                self.assertEqual(cb.orchestrate(args)["status"], "complete")
                self.assertEqual(cb.validate_backup(base / "snapshot", stanza="nl")["status"], "verified")
            self.assertEqual(sorted(reports), ["host-a.example", "host-b.example"])
            self.assertEqual(len(list((base / "snapshot" / "hosts").glob("*/*"))), 20)

    def test_external_providers_must_be_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "worlds.json"
            os.chmod(d, 0o700)
            path.write_text(json.dumps([{"name": "game", "target": "game.example", "serverRoot": "/srv/game",
                                         "backupRoot": "/srv/backup", "world": "world"}]))
            os.chmod(path, 0o600)
            self.assertEqual(cb.world_spec(path)[0]["name"], "game")
            path.write_text(json.dumps([{"name": "game", "target": "evil;foo", "serverRoot": "/srv/game",
                                         "backupRoot": "/srv/backup", "world": "world"}]))
            with self.assertRaises(cb.BackupError):
                cb.world_spec(path)

if __name__ == "__main__":
    unittest.main()
