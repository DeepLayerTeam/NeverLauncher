"""0.51.9: регрессия аварийного восстановления реальных байтов; действующие PostgreSQL, S3 и удалённый Docker проверяются отдельно."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import cross_host_recovery_0519 as rec


def ns(**kwargs):
    return argparse.Namespace(**kwargs)


def world_sample(base):
    wid = "a" * 32
    root = base / wid
    (root / "payload" / "world").mkdir(parents=True)
    data = b"Minecraft level byte verification\n"
    (root / "payload" / "world" / "level.dat").write_bytes(data)
    manifest = {"schema": "launcher-world-backup/v1", "id": wid,
                "consistency": "confirmed-stopped", "worlds": ["world"],
                "totalBytes": len(data), "entries": [
                    {"path": "world", "type": "dir", "mode": 0o700},
                    {"path": "world/level.dat", "type": "file", "mode": 0o600,
                     "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


class Recovery0519Tests(unittest.TestCase):
    def test_physical_lsn_order_not_string_concatenation(self):
        self.assertLess(rec.lsn_value("0/FFFFFFFE"), rec.lsn_value("1/0"))
        self.assertLess(rec.lsn_value("F/0"), rec.lsn_value("10/0"))

    def test_sources_are_verified_and_escrow_checked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            backup = root / "backup"; backup.mkdir()
            secret = root / "trust"; secret.write_text(json.dumps({"a": "f" * 64}))
            os.chmod(secret, 0o600)
            (backup / "manifest.json").write_text(json.dumps({
                "schema": rec.cb.SCHEMA, "version": "0.51.8",
                "trustEscrowSha256": {"a": "f" * 64}, "externalAuthPolicy": "none"}))
            os.chmod(backup / "manifest.json", 0o600)
            with patch.object(rec.cb, "validate_backup"):
                result = rec.verified_source(backup, "launcher", secret)
                self.assertEqual(result["version"], "0.51.8")
                secret.write_text(json.dumps({"a": "e" * 64}))
                with self.assertRaises(rec.RecoveryError):
                    rec.verified_source(backup, "launcher", secret)

    def test_world_tar_stream_restores_real_bytes_and_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = world_sample(root / "source")
            archive = root / "world.tar.gz"
            rec.world_stream_archive(source, archive)
            data = archive.read_bytes()
            target = root / "restored"; target.mkdir()
            destination = target / "new-world"
            with patch("sys.stdin", new=type("IO", (), {"buffer": io.BytesIO(data)})()):
                reply = rec.restore_world_local(ns(destination=str(destination), backup_id=source.name,
                                                  sha256=hashlib.sha256(data).hexdigest()))
            self.assertEqual(reply["status"], "restored")
            self.assertEqual((destination / "world" / "level.dat").read_bytes(),
                             b"Minecraft level byte verification\n")
            with self.assertRaises(rec.RecoveryError):
                rec.restore_world_local(ns(destination=str(destination), backup_id=source.name, sha256="f" * 64))

    def test_archive_mismatch_does_not_restore_world(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = world_sample(root / "source")
            archive = root / "world.tar.gz"
            rec.world_stream_archive(src, archive)
            with patch("sys.stdin", new=type("IO", (), {"buffer": io.BytesIO(archive.read_bytes())})()):
                with self.assertRaises(rec.RecoveryError):
                    rec.restore_world_local(ns(destination=str(root / "new"), backup_id=src.name,
                                               sha256="f" * 64))
            self.assertFalse((root / "new").exists())

    def test_state_is_private_crash_resumable_and_phase_checked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); os.chmod(root, 0o700)
            state = {"schema": rec.SCHEMA, "phase": "preparing", "prepared": []}
            rec.persist(root, state)
            self.assertEqual(stat.S_IMODE(rec.state_path(root).stat().st_mode), 0o600)
            state["prepared"].append("postgres-files")
            rec.persist(root, state)
            self.assertEqual(rec.read_state(root)["prepared"], ["postgres-files"])
            with self.assertRaises(FileExistsError):
                rec.cb.save_exclusive(rec.state_path(root), b"overwrite")
            os.chmod(root, 0o755)
            with self.assertRaises(rec.RecoveryError):
                rec.private_directory(root)

    def test_required_fresh_targets_and_complete_node_world_inventory(self):
        doc = {"nodes": [{"label": "a"}, {"label": "b"}], "worlds": [{"name": "world"}]}
        opts = ns(node=["a=op@new-a.example", "b=op@new-b.example"],
                  world_destination=["world=game@newgame.example:/srv/new-world"],
                  project="nl-dr-recovered", tar_image="alpine@sha256:" + "a" * 64)
        nodes, worlds = rec.target_spec(opts, doc)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(worlds["world"][1], "/srv/new-world")
        opts.world_destination = []
        with self.assertRaises(rec.RecoveryError):
            rec.target_spec(opts, doc)
        opts.world_destination = ["world=game@newgame.example:/srv/../old-world"]
        with self.assertRaises(rec.RecoveryError):
            rec.target_spec(opts, doc)
        opts.world_destination = ["world=game@newgame.example:/srv/new-world"]
        opts.node = ["a=op@new-a.example", "b=op@new-a.example"]
        with self.assertRaises(rec.RecoveryError):
            rec.target_spec(opts, doc)

    def test_source_bucket_always_rejected_and_deleted_versions_detected(self):
        with self.assertRaises(rec.RecoveryError):
            rec.fresh_bucket("source", "https://s3.example", "source")
        with patch.object(rec.cb, "s3_version_inventory", return_value=[("DeleteMarkers", "foo", "v1", True, None)]):
            with self.assertRaises(rec.RecoveryError):
                rec.fresh_bucket("fresh", "https://s3.example", "source")

    def test_volume_restore_rejects_duplicate_volume_before_reading_stdin(self):
        opts = ns(project="nl-dr-foo", volume="api_extensions", sha256="0"*64,
                  tar_image="alpine@sha256:" + "a"*64)
        with patch.object(rec, "docker_clean"), patch.object(rec.subprocess, "run", return_value=ns(returncode=0)):
            with self.assertRaises(rec.RecoveryError):
                rec.restore_volume_local(opts)

    def test_prepare_executes_real_volume_world_and_pg_restore_phases(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); os.chmod(root, 0o700)
            backup = root / "checkpoint"; backup.mkdir()
            work = root / "work"; work.mkdir(mode=0o700)
            trust = root / "trust.json"; trust.write_text("{}")
            os.chmod(trust, 0o600)
            source_world = world_sample(root / "source-world")
            target_world = backup / "worlds" / "survival" / source_world.name
            target_world.parent.mkdir(parents=True)
            import shutil
            shutil.copytree(source_world, target_world)
            for node in ("a", "b"):
                folder = backup / "hosts" / node
                folder.mkdir(parents=True)
                for volume in rec.cb.VOLUMES:
                    (folder / (volume + ".tar.gz")).write_bytes(b"transport-data")
            (backup / "s3").mkdir()
            doc = {"runId": "d"*32, "postgres": {"cohortLsn": "0/3D",
                "backup": {"label": "20261103-100000F", "stanza": "launcher"}},
                "s3": {"bucket": "old-bucket", "files": {"data": {"sha256": "0"*64, "size": 2}}},
                "nodes": [{"label": "a", "machineIdentity": "original-a"},
                          {"label": "b", "machineIdentity": "original-b"}],
                "worlds": [{"name": "survival", "backupId": source_world.name}],
                "frozenUtc": "2026-11-03T10:00:00+00:00", "completedUtc": "2026-11-03T10:04:00+00:00"}
            args = ns(backup=str(backup), work=str(work), trust_file=str(trust), stanza="launcher",
                      node=["a=ops@new-a.example", "b=ops@new-b.example"],
                      world_destination=["survival=ops@game.example:/srv/new-world"],
                      project="nl-dr-a", pgdata=str(root / "new-pgdata"),
                      s3_bucket="new-bucket", s3_endpoint="https://s3.example",
                      tar_image="alpine@sha256:" + "a"*64,
                      remote_script="/opt/launcher/scripts/operations/cross_host_recovery_0519.py")
            transferred = []
            def remote(host, script, action, *extra, **kw):
                self.assertEqual(action, "local-preflight")
                return {"status": "fresh", "machineIdentity": "fresh-"+host}
            def ship(host, script, action, source, *opts):
                transferred.append((host, action, Path(source).name))
                if action == "local-restore-volume":
                    return {"status": "restored", "volume": opts[opts.index("--volume") + 1]}
                return {"status": "restored", "backupId": source_world.name}
            def pg_restore(arg):
                target = Path(arg.pgdata)
                target.mkdir(); (target / "PG_VERSION").write_text("17")
            with patch.object(rec, "verified_source", return_value=doc), \
                 patch.object(rec, "fresh_bucket"), \
                 patch.object(rec, "remote_json", side_effect=remote), \
                 patch.object(rec, "transfer", side_effect=ship), \
                 patch.object(rec.cb, "restore_pg_fresh", side_effect=pg_restore), \
                 patch.object(rec.dr, "s3_upload_fresh"), \
                 patch.object(rec.cb, "s3_version_inventory", return_value=[("Versions", "data", "v1", True, 2)]):
                report = rec.prepare(args)
            self.assertEqual(report["status"], "prepared-not-admitted")
            self.assertEqual(report["restoredVolumes"], 20)
            self.assertEqual(len([c for c in transferred if c[1] == "local-restore-volume"]), 20)
            self.assertEqual(len([c for c in transferred if c[1] == "local-restore-world"]), 1)
            self.assertEqual(rec.read_state(work)["phase"], "prepared-not-admitted")
            with self.assertRaises(rec.RecoveryError):
                rec.prepare(args)  # сбой или повторная попытка не должны перезаписывать прежнее состояние

    def test_audit_readback_count_and_sampled_rpo(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger"
            path.write_text(json.dumps({"schema": "launcher.dr-ack-ledger/v1", "entries": [
                {"id": "audit-1", "ackUtc": "2026-11-03T12:00:00Z"},
                {"id": "audit-2", "ackUtc": "2026-11-03T12:04:00Z"}]}))
            os.chmod(path, 0o600)
            from datetime import datetime, timezone
            with patch.object(rec.cb, "execute", side_effect=[b"audit-1\n", b"\n"]):
                report = rec.audit_recovery(str(path), {}, datetime(2026, 11, 3, 12, 5, tzinfo=timezone.utc))
            self.assertEqual(report["auditEventsMissing"], 1)
            self.assertEqual(report["sampledAuditRpoSeconds"], 300)

    def test_replay_requires_fencing_before_start(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d); os.chmod(work, 0o700)
            pgdata = work / "pgdata"; pgdata.mkdir(); (pgdata / "PG_VERSION").write_text("17")
            rec.persist(work, {"schema": rec.SCHEMA, "phase": "prepared-not-admitted", "pgdata": str(pgdata)})
            opts = ns(work=str(work), source_fenced=False, pg_port=55439, socket_dir=str(work))
            with patch.object(rec.cb, "execute") as command:
                with self.assertRaises(rec.RecoveryError):
                    rec.replay_postgres(opts)
                command.assert_not_called()

    def test_replay_postgres_performs_paused_lsn_check_then_promotes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); os.chmod(root, 0o700)
            target = root / "pgdata"; target.mkdir(); (target / "PG_VERSION").write_text("17")
            sock = root / "socket"; sock.mkdir(mode=0o700)
            rec.persist(root, {"schema": rec.SCHEMA, "phase": "prepared-not-admitted",
                               "pgdata": str(target), "cohortLsn": "0/3D"})
            opts = ns(work=str(root), source_fenced=True, pg_port=55439, socket_dir=str(sock))
            with patch.object(rec.cb, "execute", return_value=b"" ) as pgctl, \
                 patch.object(rec, "pg_sql", side_effect=["true|true|0/3D", "", "f"]):
                receipt = rec.replay_postgres(opts)
            self.assertEqual(receipt["status"], "postgres-promoted-isolated")
            self.assertEqual(rec.read_state(root)["replayedLsn"], "0/3D")
            self.assertEqual(pgctl.call_count, 2)  # изолированный запуск, управляемая остановка

    def test_admission_checks_real_pg_schema_and_live_cluster_before_reporting_rto(self):
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); os.chmod(root, 0o700)
            frozen = datetime.now(timezone.utc) - timedelta(minutes=3)
            incident = datetime.now(timezone.utc) - timedelta(minutes=2)
            rec.persist(root, {"schema": rec.SCHEMA, "phase": "postgres-promoted-isolated",
                               "runId": "f"*32, "project": "nl-dr-check",
                               "nodes": {"a": "ops@new-a.example", "b": "ops@new-b.example"},
                               "worldTargets": {"survival": ["ops@game.example", "/srv/world"]},
                               "frozenUtc": frozen.isoformat(), "prepared": []})
            opts = ns(work=str(root), source_fenced=True, external_secrets_restored=True,
                      project="nl-dr-check", ready_url="https://new.example/ready",
                      incident_at=incident.isoformat(), pg_dsn_file=str(root / "dsn"),
                      ack_ledger=None, multi_host_script="/opt/launcher/scripts/operations/multi_host_0512.py",
                      directory="/opt/launcher/deploy/production")
            with patch.object(rec.nn, "dsn_environment", return_value={}), \
                 patch.object(rec.cb, "execute", return_value=b"t\n"), \
                 patch.object(rec.nn, "migration_catalog", return_value=({}, "digest")), \
                 patch.object(rec.nn, "live_pg_migrations", return_value={}), \
                 patch.object(rec.nn, "validate_schema", return_value={}) as schema, \
                 patch.object(rec, "remote_json", return_value={"ready": True, "configurationValidated": True,
                    "live": {"containers": [{"service": role, "running": True,
                        "readiness": {"versionVerified": True, "version": "0.51.9",
                                      "success": 3, "sampled": 3}} for role in ("api", "worker")]} }), \
                 patch.object(rec.multi, "cluster_verify", return_value={"multiHostControlPlaneObserved": True}):
                result = rec.admission(opts)
            schema.assert_called_once()
            self.assertEqual(result["status"], "recovery-ready")
            self.assertGreaterEqual(result["rtoSeconds"], 100)
            self.assertEqual(result["nodesReady"], 2)
            self.assertFalse(result["rpoMeasured"])
            self.assertTrue((root / rec.RECORD).is_file())

    def test_old_binary_is_not_admitted_even_if_healthy(self):
        report = {"ready": True, "configurationValidated": True,
                  "live": {"containers": [{"service": role, "running": True,
                    "readiness": {"versionVerified": True, "version": "0.51.8", "success": 3, "sampled": 3}}
                    for role in ("api", "worker")]}}
        with self.assertRaises(rec.RecoveryError):
            rec.assert_recovered_runtime(report)
        for row in report["live"]["containers"]:
            row["readiness"]["version"] = "0.51.9"
        self.assertTrue(rec.assert_recovered_runtime(report))

    def test_admit_requires_promoted_pg_and_fenced_source(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d); os.chmod(work, 0o700)
            rec.persist(work, {"schema": rec.SCHEMA, "phase": "prepared-not-admitted"})
            with self.assertRaises(rec.RecoveryError):
                rec.admission(ns(work=str(work), source_fenced=True, external_secrets_restored=True))


if __name__ == "__main__":
    unittest.main()
