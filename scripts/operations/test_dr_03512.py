"""Fail-closed tests for the real (Docker-backed) DR runner."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import dr_03512 as dr


class DR03512Tests(unittest.TestCase):
    def test_only_explicitly_confirmed_isolated_projects(self):
        for project, confirm in [
            ("launcher", "launcher"),
            ("nl-dr-test", "other"),
            ("nl-dr-../../bad", "nl-dr-../../bad"),
            ("nl-dr-", "nl-dr-"),
        ]:
            with self.subTest(project=project), self.assertRaises(dr.DrillError):
                dr.ensure_isolated(project, confirm)
        dr.ensure_isolated("nl-dr-restore01", "nl-dr-restore01")

    def make_tar(self, path: Path, items: list[tuple[str, str]]):
        with tarfile.open(path, "w:gz") as tar:
            for name, kind in items:
                data = b"sample"
                info = tarfile.TarInfo(name)
                if kind == "file":
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                elif kind == "dir":
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                elif kind == "link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/etc/passwd"
                    tar.addfile(info)

    def test_archive_rejects_traversal_link_duplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "a.tar.gz"
            for entries in [
                [("../escape", "file")],
                [("/tmp/escape", "file")],
                [("link", "link")],
                [("ok", "file"), ("ok", "file")],
            ]:
                self.make_tar(path, entries)
                with self.subTest(entries=entries), self.assertRaises(dr.DrillError):
                    dr.safe_tar(path)
            self.make_tar(path, [(".", "dir"), ("ok", "file")])
            self.assertEqual(dr.safe_tar(path), (1, 6))

    def test_real_tar_content_digest_does_not_trust_header_only(self):
        with tempfile.TemporaryDirectory() as folder:
            original, altered = (
                Path(folder) / "good.tar.gz",
                Path(folder) / "bad.tar.gz",
            )
            self.make_tar(original, [("file", "file")])
            with tarfile.open(altered, "w:gz") as tar:
                content = b"other!"
                entry = tarfile.TarInfo("file")
                entry.size = len(content)
                tar.addfile(entry, io.BytesIO(content))
            self.assertNotEqual(dr.tar_digests(original), dr.tar_digests(altered))

    def test_corrupt_snapshot_rejected_before_volume_inspection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            files = {"database.dump": b"database"}
            for volume in dr.STANDARD_VOLUMES:
                files[volume + ".tar.gz"] = b"placeholder"
            for name, contents in files.items():
                (root / name).write_bytes(contents)
            manifest = {
                "schema": 1,
                "storage": "local-volume",
                "volumes": list(dr.STANDARD_VOLUMES),
                "files": {
                    name: {
                        "size": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }
                    for name, body in files.items()
                },
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            (root / "database.dump").write_bytes(b"tampered")
            with (
                patch.object(dr, "docker_volume_exists") as exists,
                self.assertRaises(dr.DrillError),
            ):
                dr.restore_fresh(
                    "nl-dr-fresh", root / "environment", root, "nl-dr-fresh"
                )
            exists.assert_not_called()

    def test_existing_target_volume_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            files = {"database.dump": b"database"}
            for volume in dr.STANDARD_VOLUMES:
                tarpath = root / (volume + ".tar.gz")
                self.make_tar(tarpath, [(".", "dir")])
                files[tarpath.name] = tarpath.read_bytes()
            (root / "database.dump").write_bytes(files["database.dump"])
            manifest = {
                "schema": 1,
                "sourceProject": "nl-dr-original",
                "storage": "local-volume",
                "volumes": list(dr.STANDARD_VOLUMES),
                "files": {
                    name: {
                        "size": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }
                    for name, body in files.items()
                },
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            env = root / "secrets.env"
            env.write_text("EXAMPLE=foo")
            with (
                patch.object(dr, "docker_volume_exists", return_value=True),
                patch.object(dr, "compose") as compose,
                self.assertRaisesRegex(dr.DrillError, "already has state"),
            ):
                dr.restore_fresh("nl-dr-fresh", env, root, "nl-dr-fresh")
            compose.assert_not_called()

    def test_readiness_must_be_status_ready(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, *args):
                return b'{"status":"not_ready"}'

        with patch.object(dr, "urlopen", return_value=Response()):
            self.assertFalse(dr.ready("http://localhost:18080/ready"))

    def test_production_backup_requires_two_approvals_and_chaos(self):
        for production, approved in [(False, False), (True, False), (False, True)]:
            with self.assertRaises(dr.DrillError):
                dr.authorize_project(
                    "launcher", "launcher", production=production, approved=approved
                )
        dr.authorize_project("launcher", "launcher", production=True, approved=True)
        with self.assertRaises(dr.DrillError):
            dr.authorize_project(
                "launcher", "launcher", production=True, approved=True, chaos_mode=True
            )

    def test_s3_endpoint_requires_tls_unless_loopback(self):
        self.assertEqual(
            dr.s3_options("https://s3.example.org"),
            ["--endpoint-url", "https://s3.example.org"],
        )
        with self.assertRaises(dr.DrillError):
            dr.s3_options("http://s3.example.org")

    def test_s3_restore_verifies_remote_readback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "objects"
            root.mkdir()
            (root / "test.bin").write_bytes(b"correct")
            expected = {
                "test.bin": {
                    "size": 7,
                    "sha256": hashlib.sha256(b"correct").hexdigest(),
                }
            }

            def emulate_download(bucket, target, endpoint):
                target.mkdir()
                (target / "test.bin").write_bytes(b"wrong!!")

            with (
                patch.object(dr, "s3_list_first", return_value=False),
                patch.object(dr, "aws", return_value=""),
                patch.object(dr, "s3_download", side_effect=emulate_download),
                self.assertRaisesRegex(dr.DrillError, "readback differs"),
            ):
                dr.s3_upload_fresh("nl-dr-target", root, None, expected)

    def test_backup_manifest_verified_with_real_local_tar_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            names = ["database.dump", *(v + ".tar.gz" for v in dr.STANDARD_VOLUMES)]
            for name in names:
                path = root / name
                if name.endswith("tar.gz"):
                    self.make_tar(path, [(".", "dir"), ("data.txt", "file")])
                else:
                    path.write_bytes(b"postgres-custom-dump-fixture")
            data = {
                "schema": 1,
                "storage": "local-volume",
                "volumes": list(dr.STANDARD_VOLUMES),
                "files": {
                    name: {
                        "size": (root / name).stat().st_size,
                        "sha256": dr.sha256_file(root / name),
                    }
                    for name in names
                },
            }
            (root / "manifest.json").write_text(json.dumps(data))
            self.assertEqual(dr.verify_snapshot(root)["schema"], 1)
            with (root / names[1]).open("ab") as out:
                out.write(b"not-allowed")
            with self.assertRaisesRegex(dr.DrillError, "SHA-256"):
                dr.verify_snapshot(root)

    def test_chaos_rejects_nonloopback_target_before_docker(self):
        with patch.object(dr, "compose") as compose, self.assertRaises(dr.DrillError):
            dr.chaos(
                "nl-dr-test",
                Path("/env"),
                "https://production.example/ready",
                "nl-dr-test",
                False,
            )
        compose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
