import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("rehearse", Path(__file__).with_name("rehearse_cohort_04910.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
H = "a" * 64
UUID = "12345678-1234-1234-1234-123456789abc"


def write(path: Path, data: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return hashlib.sha256(data).hexdigest()


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "private"
        self.out.mkdir(mode=0o700)
        self.launcher = self.root / "launcher-cli"
        launcher_hash = write(self.launcher, b"#!/bin/sh\nexit 0\n", 0o700)
        self.config = {"format": mod.FORMAT, "launcher": str(self.launcher),
                       "launcherSha256": launcher_hash, "backend": "https://localhost:443", "projects": []}
        for i, cls in enumerate(mod.CLASSES):
            base = self.root / cls
            base.mkdir()
            source = base / "source.zip"
            with zipfile.ZipFile(source, "w") as zipfile_obj:
                zipfile_obj.writestr("profile.json", f"real-input-shape-{i}")
            source_sha = mod.sha(source)
            source.chmod(0o600)
            mp = base / "mapping.json"
            mapping_sha = write(mp, b'[{"profilePath":"profiles/main.json"}]')
            run = f"run_{i:09}"
            inv = hashlib.sha256(f"inventory{i}".encode()).hexdigest()
            report = base / "dry-run.json"
            report_sha = write(report, json.dumps({"data": {"runId": run, "sourceSha256": source_sha,
                     "inventorySha256": inv, "status": "manual", "blockers": []}}).encode())
            stage = base / "stage"
            stage.mkdir()
            write(stage / ".migration-stage.json", json.dumps({"format": "never/migration-stage/v1",
                                "runId": run, "isolated": True}).encode())
            write(stage / "live-session.json", b'{"rconAddress":"127.0.0.1:25575","clientPath":"installed/runtime.bin"}')
            for name in ("source-snapshot.json", "target-snapshot.json", "rcon-password"):
                write(stage / name, b"{}")
            for name in mod.PROBES:
                write(stage / "probes" / name, b"#!/bin/sh\nexit 1\n", 0o700)
            installed = stage / "installed"
            installed.mkdir()
            write(installed / "runtime.bin", b"old-runtime")
            pkg = base / "signed-update.zip"
            pkg_sha = write(pkg, b"signed-test-bytes")
            delivery = base / "delivery.json"
            delivery_sha = write(delivery, b"delivery-test-bytes")
            self.config["projects"].append({"referenceClass": cls, "runId": run,
                 "projectId": f"project_{i:09}", "sourceZip": str(source), "sourceSha256": source_sha,
                 "mapping": str(mp), "mappingSha256": mapping_sha,
                 "dryRunReport": str(report), "dryRunReportSha256": report_sha,
                 "inventorySha256": inv, "stage": str(stage), "installRoot": str(installed),
                 "installedComponent": "runtime.bin", "updatePackage": str(pkg),
                 "updateSha256": pkg_sha, "deliveryManifest": str(delivery),
                 "deliverySha256": delivery_sha, "expectedUpdatedVersion": "0.49.11"})
        self.config_file = self.root / "config.json"
        self.write_config()

    def write_config(self):
        write(self.config_file, json.dumps(self.config).encode())

    def validate(self):
        with patch.dict(os.environ, {"LAUNCHER_TOKEN": "test-secret"}):
            return mod.preflight(self.config, self.out)

    def test_three_unique_projects_are_preflighted_without_running_anything(self):
        self.assertEqual(len(self.validate()), 3)
        with patch.dict(os.environ, {"LAUNCHER_TOKEN": "test-secret"}), patch.object(mod, "cli", side_effect=AssertionError("Не должно выполняться")):
            self.assertEqual(mod.main(["--config", str(self.config_file), "--output-dir", str(self.out), "--preflight-only"]), 0)

    def test_duplicate_source_is_blocked(self):
        self.config["projects"][1]["sourceSha256"] = self.config["projects"][0]["sourceSha256"]
        with self.assertRaises(mod.Blocked):
            self.validate()

    def test_stale_source_bytes_rejected(self):
        with open(self.config["projects"][0]["sourceZip"], "ab") as f:
            f.write(b"tamper")
        with self.assertRaises(mod.Blocked):
            self.validate()

    def test_symlinked_staging_probe_rejected(self):
        probe = Path(self.config["projects"][0]["stage"]) / "probes" / "join"
        probe.unlink()
        probe.symlink_to(self.launcher)
        with self.assertRaises(mod.Blocked):
            self.validate()

    def test_weak_backend_and_output_permissions_rejected(self):
        self.config["backend"] = "http://public.example.com"
        with self.assertRaises(mod.Blocked):
            self.validate()
        self.config["backend"] = "https://localhost"
        self.out.chmod(0o755)
        with self.assertRaises(mod.Blocked):
            self.validate()

    def test_no_false_positive_from_failed_minecraft_join(self):
        p = self.config["projects"][0]
        doc = {"runId": p["runId"], "sourceInventorySha256": p["inventorySha256"],
               "cutoverAllowed": False, "ready": True, "blockers": [],
               "liveSession": {"clientSha256": H, "joinedAt": "2026-11-02T00:00:00Z", "playerUuid": UUID},
               "probes": [{"name": name, "passed": name != "join", "evidenceSha256": H} for name in mod.PROBES]}
        path = self.root / "live.json"
        write(path, json.dumps({"data": doc}).encode())
        with self.assertRaises(mod.Blocked):
            mod.verify_rehearsal(path, p, authoritative=True)
        doc["probes"][2]["passed"] = True
        write(path, json.dumps({"data": doc}).encode())
        self.assertTrue(mod.verify_rehearsal(path, p, authoritative=True)["ready"])
        with self.assertRaises(mod.Blocked):
            mod.verify_rehearsal(path, p, authoritative=False)
        doc["ready"] = False
        doc["blockers"] = ["pending server-side authoritative verification"]
        write(path, json.dumps({"data": doc}).encode())
        self.assertFalse(mod.verify_rehearsal(path, p, authoritative=False)["ready"])

    def test_private_non_overwriting_output(self):
        path = self.out / "receipt.json"
        mod.save_private(path, {"status": "BLOCKED"})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            mod.save_private(path, {"status": "PASS"})

    def test_cli_does_not_include_secret_in_arguments(self):
        p = self.config["projects"][0]
        self.assertNotIn("test-secret", json.dumps(p))
        with patch.dict(os.environ, {"LAUNCHER_TOKEN": "super-secret"}):
            mod.cli(str(self.launcher), ["version"], 5)

    def test_orchestration_refuses_stale_updater_and_old_client(self):
        p = self.config["projects"][0]
        old_sha = mod.sha(Path(p["installRoot"]) / p["installedComponent"])
        new_sha = hashlib.sha256(b"new-runtime").hexdigest()
        calls = []

        def fake_cli(_launcher, args, _timeout=1800):
            calls.append(args)
            dest = Path(args[args.index("--output") + 1])
            if "pre-update-live" in dest.name or "post-update-live" in dest.name:
                is_new = "post-update-live" in dest.name
                r = {"runId": p["runId"], "sourceInventorySha256": p["inventorySha256"],
                     "cutoverAllowed": False, "ready": not is_new,
                     "sourceSnapshotSha256": H, "targetSnapshotSha256": H,
                     "blockers": ["pending verification"] if is_new else [],
                     "liveSession": {"clientSha256": new_sha if is_new else old_sha,
                                     "joinedAt": "2026-11-02T18:00:00Z", "playerUuid": UUID},
                     "probes": [{"name": name, "passed": True, "evidenceSha256": H} for name in mod.PROBES]}
                write(dest, json.dumps({"data": r}).encode())
            elif "signed-update" in dest.name:
                component = Path(p["installRoot"]) / p["installedComponent"]
                component.write_bytes(b"new-runtime")
                write(dest, json.dumps({"status": "committed", "toVersion": p["expectedUpdatedVersion"],
                                        "packageSha256": p["updateSha256"]}).encode())
            else:
                write(dest, b"{}")

        case_root = self.out / p["referenceClass"]
        with patch.object(mod, "cli", side_effect=fake_cli):
            result = mod.execute_project(str(self.launcher), self.config["backend"], p, self.out)
        self.assertEqual(result["status"], "isolated-stage-import-launch-update-join-passed")
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[3][:2], ["update", "components"])
        self.assertEqual(result["installedAfterSha256"], new_sha)
        self.assertTrue((case_root / "post-update-live.json").exists())
        self.assertFalse((self.out / "cohort-04910.json").exists(), "Оператор не сертифицировал группу")

    def test_post_update_witness_must_bind_to_updated_binary(self):
        p = self.config["projects"][0]
        old_sha = mod.sha(Path(p["installRoot"]) / p["installedComponent"])
        def stale_client(_launcher, args, _timeout=1800):
            target = Path(args[args.index("--output") + 1])
            if target.name in ("pre-update-live.json", "post-update-live.json"):
                after = target.name.startswith("post-")
                d = {"runId": p["runId"], "sourceInventorySha256": p["inventorySha256"],
                     "cutoverAllowed": False, "ready": not after,
                     "sourceSnapshotSha256": H, "targetSnapshotSha256": H,
                     "blockers": ["local only"] if after else [],
                     "liveSession": {"clientSha256": old_sha, "joinedAt": "2026-11-02T18:00:00Z", "playerUuid": UUID},
                     "probes": [{"name": n, "passed": True, "evidenceSha256": H} for n in mod.PROBES]}
                write(target, json.dumps({"data": d}).encode())
            elif target.name == "signed-update.json":
                (Path(p["installRoot"]) / p["installedComponent"]).write_bytes(b"new-runtime")
                write(target, json.dumps({"status": "committed", "toVersion": p["expectedUpdatedVersion"],
                                          "packageSha256": p["updateSha256"]}).encode())
            else:
                write(target, b"{}")
        with patch.object(mod, "cli", side_effect=stale_client):
            with self.assertRaisesRegex(mod.Blocked, "upgraded executable"):
                mod.execute_project(str(self.launcher), self.config["backend"], p, self.out)

    def test_no_output_when_prerequisites_missing(self):
        self.config["projects"][2]["stage"] = str(self.root / "nonexistent")
        self.write_config()
        with patch.dict(os.environ, {"LAUNCHER_TOKEN": "test-secret"}):
            self.assertEqual(mod.main(["--config", str(self.config_file), "--output-dir", str(self.out)]), 1)
        self.assertFalse((self.out / "cohort-04910.json").exists())


if __name__ == "__main__":
    unittest.main()
