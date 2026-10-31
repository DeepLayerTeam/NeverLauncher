#!/usr/bin/env python3
"""Unit tests for fail-closed interpretation; NOT a real Minecraft E2E."""

import json
from pathlib import Path
import tempfile
import unittest

from verify_server_control_0290 import verify

SHA = "a" * 40
VERSION = "0.29.0"


class RealGameEvidenceValidation(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)
        self.result = {
            "version": VERSION,
            "status": "passed",
            "mode": "full",
            "minecraft": {"client": "actual-mojang-client", "paperJoin": "passed"},
            "checks": {
                name: True
                for name in (
                    "signedManifest",
                    "cleanSync",
                    "actualClient",
                    "paperJoin",
                    "sessionRevokeDeny",
                    "bukkitFamilyRuntime",
                    "proxyFamilyRuntime",
                    "realWorldBackupRestore",
                )
            },
            "evidence": ["world-backup-0290.json"],
        }
        self.proof = {
            "schemaVersion": "launcher.server-control.real-world-restore.v1",
            "version": VERSION,
            "sourceCommit": SHA,
            "status": "passed",
            "source": "docker-compose-real-paper-after-minecraft-client-join",
            "actualMinecraftWorld": True,
            "gracefulPaperExit": True,
            "minecraftSaveFlushAcknowledged": True,
            "worldBackupVerified": True,
            "isolatedRestoreVerified": True,
            "overwriteRejected": True,
            "returnedToHealthyService": True,
            "worldFileSha256": "c" * 64,
            "playerDataFiles": 1,
            "pluginDataFiles": 1,
            "filesVerified": 3,
        }
        self.write("result.json", self.result)
        self.write("world-backup-0290.json", self.proof)
        self.write(
            "join-paper-real-client-fresh.json",
            {"data": {"oneTime": True, "ticketVersion": 2}},
        )
        self.write("validate-paper-e2e-p3-deny.json", {"data": {"allowed": False}})
        self.write(
            "handoff-velocity-paper.json",
            {"data": {"oneTime": True, "status": "handoff-created"}},
        )

    def write(self, name, value):
        (self.dir / name).write_text(json.dumps(value))

    def test_complete_sample_shape_only(self):
        self.assertEqual(verify(self.dir, VERSION, SHA)["status"], "verified")

    def test_missing_persisted_world_denied(self):
        self.proof["playerDataFiles"] = 0
        self.write("world-backup-0290.json", self.proof)
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_wrong_commit_denied(self):
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, "b" * 40)

    def test_false_graceful_stop_denied(self):
        self.proof["minecraftSaveFlushAcknowledged"] = False
        self.write("world-backup-0290.json", self.proof)
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_unhealthy_recovery_denied(self):
        self.proof["returnedToHealthyService"] = False
        self.write("world-backup-0290.json", self.proof)
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_failed_replay_denied(self):
        self.write("validate-paper-e2e-p3-deny.json", {"data": {"allowed": True}})
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_false_handoff_denied(self):
        self.write("handoff-velocity-paper.json", {"data": {"oneTime": False}})
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_duplicate_evidence_keys_denied(self):
        (self.dir / "world-backup-0290.json").write_text(
            '{"status":"passed","status":"failed"}'
        )
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_symlink_evidence_denied(self):
        (self.dir / "world-backup-0290.json").unlink()
        (self.dir / "world-backup-0290.json").symlink_to(self.dir / "result.json")
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)

    def test_not_full_actual_e2e_denied(self):
        self.result["mode"] = "compatibility"
        self.write("result.json", self.result)
        with self.assertRaises(ValueError):
            verify(self.dir, VERSION, SHA)


if __name__ == "__main__":
    unittest.main()
