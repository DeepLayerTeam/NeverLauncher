"""Exercise the production, independently signed final-package player gate.

These temporary signed fixtures verify rejection behavior only. They are not
player certifications and must never be packaged as release evidence.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_verified_targets_0360 import TargetGateTests, COMMIT, NOW, digest
from verified_targets import (
    Blocked,
    CHECKS,
    PLAYER_CHECKS_0400,
    PLAYER_OBSERVATIONS_0400,
    TARGETS,
    checks_for,
    paths,
    verify,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import policy

VERSION = "0.40.0"


class FinalPlayerReleaseTests(unittest.TestCase):
    def setUp(self):
        historical = TargetGateTests("test_real_signature_and_exact_bytes")
        historical.setUp()
        self.addCleanup(historical.doCleanups)
        self.historical = historical
        self.bundle = historical.bundle
        self.evidence = historical.evidence
        self.keyfile = historical.keyfile
        self.private = historical.private
        self.approval = historical.approval
        cfg = policy(VERSION)
        self.approval["schemaVersion"] = cfg.approval_schema
        self.approval["version"] = VERSION
        for row in self.approval["targets"]:
            target = row["target"]
            _, old_package = paths("0.36.0", target)
            _, new_package = paths(VERSION, target)
            (self.bundle / old_package).rename(self.bundle / new_package)
            traces = self.evidence / "targets" / target
            for check in CHECKS:
                path = traces / (check + ".json")
                trace = json.loads(path.read_text())
                trace.update(schemaVersion=cfg.execution_schema, version=VERSION)
                self.write_trace(row, path, check, trace)
            for check in PLAYER_CHECKS_0400:
                player_dir = traces / "player-0400"
                player_dir.mkdir(exist_ok=True)
                log = player_dir / (check + ".log")
                log.write_bytes(
                    ("synthetic fixture only: " + target + ":" + check + "\n").encode()
                )
                actual = {
                    "schemaVersion": "launcher.player.final.0400.v1",
                    "version": VERSION,
                    "commit": COMMIT,
                    "target": target,
                    "kind": check,
                    "status": "passed",
                    "playerCycleId": "final-player-cycle-0400-" + target,
                    "binarySha256": row["binarySha256"],
                    "packageSha256": row["packageSha256"],
                    "observed": {
                        name: True for name in PLAYER_OBSERVATIONS_0400[check]
                    },
                    "runtimeLogSha256": digest(log.read_bytes()),
                }
                result_file = player_dir / (check + ".json")
                result_file.write_text(json.dumps(actual, sort_keys=True))
                trace = {
                    "schemaVersion": cfg.execution_schema,
                    "version": VERSION,
                    "commit": COMMIT,
                    "target": target,
                    "kind": check,
                    "status": "passed",
                    "actualExecution": True,
                    "simulated": False,
                    "artifactSha256": row["binarySha256"],
                    "executionId": "protected-player-0400",
                    "packageSha256": row["packageSha256"],
                    "playerCycleId": "final-player-cycle-0400-" + target,
                    "evidenceSha256": digest(result_file.read_bytes()),
                }
                self.write_trace(row, traces / (check + ".json"), check, trace)
        self.sign()

    def write_trace(self, row, path, check, trace):
        raw = json.dumps(trace, sort_keys=True).encode()
        path.write_bytes(raw)
        row["checks"][check] = {"sha256": digest(raw)}

    def sign(self):
        cfg = policy(VERSION)
        raw = json.dumps(self.approval, sort_keys=True, separators=(",", ":")).encode()
        (self.evidence / "approval.json").write_bytes(raw)
        (self.evidence / "approval.sig").write_text(
            self.private.sign(cfg.signing_domain + raw).hex()
        )

    def check(self):
        return verify(
            self.bundle, self.evidence, self.keyfile, VERSION, COMMIT, now=NOW
        )

    def modify(self, target, check, **kwargs):
        row = next(row for row in self.approval["targets"] if row["target"] == target)
        path = self.evidence / "targets" / target / (check + ".json")
        trace = json.loads(path.read_text())
        trace.update(kwargs)
        self.write_trace(row, path, check, trace)
        self.sign()

    def test_current_final_six_target_signed_package_and_player_checks(self):
        result = self.check()
        self.assertEqual(result["status"], "approved-for-release-signing")
        self.assertEqual([row["checksPassed"] for row in result["targets"]], [15] * 6)
        self.assertEqual(checks_for("0.39.8"), CHECKS)
        self.assertEqual(len(checks_for("0.40.0")), 15)
        self.assertEqual(len(checks_for("1.0.0")), 15)

    def test_missing_local_or_official_live_execution_blocks_ga(self):
        for check in ("officialOnlineModeJoin", "localYggdrasilJoin"):
            with self.subTest(check=check):
                target = "linux-x64"
                row = next(r for r in self.approval["targets"] if r["target"] == target)
                prior = row["checks"].pop(check)
                self.sign()
                with self.assertRaises(Blocked):
                    self.check()
                row["checks"][check] = prior
                self.sign()

    def test_legacy_nine_checks_do_not_certify_0400(self):
        for row in self.approval["targets"]:
            for check in PLAYER_CHECKS_0400:
                row["checks"].pop(check)
        self.sign()
        with self.assertRaises(Blocked):
            self.check()

    def test_unsigned_player_log_rejected(self):
        path = (
            self.evidence / "targets/linux-x64/player-0400/officialOnlineModeJoin.log"
        )
        path.write_text("someone replaced the real network log")
        with self.assertRaises(Blocked):
            self.check()

    def test_missing_signed_player_evidence_rejected(self):
        path = self.evidence / "targets/windows-x64/player-0400/skinCapeGameRender.json"
        path.unlink()
        with self.assertRaises((Blocked, OSError)):
            self.check()

    def test_misreported_live_observation_rejected(self):
        target = "linux-x64"
        check = "localYggdrasilJoin"
        row = next(r for r in self.approval["targets"] if r["target"] == target)
        evidence = (
            self.evidence / "targets" / target / "player-0400" / (check + ".json")
        )
        report = json.loads(evidence.read_text())
        report["observed"]["serverUUIDMatches"] = False
        evidence.write_text(json.dumps(report, sort_keys=True))
        trace = self.evidence / "targets" / target / (check + ".json")
        payload = json.loads(trace.read_text())
        payload["evidenceSha256"] = digest(evidence.read_bytes())
        self.write_trace(row, trace, check, payload)
        self.sign()
        with self.assertRaises(Blocked):
            self.check()

    def test_missing_native_real_execution_blocks(self):
        self.modify("windows-arm64", "componentPresetInstall", actualExecution=False)
        with self.assertRaises(Blocked):
            self.check()

    def test_wrong_signed_package_identity_blocks(self):
        self.modify("darwin-arm64", "officialOnlineModeJoin", packageSha256="f" * 64)
        with self.assertRaises(Blocked):
            self.check()

    def test_unrelated_player_cycles_cannot_be_combined(self):
        self.modify(
            "linux-arm64",
            "identityNegativeAndReplay",
            playerCycleId="other-player-session-0400",
        )
        with self.assertRaises(Blocked):
            self.check()

    def test_reused_foreign_platform_player_evidence_denied(self):
        foreign = next(
            r for r in self.approval["targets"] if r["target"] == "linux-arm64"
        )
        self.modify(
            "linux-x64", "skinCapeGameRender", packageSha256=foreign["packageSha256"]
        )
        with self.assertRaises(Blocked):
            self.check()

    def test_unbound_player_proof_or_unknown_fields_denied(self):
        self.modify("darwin-x64", "playerUpdateRollback", evidenceSha256="not-a-digest")
        with self.assertRaises(Blocked):
            self.check()
        self.modify(
            "darwin-x64",
            "playerUpdateRollback",
            evidenceSha256="a" * 64,
            skipRequired=True,
        )
        with self.assertRaises(Blocked):
            self.check()

    def test_unsigned_trace_replacement_denied(self):
        path = self.evidence / "targets/windows-x64/officialOnlineModeJoin.json"
        trace = json.loads(path.read_text())
        trace["status"] = "failed"
        path.write_text(json.dumps(trace))
        with self.assertRaises(Blocked):
            self.check()

    def test_tampered_final_desktop_package_denied(self):
        _, package = paths(VERSION, "linux-x64")
        (self.bundle / package).write_bytes(b"wrong installed package")
        with self.assertRaises(Blocked):
            self.check()


if __name__ == "__main__":
    unittest.main()
