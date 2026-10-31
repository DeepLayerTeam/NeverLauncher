"""Production GA security verifier regression. Synthetic FIXTURES are never GA receipts."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_verified_targets import VersionIndependentGATests
from test_verified_targets_0360 import COMMIT, NOW, timevalue
from verified_targets import (Blocked, paths, verify,
                              PLAYER_CHECKS_0400, PLAYER_OBSERVATIONS_0400)
from security_capabilities_0431 import (SCENARIOS, SCHEMA, LOG_SCHEMA, expected_scope, verify_all)
from release_policy import policy
from package_security_0431 import package, evidence_files
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from publish_0370 import verify_security_archive


class SecurityGATests(unittest.TestCase):
    def setUp(self):
        self.parent = VersionIndependentGATests("test_v2_verified_receipt_is_version_bound")
        self.parent.setUp()
        self.addCleanup(self.parent.tmp.cleanup)
        self.env = patch.dict(os.environ, {"GITHUB_RUN_ID": "401234", "GITHUB_RUN_ATTEMPT": "2"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.approval = self.parent.approval
        self.evidence = self.parent.evidence
        self.bundle = self.parent.bundle
        self.approval["version"] = "0.43.1"
        self.approval["issuedAtUtc"] = timevalue(NOW - timedelta(minutes=5))
        self.make_security_reports()

    def make_security_reports(self):
        for row in self.approval["targets"]:
            target = row["target"]
            source_bin, old_pkg = paths("0.36.1", target)
            _, new_pkg = paths("0.43.1", target)
            (self.bundle / old_pkg).rename(self.bundle / new_pkg)
            for check in list(row["checks"]):
                p = self.evidence / "targets" / target / (check + ".json")
                trace = json.loads(p.read_text())
                trace["version"] = "0.43.1"
                raw = json.dumps(trace, sort_keys=True).encode()
                p.write_bytes(raw)
                row["checks"][check]["sha256"] = hashlib.sha256(raw).hexdigest()
            player_dir = self.evidence / "targets" / target / "player-0400"
            player_dir.mkdir()
            for player_check in PLAYER_CHECKS_0400:
                log = ("observed actual fixture " + player_check + " " + target).encode()
                (player_dir / (player_check + ".log")).write_bytes(log)
                report = {
                    "schemaVersion": "launcher.player.final.0400.v1",
                    "version": "0.43.1", "commit": COMMIT,
                    "target": target, "kind": player_check, "status": "passed",
                    "playerCycleId": "real-cycle-0400-" + target,
                    "binarySha256": row["binarySha256"],
                    "packageSha256": row["packageSha256"],
                    "observed": {name: True for name in PLAYER_OBSERVATIONS_0400[player_check]},
                    "runtimeLogSha256": hashlib.sha256(log).hexdigest(),
                }
                raw = json.dumps(report, sort_keys=True).encode()
                (player_dir / (player_check + ".json")).write_bytes(raw)
                trace = {
                    "schemaVersion": policy("0.43.1").execution_schema,
                    "version": "0.43.1", "commit": COMMIT,
                    "target": target, "kind": player_check, "status": "passed",
                    "actualExecution": True, "simulated": False,
                    "artifactSha256": row["binarySha256"],
                    "executionId": "native-execution-431-" + target,
                    "packageSha256": row["packageSha256"],
                    "playerCycleId": "real-cycle-0400-" + target,
                    "evidenceSha256": hashlib.sha256(raw).hexdigest(),
                }
                self.update_trace(target, player_check, trace, sign=False)
            directory = self.evidence / "targets" / target / "security-0431"
            directory.mkdir()
            for check, (positive, negative) in SCENARIOS.items():
                correlation = "native-execution-431-" + target
                events = []
                for name, decision in ((positive, "allowed"), (negative, "denied")):
                    events.append({
                        "schemaVersion": LOG_SCHEMA,
                        "executionId": correlation,
                        "runId": "401234", "runAttempt": 2,
                        "target": target,
                        "packageSha256": row["packageSha256"],
                        "scenario": name, "observedDecision": decision,
                        "observedAtUtc": timevalue(NOW - timedelta(minutes=10)),
                        "actualExecution": True, "simulated": False,
                    })
                log = ("\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n").encode()
                (directory / (check + ".jsonl")).write_bytes(log)
                report = {
                    "schemaVersion": SCHEMA, "version": "0.43.1", "commit": COMMIT,
                    "target": target, "kind": check, "status": "passed",
                    "actualExecution": True, "simulated": False,
                    "artifactSha256": row["binarySha256"],
                    "packageSha256": row["packageSha256"],
                    "executionId": correlation,
                    "runId": "401234", "runAttempt": 2,
                    "scope": expected_scope(check),
                    "observedAtUtc": timevalue(NOW - timedelta(minutes=10)),
                    "runtimeLogSha256": hashlib.sha256(log).hexdigest(),
                    "scenarios": {positive: "allowed", negative: "denied"},
                }
                self.update_trace(target, check, report, sign=False)
        self.sign()

    def sign(self):
        self.parent.sign()

    def update_trace(self, target, check, payload, *, sign=True):
        path = self.evidence / "targets" / target / (check + ".json")
        raw = json.dumps(payload, sort_keys=True).encode()
        path.write_bytes(raw)
        row = next(row for row in self.approval["targets"] if row["target"] == target)
        row["checks"][check] = {"sha256": hashlib.sha256(raw).hexdigest()}
        if sign:
            self.sign()

    def trace(self, target="linux-x64", check="securityDeviceTrust"):
        return json.loads((self.evidence / "targets" / target / (check + ".json")).read_text())

    def check(self):
        return verify(self.bundle, self.evidence, self.parent.keyfile, "0.43.1", COMMIT, now=NOW)

    def test_real_gate_adds_six_independently_verified_capabilities_per_target(self):
        receipt = self.check()
        self.assertEqual(len(receipt["targets"]), 6)
        for row in receipt["targets"]:
            self.assertEqual(row["securityCapabilitiesVerified"], list(SCENARIOS))
            self.assertEqual(row["checksPassed"], 21)

    def test_signed_preflight_refuses_incomplete_security(self):
        self.approval["targets"][0]["checks"].pop("securityNeverGuard")
        self.sign()
        with self.assertRaisesRegex(ValueError, "missing mandatory security"):
            verify_all(self.evidence, self.approval, now=NOW)

    def test_denied_scenario_does_not_mean_success_without_observed_deny(self):
        trace = self.trace()
        trace["scenarios"]["staleDeviceEpochDenied"] = "allowed"
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        with self.assertRaisesRegex(ValueError, "positive and negative"):
            self.check()

    def test_signed_claim_without_immutable_raw_log_is_denied(self):
        path = self.evidence / "targets/linux-x64/security-0431/securityDeviceTrust.jsonl"
        path.write_bytes(b'claimed PASSED without actual run')
        with self.assertRaisesRegex(ValueError, "altered security observation log"):
            self.check()

    def test_replaced_log_with_matching_hash_but_missing_negative_event_is_denied(self):
        path = self.evidence / "targets/linux-x64/security-0431/securityDeviceTrust.jsonl"
        data = path.read_bytes().splitlines()
        path.write_bytes(data[0] + b"\n")
        trace = self.trace()
        trace["runtimeLogSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        with self.assertRaisesRegex(ValueError, "missing or extra native observations"):
            self.check()

    def test_foreign_run_or_attempt_denied(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "3"}):
            with self.assertRaisesRegex(ValueError, "runAttempt"):
                self.check()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "401235"}):
            with self.assertRaisesRegex(ValueError, "runId"):
                self.check()

    def test_wrong_architecture_and_foreign_package_denied(self):
        trace = self.trace()
        trace["target"] = "linux-arm64"
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        with self.assertRaisesRegex(ValueError, "target"):
            self.check()
        trace["target"] = "linux-x64"
        trace["packageSha256"] = "f" * 64
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        with self.assertRaisesRegex(ValueError, "packageSha256"):
            self.check()

    def test_status_skip_blocked_or_simulated_never_certifies(self):
        for field, value in (("status", "skipped"), ("status", "blocked"), ("simulated", True), ("actualExecution", False)):
            with self.subTest(field=field, value=value):
                trace = self.trace()
                original = trace[field]
                trace[field] = value
                self.update_trace("linux-x64", "securityDeviceTrust", trace)
                with self.assertRaisesRegex(ValueError, "invalid " + field):
                    self.check()
                trace[field] = original
                self.update_trace("linux-x64", "securityDeviceTrust", trace)

    def test_wrong_host_scope_denied(self):
        trace = self.trace("darwin-arm64", "securityNativeSandbox")
        trace["scope"] = "client"
        self.update_trace("darwin-arm64", "securityNativeSandbox", trace)
        with self.assertRaisesRegex(ValueError, "scope"):
            self.check()

    def test_final_package_mutation_denied(self):
        _, package = paths("0.43.1", "windows-arm64")
        (self.bundle / package).write_bytes(b"different final package")
        with self.assertRaises(Blocked):
            self.check()

    def test_old_version_cannot_reuse_signed_0431_evidence(self):
        with self.assertRaises(Blocked):
            verify(self.bundle, self.evidence, self.parent.keyfile, "0.43.2", COMMIT, now=NOW)

    def test_security_report_replay_or_old_time_denied(self):
        trace = self.trace()
        trace["observedAtUtc"] = timevalue(NOW - timedelta(days=2))
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        with self.assertRaisesRegex(ValueError, "stale, future"):
            self.check()

    def test_missing_security_evidence_from_other_platform_denied(self):
        (self.evidence / "targets/windows-arm64/securityNeverGuard.json").unlink()
        with self.assertRaises((OSError, ValueError)):
            self.check()

    def test_no_ci_run_context_no_certification(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "GITHUB_RUN_ID"):
                self.check()

    def test_archive_is_real_verifiable_release_asset(self):
        destination = self.bundle / "SECURITY_CAPABILITY_EVIDENCE_0431.zip"
        package(self.evidence, self.approval, destination, now=NOW)
        with ZipFile(destination) as signed_input:
            self.assertEqual(set(signed_input.namelist()), set(evidence_files()))
        verify_security_archive(self.bundle, self.approval, 401234, 2, now=NOW)
        with self.assertRaisesRegex(ValueError, "runAttempt"):
            verify_security_archive(self.bundle, self.approval, 401234, 3, now=NOW)
        destination.write_bytes(b"not a real ZIP")
        with self.assertRaises(Exception):
            verify_security_archive(self.bundle, self.approval, 401234, 2, now=NOW)

    def test_security_evidence_bundle_missing_or_altered_denied(self):
        destination = self.bundle / "SECURITY_CAPABILITY_EVIDENCE_0431.zip"
        with self.assertRaisesRegex(ValueError, "missing/unsafe"):
            verify_security_archive(self.bundle, self.approval, 401234, 2, now=NOW)
        path = self.evidence / "targets/linux-arm64/security-0431/securityNeverGuard.jsonl"
        path.write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "altered security observation"):
            package(self.evidence, self.approval, destination, now=NOW)
        self.assertFalse(destination.exists())

    def test_hash_conflict_after_resigning_fails(self):
        trace = self.trace()
        trace["scenarios"]["staleDeviceEpochDenied"] = "denied"
        self.update_trace("linux-x64", "securityDeviceTrust", trace)
        p = self.evidence / "targets/linux-x64/securityDeviceTrust.json"
        p.write_text(p.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "signed security capability report changed"):
            self.check()


if __name__ == "__main__":
    unittest.main()
