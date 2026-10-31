#!/usr/bin/env python3
"""Production publication acceptance: real Ed25519 fixture and remote-byte failures.

The native package fixtures are deliberately synthetic; this suite does not
attest that the actual platforms or GitHub production runners have passed.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_0370 as p
from required_jobs_0363 import declared_jobs
import test_rehearsal_0365 as base
from verified_targets import Blocked

VERSION = "0.37.0"
COMMIT = "a" * 40


class PublicationAcceptance(unittest.TestCase):
    def setUp(self):
        env_patch = patch.dict(os.environ, {"GH_TOKEN": "unit-test-token"})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.fixture = base.RehearsalTests(
            "test_valid_six_signed_targets_and_package_payloads"
        )
        version_patch = patch.object(base, "VER", VERSION)
        version_patch.start()
        self.addCleanup(version_patch.stop)
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.bundle = f.bundle
        f.sign()
        receipt = base.r.verify(f.bundle, f.evidence, f.key, VERSION, COMMIT)
        rehearsal = base.r.certify(f.bundle, f.evidence, f.key, VERSION, COMMIT)
        (f.bundle / p.RECEIPT).write_text(json.dumps(receipt))
        (f.bundle / p.REHEARSAL).write_text(json.dumps(rehearsal))
        shutil.copyfile(
            f.evidence / "approval.json", f.bundle / "GA_TARGET_APPROVAL.json"
        )
        shutil.copyfile(
            f.evidence / "approval.sig", f.bundle / "GA_TARGET_APPROVAL.sig"
        )
        (f.bundle / "RELEASE_MANIFEST.json").write_text(
            json.dumps({"version": VERSION, "sourceCommit": COMMIT})
        )
        (f.bundle / "PROVENANCE.json").write_text('{"status":"built"}')
        (f.bundle / "SBOM.spdx.json").write_text('{"spdxVersion":"SPDX-2.3"}')
        (f.bundle / "RELEASE_NOTES.txt").write_text("real release identity test")
        self.cli = f.bundle / "launcher-cli-linux-x64"
        self.cli.write_text("#!/bin/sh\nexit 0\n")
        self.cli.chmod(0o755)
        sums = []
        for file in sorted(f.bundle.iterdir()):
            sums.append(p.sha(file) + "  " + file.name)
        (f.bundle / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        (f.bundle / "SHA256SUMS.sig").write_text("signature-fixture")
        self.ci = Path(f.tmp.name) / "CI.json"
        self.dry = Path(f.tmp.name) / "DRY.json"
        self.release_key = Path(f.tmp.name) / "release-key"
        self.trust_policy = Path(f.tmp.name) / "trust-policy"
        self.trust_state = Path(f.tmp.name) / "trust-state"
        self.release_key.write_text("test public key")
        self.trust_policy.write_text('{"schemaVersion":"test"}')
        self.cireport = {
            "schemaVersion": 1,
            "status": "passed",
            "gateJob": "required-production-ci",
            "productVersion": VERSION,
            "sourceCommit": COMMIT,
            "runId": 7654321,
            "runAttempt": 1,
            "missingJobs": [],
            "unexpectedJobs": [],
            "nonSuccessJobs": {},
            "jobResults": {
                name: "success"
                for name in declared_jobs(str(p.PRODUCTION_WORKFLOW))
                - {"required-production-ci", "publish-release"}
            },
        }
        self.ci.write_text(json.dumps(self.cireport))
        self.dryreport = {
            "schemaVersion": p.DRYRUN_SCHEMA,
            "status": "passed",
            "published": False,
            "version": VERSION,
            "commit": COMMIT,
            "runId": "7654321",
            "runAttempt": "1",
            "filesCopied": len(list(f.bundle.iterdir())),
            "sha256sumsSha256": p.sha(f.bundle / "SHA256SUMS"),
            "gaApprovalSha256": receipt["approvalSha256"],
        }
        self.dry.write_text(json.dumps(self.dryreport))

    def check(self):
        with patch.object(p, "run", return_value=""):
            return p.validate(
                bundle=self.bundle,
                ci=self.ci,
                dryrun=self.dry,
                version=VERSION,
                commit=COMMIT,
                run_id=7654321,
                attempt=1,
                ga_key=self.fixture.key,
                release_key=self.release_key,
                trust_policy=self.trust_policy,
                cli=self.cli,
                trust_state=self.trust_state,
            )

    def test_current_signed_six_target_release_is_accepted(self):
        result = self.check()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["files"]), len(list(self.bundle.iterdir())))

    def test_historical_report_rejected_same_sha(self):
        self.cireport["runId"] = 7654320
        self.ci.write_text(json.dumps(self.cireport))
        with self.assertRaises(Blocked):
            self.check()

    def test_skipped_required_job_rejected(self):
        self.cireport["jobResults"]["release-bundle"] = "skipped"
        self.ci.write_text(json.dumps(self.cireport))
        with self.assertRaises(Blocked):
            self.check()

    def test_missing_required_job_rejected(self):
        self.cireport["jobResults"].pop("release-bundle")
        self.ci.write_text(json.dumps(self.cireport))
        with self.assertRaises(Blocked):
            self.check()

    def test_old_dryrun_rejected(self):
        self.dryreport["runAttempt"] = "2"
        self.dry.write_text(json.dumps(self.dryreport))
        with self.assertRaises(Blocked):
            self.check()

    def test_dryrun_wrong_checksum_rejected(self):
        self.dryreport["sha256sumsSha256"] = "0" * 64
        self.dry.write_text(json.dumps(self.dryreport))
        with self.assertRaises(Blocked):
            self.check()

    def test_tampered_package_rejected(self):
        name = "launcher-desktop-" + VERSION + "-windows-x64.zip"
        (self.bundle / name).write_bytes(b"altered")
        with self.assertRaises(Blocked):
            self.check()

    def test_extra_unsigned_asset_rejected(self):
        (self.bundle / "foreign-arch.zip").write_bytes(b"bad")
        with self.assertRaises(Blocked):
            self.check()

    def test_missing_ga_signature_rejected(self):
        (self.bundle / "GA_TARGET_APPROVAL.sig").unlink()
        with self.assertRaises(Blocked):
            self.check()

    def test_reused_signature_from_different_version_rejected(self):
        self.fixture.approval["version"] = "0.36.5"
        self.fixture.sign()
        (self.bundle / "GA_TARGET_APPROVAL.json").write_bytes(
            (self.fixture.evidence / "approval.json").read_bytes()
        )
        (self.bundle / "GA_TARGET_APPROVAL.sig").write_bytes(
            (self.fixture.evidence / "approval.sig").read_bytes()
        )
        # Recomputed public checksum is not enough to forge independent approval.
        (self.bundle / "SHA256SUMS").write_text(
            "\n".join(
                p.sha(x) + "  " + x.name
                for x in sorted(self.bundle.iterdir())
                if x.name not in ("SHA256SUMS", "SHA256SUMS.sig")
            )
            + "\n"
        )
        with self.assertRaises(Blocked):
            self.check()

    def test_publish_only_after_full_remote_roundtrip(self):
        verified = self.check()
        commands = []

        def fake_run(args, **kw):
            commands.append(args)
            if args[:3] == ["gh", "release", "download"]:
                dest = Path(args[args.index("--dir") + 1])
                for name in verified["files"]:
                    shutil.copyfile(self.bundle / name, dest / name)
            if args[:3] == ["gh", "release", "view"]:
                if "tagName,isDraft,targetCommitish,assets" in args:
                    return json.dumps(
                        {
                            "tagName": "v" + VERSION,
                            "isDraft": True,
                            "targetCommitish": COMMIT,
                            "assets": [{"name": name} for name in verified["files"]],
                        }
                    )
                return json.dumps({"tagName": "v" + VERSION, "isDraft": False})
            return ""

        from subprocess import CompletedProcess

        absent = CompletedProcess([], 1, stdout="", stderr="HTTP 404: Not Found")
        with (
            patch.object(p, "run", side_effect=fake_run),
            patch.object(p.subprocess, "run", return_value=absent),
        ):
            result = p.publish("DeepLayerTeam/Launcher", verified, self.bundle)
        self.assertEqual(result["status"], "published")
        self.assertTrue(result["verifiedRemoteBytes"])
        self.assertEqual(commands[-1][:3], ["gh", "release", "view"])
        self.assertTrue(any(x[:3] == ["gh", "release", "edit"] for x in commands))

    def test_remote_tamper_prevents_promotion(self):
        verified = self.check()
        commands = []

        def fake_run(args, **kw):
            commands.append(args)
            if args[:3] == ["gh", "release", "download"]:
                dest = Path(args[args.index("--dir") + 1])
                for name in verified["files"]:
                    shutil.copyfile(self.bundle / name, dest / name)
                (dest / "SHA256SUMS").write_bytes(b"tampered remote transfer")
            return ""

        from subprocess import CompletedProcess

        absent = CompletedProcess([], 1, stdout="", stderr="HTTP 404: Not Found")
        with (
            patch.object(p, "run", side_effect=fake_run),
            patch.object(p.subprocess, "run", return_value=absent),
        ):
            with self.assertRaises(Blocked):
                p.publish("DeepLayerTeam/Launcher", verified, self.bundle)
        self.assertFalse(any(x[:3] == ["gh", "release", "edit"] for x in commands))

    def test_preexisting_release_never_overwritten(self):
        verified = self.check()
        from subprocess import CompletedProcess

        existing = CompletedProcess([], 0, stdout="{}", stderr="")
        with patch.object(p.subprocess, "run", return_value=existing):
            with self.assertRaises(Blocked):
                p.publish("DeepLayerTeam/Launcher", verified, self.bundle)


if __name__ == "__main__":
    unittest.main()
