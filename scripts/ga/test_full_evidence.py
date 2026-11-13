"""Тесты настоящих подписанных входных фикстур для полного GA-пакета и независимого повторного воспроизведения.

Фикстуры проверяют реальную верификацию Ed25519 и финальных байтов, а не игры.
"""
from __future__ import annotations
from datetime import timedelta, datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_security_capabilities import SecurityGATests
from test_verified_targets_variant2 import COMMIT, NOW, timevalue
from security_capabilities import scenarios_for_version, LOG_SCHEMA, expected_scope
from verified_targets import paths, verify, PLAYER_CHECKS_0400, Blocked
from package_full_evidence import package, extract_verified, evidence_files

VER = "0.43.15"


def write(path: Path, doc: dict) -> str:
    raw = json.dumps(doc, sort_keys=True).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class CompleteExecutionEvidenceTests(unittest.TestCase):
    def setUp(self):
        base = SecurityGATests("test_real_gate_adds_six_independently_verified_capabilities_per_target")
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.bundle = base.bundle
        self.evidence = base.evidence
        self.key = base.parent.keyfile
        approval = base.approval
        approval["version"] = VER
        baseline = set(scenarios_for_version("0.43.1"))
        additional = {k: v for k, v in scenarios_for_version(VER).items() if k not in baseline}
        for row in approval["targets"]:
            target = row["target"]
            _, old_pkg = paths("0.43.1", target)
            _, new_pkg = paths(VER, target)
            (self.bundle / old_pkg).rename(self.bundle / new_pkg)
            directory = self.evidence / "targets" / target
            playerdir = directory / "player-0400"
            for check in PLAYER_CHECKS_0400:
                reportfile = playerdir / (check + ".json")
                report = json.loads(reportfile.read_text())
                report["version"] = VER
                reportsha = write(reportfile, report)
                tracefile = directory / (check + ".json")
                trace = json.loads(tracefile.read_text())
                trace["version"] = VER
                trace["evidenceSha256"] = reportsha
                row["checks"][check]["sha256"] = write(tracefile, trace)
            for check in row["checks"]:
                if check in PLAYER_CHECKS_0400:
                    continue
                tracefile = directory / (check + ".json")
                trace = json.loads(tracefile.read_text())
                trace["version"] = VER
                row["checks"][check]["sha256"] = write(tracefile, trace)
            for check, (positive, negative) in additional.items():
                events = []
                for scenario, decision in ((positive, "allowed"), (negative, "denied")):
                    events.append({
                        "schemaVersion": LOG_SCHEMA, "executionId": "native-execution-431-" + target,
                        "runId": "401234", "runAttempt": 2, "target": target,
                        "packageSha256": row["packageSha256"], "scenario": scenario,
                        "observedDecision": decision, "observedAtUtc": timevalue(NOW - timedelta(minutes=10)),
                        "actualExecution": True, "simulated": False,
                    })
                rawlog = ("\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n").encode()
                (directory / "security-0431" / (check + ".jsonl")).write_bytes(rawlog)
                trace = {
                    "schemaVersion": "launcher.security.capability.0431.v1",
                    "version": VER, "commit": COMMIT, "target": target,
                    "kind": check, "status": "passed", "actualExecution": True,
                    "simulated": False, "artifactSha256": row["binarySha256"],
                    "packageSha256": row["packageSha256"],
                    "executionId": "native-execution-431-" + target,
                    "runId": "401234", "runAttempt": 2,
                    "scope": expected_scope(check),
                    "observedAtUtc": timevalue(NOW - timedelta(minutes=10)),
                    "runtimeLogSha256": hashlib.sha256(rawlog).hexdigest(),
                    "scenarios": {positive: "allowed", negative: "denied"},
                }
                row["checks"][check] = {"sha256": write(directory / (check + ".json"), trace)}
        base.sign()
        self.archive = self.bundle / "GA_EXECUTION_EVIDENCE_04315.zip"

    def produce(self):
        package(self.bundle, self.evidence, self.key, VER, COMMIT, self.archive, now=NOW)

    def replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for f in ("approval.json", "approval.sig"):
                (root / f).write_bytes((self.evidence / f).read_bytes())
            extract_verified(self.archive, root, VER)
            return verify(self.bundle, root, self.key, VER, COMMIT, now=NOW)

    def test_archive_replays_real_signature_and_all_six_final_bytes(self):
        self.produce()
        receipt = self.replay()
        self.assertEqual(receipt["version"], VER)
        self.assertEqual({r["target"] for r in receipt["targets"]},
                         {r["target"] for r in self.base.approval["targets"]})
        self.assertEqual(len(receipt["targets"]), 6)

    def test_missing_player_log_never_certifies(self):
        self.produce()
        with ZipFile(self.archive) as archive:
            keep = [(n.filename, archive.read(n)) for n in archive.infolist()
                    if n.filename != "targets/linux-arm64/player-0400/localYggdrasilJoin.log"]
        with ZipFile(self.archive, "w") as archive:
            for name, data in keep:
                archive.writestr(name, data)
        with self.assertRaisesRegex(ValueError, "отсутствуют обязательные элементы либо найдены повторяющиеся или лишние"):
            self.replay()

    def test_tampered_signed_trace_refused_even_if_zip_repacked(self):
        self.produce()
        with ZipFile(self.archive) as archive:
            items = [(n.filename, archive.read(n)) for n in archive.infolist()]
        with ZipFile(self.archive, "w") as archive:
            for name, data in items:
                archive.writestr(name, data + b" " if name.endswith("/serverJoin.json") else data)
        with self.assertRaises((Blocked, ValueError)):
            self.replay()

    def test_changed_final_package_refused_at_replay(self):
        self.produce()
        _, filename = paths(VER, "windows-arm64")
        (self.bundle / filename).write_bytes(b"altered shipping bytes")
        with self.assertRaises((Blocked, ValueError)):
            self.replay()

    def test_publish_ga_rechecks_full_archive_and_rejects_unsigned_receipt(self):
        # Создавайте подписанную фикстуру в текущем CI-запуске, чтобы настоящий валидатор
        # публикации, намеренно без внедрённых часов, смог её воспроизвести.
        current = datetime.now(timezone.utc)
        signed = self.base.approval
        signed["issuedAtUtc"] = timevalue(current - timedelta(minutes=5))
        signed["expiresAtUtc"] = timevalue(current + timedelta(minutes=30))
        for row in signed["targets"]:
            folder = self.evidence / "targets" / row["target"]
            for check in scenarios_for_version(VER):
                path = folder / (check + ".json")
                trace = json.loads(path.read_text())
                trace["observedAtUtc"] = timevalue(current - timedelta(minutes=10))
                log_path = folder / "security-0431" / (check + ".jsonl")
                events = [json.loads(line) for line in log_path.read_text().splitlines()]
                for event in events:
                    event["observedAtUtc"] = trace["observedAtUtc"]
                raw = ("\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n").encode()
                log_path.write_bytes(raw)
                trace["runtimeLogSha256"] = hashlib.sha256(raw).hexdigest()
                row["checks"][check]["sha256"] = write(path, trace)
        self.base.sign()
        package(self.bundle, self.evidence, self.key, VER, COMMIT, self.archive)
        from package_security import package as security_package
        from publish import verify_ga, RECEIPT, REHEARSAL
        security_package(self.evidence, signed,
                         self.bundle / "SECURITY_CAPABILITY_EVIDENCE_0431.zip")
        for name in ("approval.json", "approval.sig"):
            source = self.evidence / name
            target = self.bundle / ("GA_TARGET_APPROVAL.json" if name.endswith(".json")
                                     else "GA_TARGET_APPROVAL.sig")
            target.write_bytes(source.read_bytes())
        receipt = verify(self.bundle, self.evidence, self.key, VER, COMMIT)
        (self.bundle / RECEIPT).write_text(json.dumps(receipt))
        rehearsal = {
            "schemaVersion": "launcher.release.rehearsal.v1",
            "status": "package-and-ga-verified", "version": VER, "commit": COMMIT,
            "runId": "401234", "runAttempt": "2",
            "gaApprovalSha256": receipt["approvalSha256"],
            "targets": [
                {"target": row["target"], "binary": paths(VER, row["target"])[0],
                 "package": paths(VER, row["target"])[1],
                 "binarySha256": row["binarySha256"],
                 "packageSha256": row["packageSha256"]}
                for row in signed["targets"]
            ],
        }
        (self.bundle / REHEARSAL).write_text(json.dumps(rehearsal))
        self.assertEqual(verify_ga(self.bundle, self.key, VER, COMMIT, 401234, 2),
                         receipt["approvalSha256"])
        receipt["targets"][0]["checksPassed"] -= 1
        (self.bundle / RECEIPT).write_text(json.dumps(receipt))
        with self.assertRaises((Blocked, ValueError)):
            verify_ga(self.bundle, self.key, VER, COMMIT, 401234, 2)

    def test_duplicate_zip_entry_rejected(self):
        self.produce()
        with ZipFile(self.archive, "a") as archive:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(evidence_files(VER)[0], b"forged duplicate")
        with self.assertRaisesRegex(ValueError, "отсутствуют обязательные элементы либо найдены повторяющиеся или лишние"):
            self.replay()


if __name__ == "__main__":
    unittest.main()
