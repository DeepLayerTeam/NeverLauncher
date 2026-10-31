"""Receipt/schema negative tests; these are NOT live browser evidence."""

import importlib.util
from pathlib import Path
import unittest

mod = Path(__file__).parents[2] / "e2e/scripts/owner-cycle-0390-browser.py"
spec = importlib.util.spec_from_file_location("ownercycle0390", mod)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CHECKS = {
    "project-created-in-admin",
    "profile-created-in-admin",
    "bad-package-denied",
    "good-package-published",
    "channel-head-confirmed",
    "rollback-confirmed",
    "operator-cross-project-denied",
    "reload-recovered-original-job",
}
COMMIT = "a" * 40


class ReceiptTests(unittest.TestCase):
    def report(self):
        return {
            "schemaVersion": 1,
            "status": "passed",
            "productVersion": "0.39.0",
            "sourceCommit": COMMIT,
            "scope": "live-admin-browser-owner-cycle-0390",
            "checks": list(CHECKS),
            "projectId": "p",
            "profileId": "m",
            "goodPackageId": "g",
            "badPackageId": "b",
            "finalReleaseId": "rollback-1",
            "initialRevision": 10,
            "finalRevision": 12,
        }

    def test_complete(self):
        m.verify_receipt(self.report(), version="0.39.0", commit=COMMIT)

    def test_fail_closed(self):
        for key, value in [
            ("status", "blocked"),
            ("sourceCommit", "b" * 40),
            ("checks", ["project-created-in-admin"]),
            ("finalRevision", 11),
            ("finalReleaseId", ""),
        ]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                item = self.report()
                item[key] = value
                m.verify_receipt(item, version="0.39.0", commit=COMMIT)

    def test_active_ga_refuses_missing_owner_receipt(self):
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from verify_current_certifications import check_admin, ADMIN_CHECKS
        from certification_run import CertificationBlocked, identity
        from unittest.mock import patch
        from datetime import datetime, timezone

        env = {
            "GITHUB_SHA": COMMIT,
            "GITHUB_REPOSITORY": "DeepLayerTeam/Launcher",
            "GITHUB_RUN_ID": "55",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        now = datetime.now(timezone.utc)
        report = {
            "status": "passed",
            "productVersion": "0.39.0",
            "commit": COMMIT,
            "checks": sorted(ADMIN_CHECKS | {"live-playwright-owner-cycle-0390"}),
            "adminBundle": {"index.html": "a" * 64, "assets/index.js": "a" * 64},
            "openapiSha256": "a" * 64,
            "certificationRun": identity("0.39.0", COMMIT, env, now=now),
        }
        with (
            patch("certification_run.os.environ", env),
            self.assertRaises(CertificationBlocked),
        ):
            check_admin(report, "0.39.0", COMMIT)
        report["ownerCycleReceiptSha256"] = "b" * 64
        with patch("certification_run.os.environ", env):
            check_admin(report, "0.39.0", COMMIT)


if __name__ == "__main__":
    unittest.main()
