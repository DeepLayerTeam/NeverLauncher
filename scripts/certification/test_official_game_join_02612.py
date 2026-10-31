import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from importlib.util import module_from_spec, spec_from_file_location

SCRIPT = Path(__file__).with_name("official-game-join-02612.py")
spec = spec_from_file_location("live_join", SCRIPT)
module = module_from_spec(spec)
spec.loader.exec_module(module)

UID = "123456781234123412341234567890ab"
SUBJECT = hashlib.sha256(UID.encode()).hexdigest()


def report():
    return {
        "schema": "launcher.official-provider-poc.v1",
        "result": "online_session_verified",
        "onlineModeSession": "verified_live_join_has_joined",
        "minecraftServicesAccess": "verified_live_profile",
        "minecraftProfileSHA256": SUBJECT,
        "stages": [
            {"name": x, "status": "passed"}
            for x in (
                "microsoft_oauth",
                "microsoft_refresh",
                "xbox_live",
                "xsts",
                "minecraft_token",
                "minecraft_entitlements",
                "minecraft_profile",
                "sessionserver_join_has_joined",
            )
        ],
    }


class TestGameJoinEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.p = self.root / "provider.json"
        self.c = self.root / "server.properties"
        self.l = self.root / "latest.log"
        self.p.write_text(json.dumps(report()))
        self.c.write_text("# Actual server properties\nonline-mode=true\n")
        self.l.write_text(
            "[Server] UUID of player PrivatePerson is 12345678-1234-1234-1234-1234567890ab\n[Server] PrivatePerson[/192.0.2.2:55555] logged in with entity id 42 at (0, 64, 0)\n"
        )

    def test_matches_official_identity_and_real_login(self):
        evidence = module.check_evidence(self.p, self.c, self.l, "vanilla")
        self.assertEqual(evidence["subjectSHA256"], SUBJECT)
        self.assertEqual(evidence["matchingEvents"], 1)
        target = self.root / "evidence.json"
        module.save_private_exclusive(target, evidence)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            module.save_private_exclusive(target, evidence)

    def test_no_offline_or_unverified_profile_success(self):
        self.c.write_text("online-mode=false\n")
        with self.assertRaises(module.CertificationFailure):
            module.check_evidence(self.p, self.c, self.l, "vanilla")
        self.c.write_text("online-mode=true\n")
        bad = report()
        bad["onlineModeSession"] = "not_verified"
        self.p.write_text(json.dumps(bad))
        with self.assertRaises(module.CertificationFailure):
            module.check_evidence(self.p, self.c, self.l, "vanilla")

    def test_wrong_player_and_loader_missing(self):
        self.l.write_text(
            "[Server] UUID of player Someone is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n[Server] Someone[/127.0.0.1:8] logged in with entity id 1\n"
        )
        with self.assertRaises(module.CertificationFailure):
            module.check_evidence(self.p, self.c, self.l, "vanilla")
        self.l.write_text(
            "Fabric Loader starting\n"
            + "[Server] UUID of player PrivatePerson is 12345678-1234-1234-1234-1234567890ab\n[Server] PrivatePerson[/127.0.0.1:8] logged in with entity id 1\n"
        )
        self.assertEqual(
            module.check_evidence(self.p, self.c, self.l, "fabric")["serverKind"],
            "fabric",
        )
        with self.assertRaises(module.CertificationFailure):
            module.check_evidence(self.p, self.c, self.l, "neoforge")

    def test_only_uuid_without_actual_login_passes(self):
        self.l.write_text(
            "[Server] UUID of player PrivatePerson is 123456781234123412341234567890ab\n"
        )
        with self.assertRaises(module.CertificationFailure):
            module.check_evidence(self.p, self.c, self.l, "vanilla")


if __name__ == "__main__":
    unittest.main()
