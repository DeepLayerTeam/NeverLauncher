#!/usr/bin/env python3
"""Unit tests exercise negative paths; mocked responses are never release evidence."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import staged_auth_0347 as auth

OFFICIAL = {
    "username": "ActualPlayer",
    "uuid": "12345678123412341234123412341234",
    "accessToken": "live-not-actually-a-token-12345",
    "userType": "msa",
    "authServerBaseUrl": "",
}
CUSTOM = dict(
    OFFICIAL, userType="mojang", authServerBaseUrl="https://staging-auth.example.net"
)
NEGATIVE = dict(
    CUSTOM,
    username="NegativeUser",
    uuid="abcdefabcdefabcdefabcdefabcdefab",
    accessToken="different-live-test-session-token",
)


class AuthBoundaryTests(unittest.TestCase):
    def test_offline_and_mock_certify_official(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "creds.json"
            for token in ("offline", "0"):
                f.write_text(json.dumps(dict(OFFICIAL, accessToken=token)))
                with self.assertRaises(auth.ProviderMisconfigured):
                    auth.run_probe("offline", f)
                with self.assertRaises(
                    (auth.ProviderRejected, auth.ProviderMisconfigured)
                ):
                    auth.run_probe("official", f)

    def test_real_mojang_join_requires_identity_and_two_endpoints(self):
        calls = []

        def fake(base, path, **kwargs):
            calls.append((base, path, kwargs))
            if "minecraft/profile" in path:
                return 200, {"name": OFFICIAL["username"], "id": OFFICIAL["uuid"]}
            if "hasJoined" in path:
                return 200, {"name": OFFICIAL["username"], "id": OFFICIAL["uuid"]}
            return 204, None

        with patch.object(auth, "provider_request", side_effect=fake):
            result = auth.official_probe(OFFICIAL, "official")
        self.assertEqual(result["providerHasJoined"], "passed")
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][0], "https://api.minecraftservices.com")
        self.assertEqual(calls[1][0], "https://sessionserver.mojang.com")
        self.assertNotEqual(calls[1][2]["data"]["serverId"], "")

    def test_outage_is_inconclusive_not_success(self):
        with patch.object(
            auth, "provider_request", side_effect=auth.ProviderUnavailable("timeout")
        ):
            with self.assertRaises(auth.ProviderUnavailable):
                auth.official_probe(OFFICIAL, "official")

    def test_wrong_identity_denied_despite_provider_200(self):
        with patch.object(
            auth,
            "provider_request",
            return_value=(200, {"name": "SomeoneElse", "id": OFFICIAL["uuid"]}),
        ):
            with self.assertRaises(auth.ProviderRejected):
                auth.official_probe(OFFICIAL, "official")

    def test_custom_replay_and_revocation_required(self):
        redemption = {}

        def fake(base, path, **kw):
            if path == "/authserver/validate":
                return 204, None
            if path.endswith("/join"):
                redemption[(kw["data"]["serverId"], kw["data"]["selectedProfile"])] = (
                    True
                )
                return 204, None
            if path.endswith("invalidate"):
                return 204, None
            if "hasJoined" in path:
                from urllib.parse import parse_qs, urlsplit

                q = parse_qs(urlsplit(path).query)
                username = q["username"][0]
                user = CUSTOM if username == CUSTOM["username"] else NEGATIVE
                key = (q["serverId"][0], user["uuid"])
                if redemption.pop(key, False) and user is CUSTOM:
                    return 200, {"name": user["username"], "id": user["uuid"]}
                return 204, None
            raise AssertionError(path)

        with patch.object(auth, "provider_request", side_effect=fake):
            result = auth.custom_probe(CUSTOM, NEGATIVE)
        self.assertTrue(result["replayDenied"])
        self.assertTrue(result["revokedSessionDenied"])

    def test_custom_replay_accepted_is_rejected(self):
        def bad(base, path, **kw):
            if "hasJoined" in path:
                return 200, {"name": CUSTOM["username"], "id": CUSTOM["uuid"]}
            return 204, None

        with patch.object(auth, "provider_request", side_effect=bad):
            with self.assertRaisesRegex(auth.ProviderRejected, "replay"):
                auth.custom_probe(CUSTOM, NEGATIVE)

    def test_guard_requires_actual_backend_policy_denial(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "negative.json"
            f.write_text(json.dumps(NEGATIVE))

            def fake(base, path, **kw):
                if "validate" in path:
                    return 204, None
                raise auth.ProviderRejected("guard trust policy denied")

            with patch.object(auth, "provider_request", side_effect=fake):
                result = auth.guard_denial_probe(CUSTOM, f)
            self.assertTrue(result["negativeGuardJoinDenied"])
            with patch.object(auth, "provider_request", return_value=(204, None)):
                with self.assertRaisesRegex(auth.ProviderRejected, "able to join"):
                    auth.guard_denial_probe(CUSTOM, f)


if __name__ == "__main__":
    unittest.main()
