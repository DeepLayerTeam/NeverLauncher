import hashlib
import importlib.util
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

spec = importlib.util.spec_from_file_location(
    "official_ga_gate", Path(__file__).with_name("official_minecraft_0270.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SHA = "a" * 40
SUBJECT = "c" * 64
CLIENT = "12345678-1234-1234-1234-123456789abc"
NOW = datetime.now(timezone.utc)
TIME = NOW.isoformat()
STAGES = sorted(gate.REQUIRED_STAGES)


def provider(flow, platform, arch):
    return dict(
        schema="launcher.official-provider-poc.v1",
        version="0.27.0",
        oauthFlow=flow,
        clientId=CLIENT,
        provider="fixed_official_microsoft_xbox_minecraft_hosts",
        os=platform,
        architecture=arch,
        result="online_session_verified",
        minecraftServicesAccess="verified_live_profile",
        onlineModeSession="verified_live_join_has_joined",
        stages=[dict(name=x, status="passed") for x in STAGES],
        minecraftProfileSHA256=SUBJECT,
        timestampUTC=TIME,
    )


def common(target):
    return dict(
        commit=SHA,
        productVersion="0.27.0",
        target=target,
        status="passed",
        simulated=False,
        mocked=False,
        actualExecution=True,
        observedUTC=TIME,
    )


def proof(label, target):
    platform, arch = target.split("-")
    if label in ("browser", "device"):
        return provider(label, platform, arch)
    data = common(target)
    if label in ("vanilla", "modded"):
        data.update(
            schema="launcher.official-game-join-evidence.v1",
            onlineMode=True,
            providerOnlineSession="verified_in_supplied_report",
            serverLogin="matching_official_uuid_and_login_recorded",
            subjectSHA256=SUBJECT,
            matchingEvents=1,
            reviewedOriginalLogs=True,
            actualClientWorldEntry=True,
            serverKind="vanilla" if label == "vanilla" else "fabric",
        )
    elif label == "vault":
        data.update(
            schema="launcher.official-vault-live.v1",
            keychainAvailable=True,
            credentialsAbsentFromRenderer=True,
            identityUUIDSHA256=SUBJECT,
            checks={
                k: "passed"
                for k in (
                    "restart",
                    "refresh",
                    "revoked-refresh",
                    "cancel",
                    "select",
                    "logout",
                    "relogin",
                    "token-leak",
                    "yggdrasil-isolation",
                    "offline-isolation",
                )
            },
        )
    else:
        data.update(
            schema="launcher.official-signed-delivery.v1",
            signatureVerified=True,
            productionKey=True,
            trustedSigner="Test-only fixture signer",
            artifactSha256="f" * 64,
            platformSigning={
                "windows": "authenticode",
                "darwin": "developer-id-notarized",
                "linux": "signed-release-manifest",
            }[platform],
        )
    return data


class OfficialGATest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = (
            Ed25519PrivateKey.generate()
        )  # Only synthetic test data, never a release key.
        self.pub = (
            self.key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        for platform, arch in sorted(gate.TARGETS):
            target = f"{platform}-{arch}"
            folder = self.root / target
            folder.mkdir()
            objects = {}
            for label in sorted(gate.REPORTS):
                name = f"{label}.json"
                body = json.dumps(proof(label, target), sort_keys=True).encode()
                (folder / name).write_bytes(body)
                objects[label] = {
                    "file": name,
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            attestation = dict(
                schemaVersion=gate.SCHEMA,
                productVersion="0.27.0",
                commit=SHA,
                target=target,
                status="passed",
                gitTreeClean=True,
                observedUTC=TIME,
                checks={k: "passed" for k in gate.REQUIRED_CHECKS},
                externalApproval=dict(
                    provider="Minecraft Services",
                    ownApplication=True,
                    manuallyConfirmed=True,
                    recordId="test-record-1234",
                    confirmedUTC=TIME,
                ),
                clientId=CLIENT,
                objects=objects,
            )
            self.resign(folder, attestation)

    def resign(self, folder, attestation):
        raw = json.dumps(attestation, sort_keys=True).encode()
        (folder / "attestation.json").write_bytes(raw)
        (folder / "attestation.sig").write_text(self.key.sign(gate.DOMAIN + raw).hex())

    def change_report(self, target, label, mutate, resign=False):
        folder = self.root / target
        obj = json.loads((folder / f"{label}.json").read_text())
        mutate(obj)
        data = json.dumps(obj, sort_keys=True).encode()
        (folder / f"{label}.json").write_bytes(data)
        if resign:
            att = json.loads((folder / "attestation.json").read_text())
            att["objects"][label]["sha256"] = hashlib.sha256(data).hexdigest()
            self.resign(folder, att)

    def verify(self):
        return gate.verify_all(self.root, self.pub, SHA, now=NOW)

    def test_complete_six_target_fixture(self):
        receipt = self.verify()
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(receipt["targets"]), 6)

    def test_unsigned_mutation_and_replaced_report_rejected(self):
        self.change_report(
            "windows-amd64", "vault", lambda d: d["checks"].update(logout="failed")
        )
        with self.assertRaisesRegex(gate.GateError, "digest mismatch"):
            self.verify()
        self.change_report(
            "windows-amd64",
            "vault",
            lambda d: d["checks"].update(logout="failed"),
            resign=True,
        )
        with self.assertRaisesRegex(gate.GateError, "vault/lifecycle"):
            self.verify()

    def test_failed_signer_or_wrong_commit(self):
        with self.assertRaises(gate.GateError):
            gate.verify_all(self.root, "f" * 64, SHA, now=NOW)
        with self.assertRaises(gate.GateError):
            gate.verify_all(self.root, self.pub, "b" * 40, now=NOW)

    def test_provider_wrong_uuid_is_rejected(self):
        self.change_report(
            "linux-amd64",
            "device",
            lambda d: d.update(minecraftProfileSHA256="b" * 64),
            resign=True,
        )
        with self.assertRaisesRegex(gate.GateError, "same official account"):
            self.verify()

    def test_fake_approval_and_skipped_checks_fail(self):
        folder = self.root / "darwin-arm64"
        att = json.loads((folder / "attestation.json").read_text())
        att["externalApproval"]["manuallyConfirmed"] = False
        self.resign(folder, att)
        with self.assertRaisesRegex(gate.GateError, "provider approval"):
            self.verify()
        att["externalApproval"]["manuallyConfirmed"] = True
        att["checks"]["signed-native-delivery"] = "skipped"
        self.resign(folder, att)
        with self.assertRaisesRegex(gate.GateError, "skipped GA"):
            self.verify()

    def test_stale_missing_or_linked_proof_fails(self):
        with self.assertRaisesRegex(gate.GateError, "stale"):
            gate.verify_all(self.root, self.pub, SHA, now=NOW + timedelta(days=15))
        (self.root / "windows-arm64" / "device.json").unlink()
        with self.assertRaisesRegex(gate.GateError, "missing/symlinked"):
            self.verify()

    def test_duplicate_json_and_artifact_traversal_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "duplicate"):
            gate.strict_json(b'{"x":1,"x":2}')
        with self.assertRaises(gate.GateError):
            gate.file_bytes(self.root, "../secret.json", "f" * 64)

    def test_protected_signer_requires_valid_key_and_refuses_overwrite(self):
        from importlib.util import spec_from_file_location, module_from_spec

        signer_spec = spec_from_file_location(
            "operator_signer",
            Path(__file__).with_name("sign_official_minecraft_0270.py"),
        )
        import sys

        directory = str(Path(__file__).parent)
        sys.path.insert(0, directory)
        try:
            signer = module_from_spec(signer_spec)
            signer_spec.loader.exec_module(signer)
        finally:
            sys.path.remove(directory)
        folder = self.root / "windows-amd64"
        (folder / "attestation.sig").unlink()
        seed = self.key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        with self.assertRaisesRegex(Exception, "differs"):
            signer.sign_attestation(folder, "e" * 64, seed, SHA)
        signer.sign_attestation(folder, self.pub, seed, SHA)
        self.assertEqual((folder / "attestation.sig").stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(Exception, "already exists"):
            signer.sign_attestation(folder, self.pub, seed, SHA)

    def test_release_never_has_local_approval_key(self):
        # CI cannot fabricate external approval because the signing key is not in the repo.
        self.assertFalse((Path(__file__).parent / "official-ga-seed.key").exists())


if __name__ == "__main__":
    unittest.main()
