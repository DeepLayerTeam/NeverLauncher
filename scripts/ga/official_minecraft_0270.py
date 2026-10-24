#!/usr/bin/env python3
"""Fail-closed, offline verification of independent live official-Minecraft GA evidence.

An authorized operator signs exact bytes of each attestation OUTSIDE this repo.
This program NEVER creates approval, private keys, test reports, or signatures.
Every referenced evidence file is content-addressed inside its own target folder.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b"NeverLauncher-Official-Minecraft-GA-0.27.0-v1\n"
SCHEMA = "neverlauncher.official-minecraft.ga-attestation.v1"
TARGETS = {(p, a) for p in ("windows", "linux", "darwin") for a in ("amd64", "arm64")}
GO_PLATFORM = {"windows":"windows", "linux":"linux", "darwin":"darwin"}
REPORTS = {"browser", "device", "vanilla", "modded", "vault", "signature"}
REQUIRED_STAGES = {"microsoft_oauth", "microsoft_refresh", "xbox_live", "xsts", "minecraft_token",
                   "minecraft_entitlements", "minecraft_profile", "sessionserver_join_has_joined"}
REQUIRED_CHECKS = {"oauth-pkce-live", "device-code-live", "provider-approved", "sessionserver-join-live",
                   "vanilla-world-join", "modded-world-join", "native-vault-restart",
                   "native-vault-refresh", "native-vault-logout", "native-vault-relogin",
                   "identity-uuid-stable", "offline-yggdrasil-isolation", "token-leak-audit",
                   "signed-native-delivery"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GITSHA = re.compile(r"[0-9a-f]{40}\Z")
SUBJECT = re.compile(r"[0-9a-f]{64}\Z")

class GateError(ValueError):
    pass


def require(test: bool, message: str) -> None:
    if not test:
        raise GateError(message)


def strict_json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _v: (_ for _ in ()).throw(GateError("invalid numeric constant")))
    require(type(value) is dict, "evidence is not a JSON object")
    return value


def file_bytes(folder: Path, filename: str, expected_digest: str, *, max_size: int = 1_048_576) -> bytes:
    require(isinstance(filename, str) and filename not in (".", "..") and Path(filename).name == filename and
            filename.endswith(".json") and not filename.startswith("."), "unsafe evidence filename")
    require(isinstance(expected_digest, str) and SHA256.fullmatch(expected_digest) is not None, "invalid evidence digest")
    path = folder / filename
    require(not folder.is_symlink() and not path.is_symlink() and path.is_file(), "missing/symlinked evidence file")
    require(path.stat().st_size <= max_size, "oversized GA evidence")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_digest, "evidence content digest mismatch")
    return raw


def checked_time(value: str, now: datetime) -> None:
    require(isinstance(value, str), "missing observed time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise GateError("invalid observed time") from e
    require(parsed.tzinfo is not None and now - timedelta(days=14) <= parsed.astimezone(timezone.utc) <= now + timedelta(minutes=5),
            "missing/stale/future GA evidence")


def common_report(report: dict, target: str, commit: str, version: str, now: datetime) -> None:
    require(report.get("commit") == commit and report.get("productVersion") == version and
            report.get("target") == target and report.get("status") == "passed", "report not bound to exact source/platform")
    require(report.get("simulated") is False and report.get("mocked") is False and report.get("actualExecution") is True,
            "missing affirmative live execution proof")
    checked_time(report.get("observedUTC"), now)


def check_provider(report: dict, flow: str, platform: str, arch: str, client: str, now: datetime) -> str:
    require(report.get("schema") == "neverlauncher.official-provider-poc.v1" and
            report.get("version") == "0.27.0" and report.get("oauthFlow") == flow and
            report.get("clientId") == client and report.get("provider") == "fixed_official_microsoft_xbox_minecraft_hosts" and
            report.get("os") == platform and report.get("architecture") == arch, "wrong live provider POC")
    require(report.get("result") == "online_session_verified" and
            report.get("minecraftServicesAccess") == "verified_live_profile" and
            report.get("onlineModeSession") == "verified_live_join_has_joined", "provider/sessionserver live result not passed")
    stages = report.get("stages")
    require(isinstance(stages, list) and REQUIRED_STAGES <= {
        s.get("name") for s in stages if isinstance(s, dict) and s.get("status") == "passed"
    }, "provider chain missing successful stage")
    subject = report.get("minecraftProfileSHA256")
    require(isinstance(subject, str) and SUBJECT.fullmatch(subject) is not None, "missing stable UUID digest")
    checked_time(report.get("timestampUTC"), now)
    return subject


def verify_target(root: Path, platform: str, arch: str, key: Ed25519PublicKey, commit: str,
                  now: datetime) -> dict:
    target = f"{platform}-{arch}"
    folder = root / target
    require(folder.is_dir() and not folder.is_symlink(), f"missing {target} evidence")
    att = folder / "attestation.json"
    sig = folder / "attestation.sig"
    require(not att.is_symlink() and not sig.is_symlink() and att.is_file() and sig.is_file(), "missing/symlinked GA signature")
    require(att.stat().st_size <= 64 * 1024 and sig.stat().st_size <= 256, "oversized GA attestation/signature")
    raw = att.read_bytes()
    try:
        signature = bytes.fromhex(sig.read_text("ascii").strip())
        require(len(signature) == 64, "invalid Ed25519 signature length")
        key.verify(signature, DOMAIN + raw)
    except (ValueError, InvalidSignature) as e:
        raise GateError("GA evidence attestation signature invalid") from e
    data = strict_json(raw)
    require(data.get("schemaVersion") == SCHEMA and data.get("productVersion") == "0.27.0" and
            data.get("commit") == commit and data.get("target") == target and data.get("status") == "passed" and
            data.get("gitTreeClean") is True, "signed GA attestation does not match source and target")
    checked_time(data.get("observedUTC"), now)
    checks = data.get("checks")
    require(type(checks) is dict and set(checks) == REQUIRED_CHECKS and
            all(v == "passed" for v in checks.values()), "missing/failed/skipped GA acceptance check")
    approval = data.get("externalApproval")
    require(type(approval) is dict and approval.get("provider") == "Minecraft Services" and
            approval.get("ownApplication") is True and approval.get("manuallyConfirmed") is True and
            isinstance(approval.get("recordId"), str) and 8 <= len(approval["recordId"]) <= 160,
            "provider approval must be manually confirmed and independently attested")
    checked_time(approval.get("confirmedUTC"), now)
    client = data.get("clientId")
    require(isinstance(client, str) and re.fullmatch(r"[a-fA-F0-9-]{36}", client) is not None,
            "client ID missing from independently signed evidence")
    objects = data.get("objects")
    require(type(objects) is dict and set(objects) == REPORTS, "missing exact GA evidence set")
    proofs = {}
    for label, reference in objects.items():
        require(type(reference) is dict and set(reference) == {"file", "sha256"}, "invalid attached proof reference")
        proofs[label] = strict_json(file_bytes(folder, reference["file"], reference["sha256"]))
    browser = check_provider(proofs["browser"], "browser", platform, arch, client, now)
    device = check_provider(proofs["device"], "device", platform, arch, client, now)
    require(browser == device, "browser and device did not verify the same official account")
    for label, kind in (("vanilla", "vanilla"), ("modded", None)):
        proof = proofs[label]
        common_report(proof, target, commit, "0.27.0", now)
        require(proof.get("schema") == "neverlauncher.official-game-join-evidence.v1" and
                proof.get("onlineMode") is True and proof.get("providerOnlineSession") == "verified_in_supplied_report" and
                proof.get("serverLogin") == "matching_official_uuid_and_login_recorded" and
                proof.get("subjectSHA256") == browser and type(proof.get("matchingEvents")) is int and
                proof["matchingEvents"] >= 1 and proof.get("reviewedOriginalLogs") is True and
                proof.get("actualClientWorldEntry") is True, "unverified real game world join")
        require(proof.get("serverKind") == kind if kind else proof.get("serverKind") in {"fabric", "forge", "neoforge"},
                "wrong vanilla/modded loader")
    vault = proofs["vault"]
    common_report(vault, target, commit, "0.27.0", now)
    require(vault.get("schema") == "neverlauncher.official-vault-live.v1" and
            vault.get("keychainAvailable") is True and vault.get("credentialsAbsentFromRenderer") is True and
            vault.get("identityUUIDSHA256") == browser and
            type(vault.get("checks")) is dict and
            all(vault["checks"].get(k) == "passed" for k in (
                "restart", "refresh", "revoked-refresh", "cancel", "select", "logout", "relogin", "token-leak",
                "yggdrasil-isolation", "offline-isolation")), "native OS vault/lifecycle not verified")
    signed = proofs["signature"]
    common_report(signed, target, commit, "0.27.0", now)
    require(signed.get("schema") == "neverlauncher.official-signed-delivery.v1" and
            signed.get("signatureVerified") is True and signed.get("productionKey") is True and
            isinstance(signed.get("trustedSigner"), str) and signed["trustedSigner"].strip() and
            isinstance(signed.get("artifactSha256"), str) and SHA256.fullmatch(signed["artifactSha256"]) is not None and
            signed.get("platformSigning") == {"windows": "authenticode", "darwin": "developer-id-notarized", "linux": "signed-release-manifest"}[platform],
            "native production signature not verified")
    return {"target": target, "attestationSha256": hashlib.sha256(raw).hexdigest(),
            "signedArtifactSha256": signed["artifactSha256"], "status": "passed"}


def verify_all(root: Path, public_key_hex: str, commit: str, now: datetime | None = None) -> dict:
    require(isinstance(commit, str) and GITSHA.fullmatch(commit) is not None, "exact git SHA required")
    require(isinstance(public_key_hex, str) and re.fullmatch(r"[0-9a-fA-F]{64}", public_key_hex) is not None,
            "pinned Ed25519 public key required")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    now = now or datetime.now(timezone.utc)
    records = [verify_target(root, p, a, key, commit, now) for p, a in sorted(TARGETS)]
    return {"schemaVersion": "neverlauncher.official-minecraft.ga-receipt.v1",
            "productVersion": "0.27.0", "commit": commit, "status": "passed", "targets": records}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestations", required=True, type=Path)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = verify_all(args.attestations, args.public_key, args.commit)
    except (GateError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"0.27.0 official Minecraft GA blocked: {exc}", file=sys.stderr)
        return 2
    # This is a receipt about signatures and operator attestations, NOT
    # a claim that an unauthenticated JSON file proves the platform execution.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("0.27.0 official Minecraft GA: six signed live attestations verified")
    return 0

if __name__ == "__main__":
    sys.exit(main())
