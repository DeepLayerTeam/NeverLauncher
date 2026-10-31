#!/usr/bin/env python3
"""Verify evidence from an ACTUAL official Minecraft Java client/server login.

Runs only on operator-supplied server.properties, server log, and LIVE provider
POC output. Never launches a fake Minecraft provider or alters online-mode.
This is a local evidence consistency check, not a cryptographic attestation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

UUID_RE = re.compile(
    r"UUID of player (?P<name>[A-Za-z0-9_]{3,16}) is (?P<uuid>[a-fA-F0-9-]{32,36})"
)
LOGIN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_]{3,16})\[[^\]\r\n]*\] logged in with entity id \d+", re.I
)
LOADER_MARKERS = {
    "fabric": ("fabric loader", "fabricloader", "fabric-loader"),
    "forge": ("forge mod loader", "modlauncher", "minecraftforge", "forge version"),
    "neoforge": ("neoforge", "neoforged"),
}


class CertificationFailure(ValueError):
    pass


def check_evidence(
    report_path: Path, properties_path: Path, log_path: Path, kind: str
) -> dict:
    if kind not in {"vanilla", *LOADER_MARKERS}:
        raise CertificationFailure("unsupported server loader")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if (
        report.get("schema") != "launcher.official-provider-poc.v1"
        or report.get("result") != "online_session_verified"
    ):
        raise CertificationFailure(
            "report is not a successful live online session verification"
        )
    if (
        report.get("onlineModeSession") != "verified_live_join_has_joined"
        or report.get("minecraftServicesAccess") != "verified_live_profile"
    ):
        raise CertificationFailure("Mojang join/hasJoined proof missing")
    stages = report.get("stages", [])
    mandatory = {
        "microsoft_oauth",
        "microsoft_refresh",
        "xbox_live",
        "xsts",
        "minecraft_token",
        "minecraft_entitlements",
        "minecraft_profile",
        "sessionserver_join_has_joined",
    }
    if not isinstance(stages, list) or not mandatory.issubset(
        {
            s.get("name")
            for s in stages
            if isinstance(s, dict) and s.get("status") == "passed"
        }
    ):
        raise CertificationFailure("real authentication chain not fully passed")
    subject = report.get("minecraftProfileSHA256")
    if not isinstance(subject, str) or not re.fullmatch(r"[a-f0-9]{64}", subject):
        raise CertificationFailure("no stable Minecraft subject digest")
    raw_properties = properties_path.read_text(encoding="utf-8-sig")
    values = {}
    for line in raw_properties.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    if values.get("online-mode", "").lower() != "true":
        raise CertificationFailure(
            "server.properties does not enforce online-mode=true"
        )
    if values.get("enforce-secure-profile", "").lower() == "false":
        # This setting is independent of online-mode, but include it as a
        # warning rather than treating legitimate older servers as unsafe.
        secure_profile = "disabled_by_server"
    else:
        secure_profile = "default_or_enabled"
    # Keep the bounded reader to avoid accidentally ingesting large histories.
    if log_path.stat().st_size > 32 * 1024 * 1024:
        raise CertificationFailure(
            "server log exceeds 32 MiB, provide the bounded actual run"
        )
    log = log_path.read_text(encoding="utf-8", errors="replace")
    if kind in LOADER_MARKERS and not any(
        marker in log.lower() for marker in LOADER_MARKERS[kind]
    ):
        raise CertificationFailure(
            f"server log does not establish {kind} loader startup"
        )
    matches = []
    observed = {}
    for line_no, line in enumerate(log.splitlines(), 1):
        match = UUID_RE.search(line)
        if match:
            normalized = match.group("uuid").replace("-", "").lower()
            if len(normalized) != 32:
                continue
            digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()
            if digest == subject:
                observed[match.group("name").lower()] = line_no
        joined = LOGIN_RE.search(line)
        if joined:
            username = joined.group("name").lower()
            original = observed.get(username)
            if original is not None and original < line_no and line_no - original < 500:
                matches.append((original, line_no))
    if not matches:
        raise CertificationFailure(
            "no matching official UUID followed by successful login event"
        )
    return {
        "schema": "launcher.official-game-join-evidence.v1",
        "release": report.get("version", "0.26.12"),
        "verifiedUTC": datetime.now(timezone.utc).isoformat(),
        "serverKind": kind,
        "onlineMode": True,
        "secureProfilePolicy": secure_profile,
        "providerOnlineSession": "verified_in_supplied_report",
        "serverLogin": "matching_official_uuid_and_login_recorded",
        "subjectSHA256": subject,
        "matchingEvents": len(matches),
        "provenance": "operator_supplied_files_not_cryptographically_attested",
    }


def save_private_exclusive(path: Path, obj: dict):
    payload = (
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provider-report", required=True, type=Path)
    ap.add_argument("--server-properties", required=True, type=Path)
    ap.add_argument("--server-log", required=True, type=Path)
    ap.add_argument(
        "--kind", choices=["vanilla", "fabric", "forge", "neoforge"], required=True
    )
    ap.add_argument("--evidence", required=True, type=Path)
    args = ap.parse_args()
    try:
        evidence = check_evidence(
            args.provider_report, args.server_properties, args.server_log, args.kind
        )
        save_private_exclusive(args.evidence, evidence)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(
            f"Official game join could not be certified: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return 2
    print(
        f"Evidence written: {args.evidence} (server kind: {args.kind}; real operator log required)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
