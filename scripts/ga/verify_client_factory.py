#!/usr/bin/env python3
"""Fail-closed inspection of independent Client Factory GA CI artifacts.

Does not replace verification of the actual Minecraft files on the original
runner: requires the separately approved *successful* exact-commit CI run.
"""

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FAMILIES = {"vanilla", "fabric", "quilt", "forge", "neoforge"}
HEX64 = re.compile(r"^[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")


def fail(message):
    raise ValueError(message)


def unique(root, name):
    files = list(root.rglob(name))
    if len(files) != 1 or not files[0].is_file() or files[0].is_symlink():
        fail(f"exactly one regular {name} is required, found {len(files)}")
    return files[0]


def read(path, limit=32 << 20):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        fail(f"invalid evidence file {path}")
    return path.read_bytes()


def decode(raw):
    return json.loads(raw)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_signature(payload, public_key, hashed):
    raw = base64.b64decode(payload["signature"], validate=True)
    to_sign = dict(payload)
    to_sign["signature"] = ""
    signed = json.dumps(to_sign, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    if hashed:
        signed = hashlib.sha256(signed).digest()
    Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_key, validate=True)
    ).verify(raw, signed)
    if payload.get("publicKey") != public_key:
        fail("certificate embeds an unapproved public key")


def verify(root, runtime_key, join_key, version, commit):
    if version != "0.28.0" or not SHA.fullmatch(commit):
        fail("invalid GA version or commit")
    if runtime_key == join_key:
        fail("client launch and server join must use independent trust roots")
    certificates = list(root.rglob("runtime-certificate.json"))
    if len(certificates) != 5:
        fail(
            f"exactly five native launch certificates required, got {len(certificates)}"
        )
    families = set()
    digest_set = set()
    for file in certificates:
        cert = decode(read(file, 1 << 20))
        if (
            cert.get("schema") != "launcher.factory.runtime-certificate.v1"
            or cert.get("status") != "certified"
        ):
            fail(f"invalid runtime certificate {file}")
        loader = cert.get("loader")
        target = cert.get("target")
        if (
            loader not in FAMILIES
            or loader in families
            or target != {"os": "linux", "arch": "x86_64"}
        ):
            fail("duplicate/missing loader or mismatching runner target")
        families.add(loader)
        if (
            not HEX64.fullmatch(cert.get("planSha256", ""))
            or not HEX64.fullmatch(cert.get("javaSha256", ""))
            or not HEX64.fullmatch(cert.get("runtimeSha256", ""))
        ):
            fail("missing runtime/toolchain identity")
        digest_set.add(cert["planSha256"])
        verify_signature(cert, runtime_key, True)
        for kind, rel, digest in [
            ("probe", cert.get("probeFile"), cert.get("probeSha256")),
            ("log", cert.get("logFile"), cert.get("logSha256")),
        ]:
            if (
                not rel
                or "/" in rel
                or "\\" in rel
                or rel in {".", ".."}
                or not HEX64.fullmatch(digest or "")
            ):
                fail("invalid certificate evidence path")
            contents = read(file.parent / rel)
            if sha(contents) != digest:
                fail(f"{kind} digest mismatch for {loader}")
            if kind == "probe":
                probe = decode(contents)
                if (
                    probe.get("status") != "passed"
                    or probe.get("minecraftVersion") != cert.get("profileId")
                    or probe.get("detectedJavaMajor") != cert.get("javaMajor")
                    or probe.get("classpathEntries", 0) < 1
                    or not (probe.get("timedOut") or probe.get("success"))
                ):
                    fail(f"invalid launch probe for {loader}")
            elif b"--- process output ---" not in contents or not re.search(
                rb"(?i)(?:LWJGL|MinecraftForge|FabricLoader|QuiltLoader|Minecraft client initialized)",
                contents.split(b"--- process output ---", 1)[1],
            ):
                fail(f"missing game startup proof for {loader}")
    if families != FAMILIES or len(digest_set) != 5:
        fail("runtime matrix must attest five distinct loader builds")
    join_file = unique(root, "matching-server.json")
    join_raw = read(join_file, 2 << 20)
    join = decode(join_raw)
    if (
        join.get("status") != "passed"
        or join.get("serverHost") != "127.0.0.1"
        or not all(
            join.get(k) is True
            for k in [
                "serverVersionMatched",
                "clientJoinedServer",
                "actualClient",
                "serverProcessAlive",
            ]
        )
        or not join.get("minecraftVersion")
        or not (
            join["minecraftVersion"]
            == join.get("clientVersion")
            == join.get("serverVersion")
        )
    ):
        fail("exact-version real client/server join not proven")
    att = decode(read(unique(root, "join-attestation.json"), 1 << 20))
    if (
        att.get("schema") != "launcher.factory.ga-join-attestation.v1"
        or att.get("version") != version
        or att.get("commit") != commit
        or att.get("evidenceSha256") != sha(join_raw)
    ):
        fail("join attestation not bound to required release and evidence")
    age = datetime.now(timezone.utc) - datetime.fromisoformat(
        att["createdAt"].replace("Z", "+00:00")
    )
    if age < -timedelta(minutes=5) or age > timedelta(days=30):
        fail("join attestation age invalid")
    verify_signature(att, join_key, False)
    ga = decode(read(unique(root, "ga-report.json"), 1 << 20))
    if (
        ga.get("schema") != "launcher.factory.ga-report.v1"
        or ga.get("status") != "passed"
        or ga.get("version") != version
        or ga.get("commit") != commit
        or ga.get("certifiedTargets") != 5
        or ga.get("certifiedFamilies") != 5
        or ga.get("joinEvidenceSha256") != sha(join_raw)
    ):
        fail("GA report missing or inconsistent")
    return {
        "status": "passed",
        "version": version,
        "commit": commit,
        "families": sorted(families),
        "joinEvidenceSha256": sha(join_raw),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--runtime-public-key", required=True)
    p.add_argument("--join-public-key", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    args = p.parse_args()
    print(
        json.dumps(
            verify(
                args.evidence,
                args.runtime_public_key,
                args.join_public_key,
                args.version,
                args.commit,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
