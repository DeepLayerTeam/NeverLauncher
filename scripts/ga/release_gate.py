#!/usr/bin/env python3
"""Verify *signed* six-platform GA evidence and the exact artifacts it describes.

Only an authorized release CI signing key may produce an accepted attestation.
This verifier cannot create attestations or label unsigned packages as GA.
Evidence is deliberately external to source code and bound to one exact SHA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b"NeverLauncher-GA-0.24.0-attestation-v1\n"
TARGETS = {(p, a) for p in ("windows", "linux", "darwin") for a in ("amd64", "arm64")}
COMMON_CHECKS = {"os-signature", "installer-clean-machine", "managed-java-real",
                 "minecraft-real-launch", "recovery-rollback", "powerloss-recovery",
                 "runtime-certification", "baseline-benchmark"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GITSHA = re.compile(r"^[a-f0-9]{40}$")


def load_attested_file(folder: Path, name: str, digest: str) -> bytes:
    """Only direct, ordinary files inside the target folder are eligible."""
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"unsafe artifact path: {name!r}")
    if not SHA256.fullmatch(digest):
        raise ValueError(f"invalid SHA-256 for {name}")
    path = folder / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or symlinked file: {path}")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"content digest mismatch: {name}")
    return raw


def check_report(data: bytes, *, commit: str, version: str, subject: str) -> None:
    report = json.loads(data)
    if report.get("commit") != commit or report.get("productVersion") != version or report.get("status") != "passed":
        raise ValueError(f"{subject}: real execution report incomplete/mismatched")
    if report.get("simulated") or report.get("mocked"):
        raise ValueError(f"{subject}: simulated or mocked execution cannot certify GA")
    if subject == "osSignature":
        if report.get("signatureVerified") is not True or not report.get("trustedSigner"):
            raise ValueError("native OS signature/pinned publisher was not verified")
    elif subject == "cleanMachine":
        if report.get("schemaVersion") != "neverlauncher.ga.clean-machine.v1" or not SHA256.fullmatch(report.get("javaSha256", "")) or not SHA256.fullmatch(report.get("logSha256", "")) or not report.get("minecraftVersion"):
            raise ValueError("real Minecraft/Managed Java evidence missing")
    elif subject == "certification":
        if not report.get("gitTreeClean") or not report.get("suites") or report.get("unmetGates"):
            raise ValueError("full certification suites missing or incomplete")
        if any(s.get("status") != "passed" for s in report["suites"]):
            raise ValueError("failed or skipped certification suite")
    elif subject == "benchmark":
        if not isinstance(report.get("runs"), list) or len(report["runs"]) < 6 or report.get("speedup", 0) <= 1:
            raise ValueError("baseline benchmark measurement/speedup missing")
        if not SHA256.fullmatch(report.get("baselineExecutableSha256", "")) or not SHA256.fullmatch(report.get("candidateExecutableSha256", "")):
            raise ValueError("real compiled baseline/candidate hashes missing")
        if {r.get("implementation") for r in report["runs"]} != {"baseline", "candidate"}:
            raise ValueError("not a baseline vs candidate benchmark")


def verify_target(folder: Path, key: Ed25519PublicKey, commit: str, version: str):
    data = (folder / "attestation.json")
    sig = (folder / "attestation.sig")
    if data.is_symlink() or sig.is_symlink():
        raise ValueError("symlinked attestation not accepted")
    raw = data.read_bytes()
    signature = bytes.fromhex(sig.read_text("ascii").strip())
    key.verify(signature, DOMAIN + raw)
    doc = json.loads(raw)
    pair = (doc.get("platform"), doc.get("architecture"))
    if pair not in TARGETS or folder.name != "-".join(pair):
        raise ValueError(f"unexpected platform/architecture {pair}")
    if doc.get("schemaVersion") != "neverlauncher.ga.attestation.v1" or doc.get("status") != "passed":
        raise ValueError("unsupported or incomplete signed attestation")
    if doc.get("commit") != commit or doc.get("productVersion") != version:
        raise ValueError("attestation commit/version mismatch")
    if doc.get("gitTreeClean") is not True:
        raise ValueError("release must originate from clean source tree")
    checks = doc.get("checks")
    expected = COMMON_CHECKS | ({"windows-executable-lock"} if pair[0] == "windows" else set())
    if not isinstance(checks, dict) or any(checks.get(c) != "passed" for c in expected):
        raise ValueError(f"missing or failed required evidence checks: {sorted(expected)}")
    objects = doc.get("objects", {})
    if not isinstance(objects, dict) or set(objects) != {"installer", "osSignature", "cleanMachine", "certification", "benchmark"}:
        raise ValueError("exactly five attached artifact/proof objects required")
    proofs = {}
    for name, obj in objects.items():
        if not isinstance(obj, dict):
            raise ValueError(f"invalid {name} object")
        content = load_attested_file(folder, obj.get("file"), obj.get("sha256"))
        if name != "installer":
            check_report(content, commit=commit, version=version, subject=name)
            proofs[name] = json.loads(content)
    installer_sha = objects["installer"]["sha256"]
    if proofs["osSignature"].get("artifactSha256") != installer_sha or proofs["cleanMachine"].get("installerSha256") != installer_sha:
        raise ValueError("signature or clean-machine evidence describes a different installer")
    for name in ("osSignature", "cleanMachine"):
        if proofs[name].get("platform") != {"windows":"Windows", "linux":"Linux", "darwin":"Darwin"}[pair[0]]:
            raise ValueError(f"{name}: platform mismatch")
    return pair, {"attestationSha256": hashlib.sha256(raw).hexdigest(),
                  "installerSha256": objects["installer"]["sha256"],
                  "platform":pair[0], "architecture":pair[1], "status":"passed"}


def verify_all(root: Path, public_key_hex: str, commit: str, version="0.24.0") -> dict:
    if not GITSHA.fullmatch(commit):
        raise ValueError("exact 40-byte git commit is mandatory")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    results = []
    for platform, arch in sorted(TARGETS):
        folder = root / f"{platform}-{arch}"
        pair, result = verify_target(folder, key, commit, version)
        assert pair == (platform, arch)
        results.append(result)
    return {"schemaVersion":"neverlauncher.ga.release.v1", "productVersion":version,
            "commit":commit, "status":"passed", "artifacts":results}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attestations", type=Path, required=True)
    p.add_argument("--trusted-attestation-public-key", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        result = verify_all(args.attestations, args.trusted_attestation_public_key, args.commit)
    except (OSError, ValueError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
        result = {"productVersion":"0.24.0", "commit":args.commit, "status":"incomplete", "reason":str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(f"GA release gate: {result['status']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
