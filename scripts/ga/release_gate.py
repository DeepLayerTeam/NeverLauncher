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
COMPONENT_GA_DOMAIN = b"NeverLauncher-GA-0.25.0-optional-components-v1\n"
COMPONENT_GA_SCHEMA = "neverlauncher.ga.optional-components.v1"
COMPONENT_GA_CHECKS = {"signed-catalog", "dependency-conflicts", "condition-boundaries",
                       "signed-actions", "ownership-rollback", "selection-migration",
                       "gravit-import", "native-adversarial", "fault-injection",
                       "neverguard-live", "serverbridge-replay", "minecraft-real-launch"}
TARGETS = {(p, a) for p in ("windows", "linux", "darwin") for a in ("amd64", "arm64")}
COMMON_CHECKS = {"os-signature", "installer-clean-machine", "managed-java-real",
                 "minecraft-real-launch", "recovery-rollback", "powerloss-recovery",
                 "runtime-certification", "baseline-benchmark"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GITSHA = re.compile(r"^[a-f0-9]{40}$")


def strict_json(raw: bytes) -> dict:
    def reject_duplicates(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON field: {key}")
            obj[key] = value
        return obj
    doc = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(doc, dict):
        raise ValueError("evidence must be a JSON object")
    return doc


def load_attested_file(folder: Path, name: str, digest: str, *, binary: bool = False) -> bytes:
    """Only direct, ordinary files inside the target folder are eligible."""
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"unsafe artifact path: {name!r}")
    if not SHA256.fullmatch(digest):
        raise ValueError(f"invalid SHA-256 for {name}")
    path = folder / name
    if folder.is_symlink() or path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or symlinked file: {path}")
    hasher = hashlib.sha256()
    raw = bytearray()
    total = 0
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            total += len(chunk)
            if total > 4 * 1024 ** 3:
                raise ValueError(f"artifact exceeds maximum 4 GiB: {name}")
            hasher.update(chunk)
            # Installer binaries are hashed as a stream. JSON proof files must
            # remain small; never retain multi-gigabyte inputs in memory.
            if not binary:
                if len(raw) + len(chunk) > 8 * 1024 * 1024:
                    raise ValueError(f"oversized evidence JSON: {name}")
                raw.extend(chunk)
    if hasher.hexdigest() != digest:
        raise ValueError(f"content digest mismatch: {name}")
    return bytes(raw)


def check_report(data: bytes, *, commit: str, version: str, subject: str, target: str = "") -> None:
    report = strict_json(data)
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
    elif subject in ("nativeRun", "minecraftRun", "guardRun", "bridgeRun"):
        if report.get("target") != target or report.get("actualExecution") is not True:
            raise ValueError(f"{subject}: missing actual execution or platform binding")
        if subject == "nativeRun":
            if report.get("signedManifestVersion") != "3.0" or report.get("catalogSchema") != "5.0" or not isinstance(report.get("httpRequests"), int) or report["httpRequests"] <= 0:
                raise ValueError("native component runtime did not exercise verified HTTP install")
        elif subject == "minecraftRun":
            if report.get("actualClient") is not True or report.get("loader") not in ("vanilla", "fabric", "quilt", "forge", "neoforge"):
                raise ValueError("Minecraft JVM launch was not verified")
        elif subject == "guardRun":
            if report.get("kind") != "neverguard-live-attestation" or report.get("actualIntegration") is not True:
                raise ValueError("NeverGuard live integration was not verified")
        else:
            if report.get("kind") != "serverbridge-real-join-replay" or report.get("actualIntegration") is not True:
                raise ValueError("ServerBridge live join/replay tests were not verified")
    elif subject == "components":
        if version != "0.25.0" or report.get("schemaVersion") != "neverlauncher.components.certification.v1":
            raise ValueError("unsupported optional components certification schema")
        if report.get("target") != target or report.get("gitTreeClean") is not True:
            raise ValueError("optional components certification target/source mismatch")
        if report.get("signedManifestVersion") != "3.0" or report.get("catalogSchema") != "5.0":
            raise ValueError("optional components certification lacks signed v3/v5 catalogue")
        if report.get("actualMinecraftClient") is not True or report.get("actualGuardIntegration") is not True or report.get("actualBridgeIntegration") is not True:
            raise ValueError("actual Minecraft/Guard/Bridge evidence missing")
        checks = report.get("checks")
        if not isinstance(checks, dict) or any(checks.get(c) != "passed" for c in COMPONENT_GA_CHECKS):
            raise ValueError("optional components certification has skipped/failed gates")
        if not SHA256.fullmatch(report.get("nativeEvidenceSha256", "")):
            raise ValueError("native execution evidence digest missing")
        for section in ("minecraftEvidence", "guardEvidence", "bridgeEvidence"):
            reference = report.get(section)
            if not isinstance(reference, dict) or not SHA256.fullmatch(reference.get("sha256", "")) or reference.get("target") != target:
                raise ValueError(f"optional components {section} not bound to target")
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
    if len(raw) > 1024 * 1024:
        raise ValueError("oversized signed GA attestation")
    signature = bytes.fromhex(sig.read_text("ascii").strip())
    key.verify(signature, (COMPONENT_GA_DOMAIN if version == "0.25.0" else DOMAIN) + raw)
    doc = strict_json(raw)
    pair = (doc.get("platform"), doc.get("architecture"))
    if pair not in TARGETS or folder.name != "-".join(pair):
        raise ValueError(f"unexpected platform/architecture {pair}")
    schema = COMPONENT_GA_SCHEMA if version == "0.25.0" else "neverlauncher.ga.attestation.v1"
    if doc.get("schemaVersion") != schema or doc.get("status") != "passed":
        raise ValueError("unsupported or incomplete signed attestation")
    if doc.get("commit") != commit or doc.get("productVersion") != version:
        raise ValueError("attestation commit/version mismatch")
    if doc.get("gitTreeClean") is not True:
        raise ValueError("release must originate from clean source tree")
    checks = doc.get("checks")
    expected = COMMON_CHECKS | ({"windows-executable-lock"} if pair[0] == "windows" else set())
    if version == "0.25.0":
        expected |= {"component-graph", "signed-actions", "migration", "serverbridge-plan-evidence", "minecraft-component-launch"}
    if not isinstance(checks, dict) or any(checks.get(c) != "passed" for c in expected):
        raise ValueError(f"missing or failed required evidence checks: {sorted(expected)}")
    objects = doc.get("objects", {})
    required_objects = {"installer", "osSignature", "cleanMachine", "certification", "benchmark"}
    if version == "0.25.0":
        required_objects.update({"components", "nativeRun", "minecraftRun", "guardRun", "bridgeRun"})
    if not isinstance(objects, dict) or set(objects) != required_objects:
        raise ValueError(f"exactly {len(required_objects)} attached artifact/proof objects required")
    proofs = {}
    for name, obj in objects.items():
        if not isinstance(obj, dict):
            raise ValueError(f"invalid {name} object")
        content = load_attested_file(folder, obj.get("file"), obj.get("sha256"), binary=name == "installer")
        if name != "installer":
            check_report(content, commit=commit, version=version, subject=name, target=f"{pair[0]}-{pair[1]}")
            proofs[name] = strict_json(content)
    installer_sha = objects["installer"]["sha256"]
    if version == "0.25.0":
        components = proofs["components"]
        # The component report must describe this exact installer, not a previous
        # tested build of the same version or commit.
        if components.get("installerSha256") != installer_sha:
            raise ValueError("components certification belongs to another installer")
        if components["nativeEvidenceSha256"] != objects["nativeRun"]["sha256"]:
            raise ValueError("native run digest does not match authenticated evidence")
        for section, object_name in (("minecraftEvidence", "minecraftRun"),
                                     ("guardEvidence", "guardRun"),
                                     ("bridgeEvidence", "bridgeRun")):
            if components[section]["sha256"] != objects[object_name]["sha256"]:
                raise ValueError(f"{section}: authenticated evidence digest mismatch")
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
    if not re.fullmatch(r"[a-fA-F0-9]{64}", public_key_hex):
        raise ValueError("trusted attestation key must be 32 raw bytes in hex")
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
    p.add_argument("--version", default="0.24.0", choices=("0.24.0", "0.25.0"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        result = verify_all(args.attestations, args.trusted_attestation_public_key, args.commit, version=args.version)
    except (OSError, ValueError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
        result = {"productVersion":args.version, "commit":args.commit, "status":"incomplete", "reason":str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(f"GA release gate: {result['status']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
