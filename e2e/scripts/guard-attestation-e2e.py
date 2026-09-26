#!/usr/bin/env python3
"""Build a valid Linux NeverGuard attestation for the PostgreSQL protocol E2E.

This is a protocol fixture, not a provenance claim: the backend still verifies
challenge freshness, the P-256 device signature, exact allowlisted Guard/Desktop
hash pair, process-boundary fields, evidence/attestation digests and one-time
launch-ticket consumption.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time

GUARD_HASH = "a" * 64
LAUNCHER_HASH = "b" * 64
GUARD_MODULES = "6" * 64
LAUNCHER_MODULES = "7" * 64
EVIDENCE_SESSION_PROOF = "8" * 64
ATTESTATION_SESSION_PROOF = "9" * 64


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def process(pid: int, image_hash: str, module_hash: str, parent_death_signal: bool) -> dict:
    return {
        "pid": pid,
        "imagePath": "/opt/neverlauncher/e2e-binary",
        "imageSha256": image_hash,
        "imageSize": 2048,
        "imageModifiedUnixMs": 2000,
        "processCreatedFiletime": 12345,
        "authenticode": {"trusted": False, "status": "not-applicable-linux"},
        "mitigations": {
            "dep": None,
            "aslr": None,
            "dynamicCode": None,
            "extensionPointDisable": None,
            "controlFlowGuard": None,
            "binarySignature": None,
            "imageLoad": None,
            "childProcess": None,
            "userShadowStack": None,
            "sehop": None,
            "queryFailures": [],
        },
        "modules": {
            "moduleCount": 3,
            "moduleSetSha256": module_hash,
            "nonSystemModuleNames": [],
        },
        "linux": {
            "uid": 1000,
            "gid": 1000,
            "noNewPrivs": True,
            "seccompMode": 2,
            "dumpableDisabled": True,
            "parentDeathSignal": parent_death_signal,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in ("challenge-id", "challenge", "challenge-expires-at", "launcher-version", "user-id", "device-id", "session-id", "binding-epoch", "fingerprint"):
        ap.add_argument(f"--{name}", required=True)
    a = ap.parse_args()

    now = int(time.time())
    evidence_core = {
        "schema": "neverguard/linux-integrity-evidence/v1",
        "evidenceVersion": 1,
        "evidenceId": "b" * 32,
        "collectedAtUnix": now,
        "boundary": {"expectedParentPid": 200, "observedParentPid": 200, "parentMatches": True},
        "guard": process(201, GUARD_HASH, GUARD_MODULES, True),
        "launcher": process(200, LAUNCHER_HASH, LAUNCHER_MODULES, False),
    }
    evidence_sha = hashlib.sha256(compact(evidence_core)).hexdigest()
    evidence = dict(evidence_core)
    evidence["evidenceSha256"] = evidence_sha
    evidence["sessionProof"] = EVIDENCE_SESSION_PROOF

    process_policy = {
        "schema": "neverguard/linux-runtime-process-policy/v1",
        "policyVersion": 1,
        "pid": 201,
        "enforced": True,
        "dynamicCodeProhibited": False,
        "extensionPointsDisabled": False,
        "strictHandleChecks": False,
        "remoteImagesBlocked": False,
        "lowMandatoryLabelImagesBlocked": False,
        "preferSystem32Images": False,
        "childProcessCreationBlocked": False,
        "linux": {
            "noNewPrivs": True,
            "dumpableDisabled": True,
            "coreDumpsDisabled": True,
            "ptraceRestricted": True,
            "parentDeathSignal": True,
            "privateUmask": True,
        },
    }
    challenge_sha = hashlib.sha256(a.challenge.encode("utf-8")).hexdigest()
    attestation = {
        "schema": "neverguard/linux-guard-attestation/v1",
        "attestationVersion": 1,
        "challengeId": a.challenge_id,
        "challengeSha256": challenge_sha,
        "collectedAtUnix": now,
        "evidence": evidence,
        "processPolicy": process_policy,
        "attestationSha256": "",
        "sessionProof": ATTESTATION_SESSION_PROOF,
    }
    linux = process_policy["linux"]
    core_payload = (
        "NeverLauncher Guard Attestation Core Linux v1\n"
        f"challenge-id={a.challenge_id}\n"
        f"challenge-sha256={challenge_sha}\n"
        f"evidence-id={evidence['evidenceId']}\n"
        f"evidence-sha256={evidence_sha}\n"
        f"guard-sha256={GUARD_HASH}\n"
        f"launcher-sha256={LAUNCHER_HASH}\n"
        f"guard-module-set-sha256={GUARD_MODULES}\n"
        f"launcher-module-set-sha256={LAUNCHER_MODULES}\n"
        "process-policy-version=1\n"
        "process-policy-enforced=true\n"
        f"no-new-privs={str(linux['noNewPrivs']).lower()}\n"
        f"dumpable-disabled={str(linux['dumpableDisabled']).lower()}\n"
        f"core-dumps-disabled={str(linux['coreDumpsDisabled']).lower()}\n"
        f"ptrace-restricted={str(linux['ptraceRestricted']).lower()}\n"
        f"parent-death-signal={str(linux['parentDeathSignal']).lower()}\n"
        f"private-umask={str(linux['privateUmask']).lower()}\n"
        f"collected-at={now}\n"
    )
    attestation_sha = hashlib.sha256(core_payload.encode("utf-8")).hexdigest()
    attestation["attestationSha256"] = attestation_sha

    signing_payload = (
        "NeverLauncher Guard Attestation Device Binding v1\n"
        "purpose=guard-attest\n"
        f"challenge={a.challenge.strip()}\n"
        f"challenge-id={a.challenge_id.strip()}\n"
        f"user={a.user_id.strip()}\n"
        f"device={a.device_id.strip()}\n"
        f"session={a.session_id.strip()}\n"
        f"binding-epoch={a.binding_epoch.strip()}\n"
        f"launcher-version={a.launcher_version.strip()}\n"
        f"fingerprint={a.fingerprint.strip()}\n"
        f"attestation-sha256={attestation_sha}\n"
        f"evidence-sha256={evidence_sha}\n"
        f"guard-sha256={GUARD_HASH}\n"
        f"launcher-sha256={LAUNCHER_HASH}\n"
        f"challenge-expires-at={a.challenge_expires_at.strip()}\n"
    )
    print(json.dumps({"attestation": attestation, "signingPayload": signing_payload}, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
