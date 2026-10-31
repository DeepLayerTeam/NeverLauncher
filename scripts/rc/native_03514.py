#!/usr/bin/env python3
"""0.35.14 executable native acceptance, not a synthetic test result.

Uses the actual compiled Runtime and its fixture-only Ed25519 signer.
Performs signed HTTPS-independent localhost transport, transactional repair,
cache re-use, signature/fingerprint tampering and independently hashes files.
This is NOT a Minecraft launch or protected release attestation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import rc_extended
from certification_run import identity, CertificationBlocked

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "performance"))
from benchmark_03511 import (
    RepeatingRangeServer,
    file_entry,
    hash_file,
    isolated_env,
    manifest_base,
    repeating_hash,
    signed_manifest,
)


class RCBlocked(RuntimeError):
    pass


def require(value: bool, reason: str):
    if not value:
        raise RCBlocked(reason)


def process(
    executable: Path, *args: str, env=None, timeout=180
) -> tuple[int, dict | None]:
    try:
        cmd = subprocess.run(
            [str(executable), *map(str, args)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RCBlocked(
            f"actual native process could not execute: {type(exc).__name__}"
        ) from exc
    require(
        len(cmd.stdout) <= 2**20 and len(cmd.stderr) <= 2**20,
        "oversized native response",
    )
    try:
        obj = json.loads(cmd.stdout) if cmd.stdout else None
    except ValueError:
        obj = None
    return cmd.returncode, obj


def pass_native(result: tuple[int, dict | None], status: str = "ready"):
    code, response = result
    require(
        code == 0 and isinstance(response, dict) and response.get("status") == status,
        f"native operation did not return {status}",
    )
    return response


def reject_native(result: tuple[int, dict | None], message: str):
    code, response = result
    # Native errors may be nonzero or a structured status=invalid; both must
    # explicitly reject the request. A nonzero with ready is never acceptable.
    require(
        not (isinstance(response, dict) and response.get("status") == "ready"), message
    )
    require(
        code != 0
        or (isinstance(response, dict) and response.get("status") == "invalid"),
        message,
    )


def check_binary(path: Path) -> Path:
    require(
        path.is_file() and not path.is_symlink(),
        "native executable is absent or symlinked",
    )
    require(
        os.name == "nt" or os.access(path, os.X_OK),
        "native executable is not executable",
    )
    return path.resolve()


def execute(runtime: Path, signer: Path, version: str, commit: str) -> dict:
    runtime, signer = check_binary(runtime), check_binary(signer)
    require(rc_extended(version), "release candidate version mismatch")
    require(
        re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "missing exact source commit"
    )
    checkout = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(
        checkout.returncode == 0 and checkout.stdout.strip() == commit,
        "native tests do not match source checkout",
    )
    help_result = pass_native(process(runtime, "--help"))
    require(
        help_result.get("version") == version,
        "compiled runtime differs from canonical release version",
    )
    require(
        "sync-local" in help_result.get("commands", []),
        "real transactional sync command missing",
    )
    checks = ["binary-version-and-runtime-cli"]
    with tempfile.TemporaryDirectory(prefix="nl-rc-03514-") as tmp:
        work = Path(tmp)
        root = work / "installed"
        block = hashlib.shake_256(b"launcher-03514-native-e2e").digest(128 * 1024)
        size = len(block) * 4
        digest = repeating_hash(block, size)
        with RepeatingRangeServer(block, size) as network:
            manifest, pubkey = signed_manifest(
                signer,
                work,
                manifest_base(
                    [file_entry("libraries/rc/fixture.jar", size, digest, network.url)],
                    version=version,
                ),
            )
            require(
                hash_file(manifest) and len(pubkey) == 64,
                "real Ed25519 fixture signer failed",
            )
            env = isolated_env(work / "cache")
            before = network.transferred
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                    timeout=180,
                )
            )
            file = root / "libraries/rc/fixture.jar"
            require(
                file.is_file()
                and file.stat().st_size == size
                and hash_file(file) == digest,
                "native sync did not publish authenticated fixture bytes",
            )
            require(
                network.transferred - before >= size,
                "no real network bytes transferred",
            )
            checks.append("signed-transactional-http-download-and-independent-sha256")
            pass_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                )
            )
            checks.append("installed-signature-and-file-verification")
            before = network.transferred
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                )
            )
            require(
                network.transferred == before,
                "identical installed release triggered another download",
            )
            checks.append("warm-update-without-network-download")
            # Damage an installed file without touching its signed manifest.
            with file.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"TAMPERED-03514")
                handle.flush()
                os.fsync(handle.fileno())
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                ),
                "corrupt installed file considered ready",
            )
            checks.append("corrupt-file-rejected-by-native-verifier")
            pass_native(
                process(
                    runtime,
                    "sync-local",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                    timeout=180,
                )
            )
            require(
                hash_file(file) == digest, "native repair did not restore correct bytes"
            )
            checks.append("real-transactional-repair-and-independent-sha256")
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    manifest,
                    "--root",
                    root,
                    "--pinned-public-key",
                    "00" * 32,
                    env=env,
                ),
                "wrong pinned Ed25519 key accepted",
            )
            checks.append("wrong-trust-root-denied")
            altered = work / "altered-manifest.json"
            doc = json.loads(manifest.read_text(encoding="utf-8"))
            doc["version"] = "forged-without-resigning"
            altered.write_text(json.dumps(doc), encoding="utf-8")
            reject_native(
                process(
                    runtime,
                    "verify",
                    "--manifest",
                    altered,
                    "--root",
                    root,
                    "--pinned-public-key",
                    pubkey,
                    env=env,
                ),
                "modified signed payload accepted",
            )
            checks.append("modified-signed-manifest-denied")
            return {
                "schemaVersion": "launcher.rc.native.v1",
                "version": version,
                "status": "passed",
                "simulated": False,
                "commit": commit,
                "platform": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "runtimeSha256": hash_file(runtime),
                "signerSha256": hash_file(signer),
                "signedFixtureSha256": hash_file(manifest),
                "fixtureBytes": size,
                "checks": checks,
                "certificationScope": "real native signed sync, verify, repair, rejection only; not Minecraft/GUI E2E",
                "timestampUtc": datetime.now(timezone.utc).isoformat(),
                "certificationRun": identity(version, commit, root=ROOT),
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    args.output.unlink(
        missing_ok=True
    )  # stale PASSED artifact must not survive a failed rerun
    try:
        result = execute(args.runtime, args.signer, version, args.commit)
    except (RCBlocked, ValueError, OSError, RuntimeError, CertificationBlocked) as exc:
        print("Native RC blocked: " + str(exc), file=sys.stderr)
        return 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name("." + args.output.name + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8") as f:
            os.chmod(tmp, 0o600)
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, args.output)
    finally:
        tmp.unlink(missing_ok=True)
    print(
        f"Native 0.35.14 RC: {len(result['checks'])} real checks passed ({result['platform']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
