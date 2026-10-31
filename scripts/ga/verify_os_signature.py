#!/usr/bin/env python3
"""Verify the actual platform signature of a distribution installer.

Must run on the package's native OS with an externally pinned publisher identity.
No unsigned test mode; a matching digest alone is not a signature check.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def execute(cmd, timeout=90, env=None):
    r = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env
    )
    if r.returncode:
        raise ValueError(
            f"{cmd[0]} signature check rejected artifact: {(r.stdout + r.stderr)[-700:]}"
        )
    return r.stdout + r.stderr


def verify(path: Path, signer: str):
    if not path.is_file() or path.is_symlink():
        raise ValueError("installer missing or symlinked")
    system = platform.system()
    if system == "Windows":
        # Powershell verifies the Authenticode trust chain and signer certificate.
        # SIGNS may be timestamped; the OS remains the certificate-chain authority.
        if not re.fullmatch("[0-9A-Fa-f]{40}", signer):
            raise ValueError("expected 40-hex Authenticode certificate thumbprint")
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath $env:NL_GA_INSTALLER; "
            'if ($s.Status -ne "Valid" -or $null -eq $s.SignerCertificate '
            "-or $s.SignerCertificate.Thumbprint -ne $env:NL_GA_SIGNER) { exit 11 }"
        )
        env = dict(
            os.environ, NL_GA_INSTALLER=str(path.resolve()), NL_GA_SIGNER=signer.upper()
        )
        execute(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script], env=env
        )
    elif system == "Darwin":
        if not re.fullmatch("[A-Z0-9]{10}", signer):
            raise ValueError("expected Apple Developer Team ID")
        checked = execute(["pkgutil", "--check-signature", str(path.resolve())])
        if f"({signer})" not in checked or "Developer ID Installer:" not in checked:
            raise ValueError(
                "macOS package is not signed by the pinned Developer ID Installer"
            )
        execute(
            [
                "spctl",
                "--assess",
                "--type",
                "install",
                "--verbose=2",
                str(path.resolve()),
            ]
        )
    elif system == "Linux":
        if not re.fullmatch("[0-9A-Fa-f]{40}", signer):
            raise ValueError("expected GPG fingerprint")
        # Pinned public key is imported by protected CI into a dedicated keyring;
        # a generic system keyring accepting any signer is not sufficient.
        keyring = os.environ.get("LAUNCHER_GA_GPG_KEYRING")
        if not keyring or not Path(keyring).is_file():
            raise ValueError("isolated trusted GPG keyring required")
        asc = Path(str(path) + ".asc")
        if not asc.is_file() or asc.is_symlink():
            raise ValueError("missing detached Linux package signature")
        result = execute(
            [
                "gpg",
                "--batch",
                "--no-default-keyring",
                "--keyring",
                keyring,
                "--status-fd",
                "1",
                "--verify",
                str(asc),
                str(path),
            ]
        )
        if not any(
            line.startswith("[GNUPG:] VALIDSIG " + signer.upper() + " ")
            for line in result.splitlines()
        ):
            raise ValueError("detached signature signer fingerprint mismatch")
    else:
        raise ValueError("unsupported native signing platform")
    return {
        "status": "passed",
        "signatureVerified": True,
        "platform": system,
        "trustedSigner": signer.upper(),
        "artifactSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installer", type=Path, required=True)
    p.add_argument("--expected-signer", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        if not re.fullmatch("[0-9a-f]{40}", args.commit):
            raise ValueError("exact git commit required")
        report = verify(args.installer, args.expected_signer)
        report.update(productVersion="0.24.0", commit=args.commit)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        report = {
            "status": "failed",
            "productVersion": "0.24.0",
            "commit": args.commit,
            "error": str(exc),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("native OS signature:", report["status"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
