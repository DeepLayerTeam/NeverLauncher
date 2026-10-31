#!/usr/bin/env python3
"""Verify final six-platform packages against independently signed GA approval.

`certify` executes BEFORE release manifest signing. `dry-run` copies the signed
release to an isolated publication directory and invokes the real CLI publish
validator on the copied files; neither action uploads or promotes a release.
"""

from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ga"))
from verified_targets import Blocked, TARGETS, paths, sha, verify, require
from release_policy import requires_rehearsal

SCHEMA = "launcher.release.rehearsal.v1"
SHA = re.compile("[a-f0-9]{64}\\Z")
MAX_ENTRIES = 25000
MAX_UNCOMPRESSED = 4 * 1024**3


def architecture(content: bytes, target: str) -> None:
    system, arch = target.split("-")
    if system == "windows":
        require(
            len(content) >= 0x40 and content[:2] == b"MZ", "not a Windows executable"
        )
        offset = struct.unpack_from("<I", content, 0x3C)[0]
        require(
            offset >= 0x40
            and offset + 24 <= len(content)
            and content[offset : offset + 4] == b"PE\0\0",
            "bad PE header",
        )
        actual = struct.unpack_from("<H", content, offset + 4)[0]
        require(
            actual == {"x64": 0x8664, "arm64": 0xAA64}[arch], "wrong PE architecture"
        )
        # IMAGE_DIRECTORY_ENTRY_SECURITY contains the Authenticode certificate table.
        # Its presence is NOT a chain-of-trust verification: the native Windows
        # signer/OS checks this and signs its result in the independent GA traces.
        opt = offset + 24
        magic = struct.unpack_from("<H", content, opt)[0]
        require(magic == 0x20B and opt + 144 <= len(content), "PE32+ required")
        cert_offset, cert_size = struct.unpack_from("<II", content, opt + 112 + 4 * 8)
        require(
            cert_offset > 0
            and cert_size >= 8
            and cert_offset + cert_size <= len(content),
            "missing Authenticode certificate table",
        )
    elif system == "linux":
        require(
            len(content) >= 20 and content[:6] == b"\x7fELF\x02\x01",
            "ELF64 little endian required",
        )
        require(
            struct.unpack_from("<H", content, 18)[0] == {"x64": 62, "arm64": 183}[arch],
            "wrong ELF architecture",
        )
    else:
        require(
            len(content) >= 32 and content[:4] == b"\xcf\xfa\xed\xfe",
            "Mach-O 64-bit required",
        )
        require(
            struct.unpack_from("<I", content, 4)[0]
            == {"x64": 0x01000007, "arm64": 0x0100000C}[arch],
            "wrong Mach-O architecture",
        )
        ncmds = struct.unpack_from("<I", content, 16)[0]
        size = struct.unpack_from("<I", content, 20)[0]
        require(0 < ncmds <= 200 and 32 + size <= len(content), "bad Mach-O commands")
        cursor = 32
        signed = False
        for _ in range(ncmds):
            require(cursor + 8 <= 32 + size, "bad Mach-O command size")
            cmd, length = struct.unpack_from("<II", content, cursor)
            require(
                length >= 8 and cursor + length <= 32 + size, "truncated Mach-O command"
            )
            if cmd == 0x1D:
                require(length >= 16, "truncated code-signing command")
                off, length_sig = struct.unpack_from("<II", content, cursor + 8)
                require(
                    off > 0 and length_sig > 0 and off + length_sig <= len(content),
                    "invalid Mach-O code signature",
                )
                signed = True
            cursor += length
        require(signed, "macOS code signature absent")


def safe_members(members: dict[str, bytes]) -> None:
    require(
        len(members) <= MAX_ENTRIES
        and sum(map(len, members.values())) <= MAX_UNCOMPRESSED,
        "archive size/entry limit",
    )
    seen = set()
    for name in members:
        path = PurePosixPath(name)
        require(
            name not in seen
            and not name.startswith("/")
            and "\\" not in name
            and all(x not in ("", ".", "..") for x in name.split("/"))
            and not path.is_absolute(),
            "duplicate or unsafe archive member: " + name,
        )
        seen.add(name)


def unpack(path: Path) -> dict[str, bytes]:
    result = {}
    total = 0
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for meta in archive.infolist():
                if meta.is_dir():
                    continue
                mode = (meta.external_attr >> 16) & 0o170000
                require(
                    mode != 0o120000 and not meta.flag_bits & 1,
                    "archive symlink/encrypted entry",
                )
                require(
                    meta.filename not in result and meta.file_size <= MAX_UNCOMPRESSED,
                    "archive duplicate or oversized member",
                )
                total += meta.file_size
                require(
                    total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES,
                    "archive expansion limit",
                )
                result[meta.filename] = archive.read(meta)
    else:
        require(path.name.endswith(".tar.gz"), "unsupported installer format")
        with tarfile.open(path, mode="r:gz") as archive:
            for meta in archive:
                if meta.isdir():
                    continue
                require(meta.isfile() and meta.name not in result, "unsafe TAR member")
                total += meta.size
                require(
                    total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES,
                    "TAR expansion limit",
                )
                reader = archive.extractfile(meta)
                require(reader is not None, "unreadable TAR member")
                result[meta.name] = reader.read()
    safe_members(result)
    return result


def verify_update_payload_0410(
    members: dict[str, bytes], manifest: dict, system: str, arch: str, version: str
) -> None:
    """Check that the *shipped* component updater can consume this exact installer.

    A successfully signed installer with a stale component update manifest cannot
    be repaired or rolled back safely. The outer GA signature binds the package;
    this independently verifies the inner install/update byte graph.
    """
    prefix = {"windows": "", "linux": "launcher/", "darwin": "Launcher.app/"}[system]
    manifest_member = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_UPDATE_MANIFEST.json"
    )
    require(
        manifest_member in members,
        "missing installed component update manifest: " + manifest_member,
    )
    update_bytes = members[manifest_member]
    update = json.loads(update_bytes, object_pairs_hook=_no_dupes)
    require(
        isinstance(update, dict)
        and update.get("schemaVersion") == "1.0"
        and update.get("product") == "Launcher"
        and update.get("productVersion") == version
        and update.get("architecture") == arch
        and update.get("platform") == {"darwin": "macos"}.get(system, system),
        "installed component update manifest identity mismatch",
    )
    require(
        update.get("layout")
        == ("macos-app-bundle" if system == "darwin" else "adjacent-files"),
        "installed component update layout mismatch",
    )
    expected_roles = {
        "desktop": "desktop-launcher",
        "guard": "guard",
        "runtime": "runtime",
    }
    if system == "windows":
        expected_roles["sensor"] = "sensor"
    expected_support = {"updater": "cli"}
    if system != "darwin":
        expected_support["package-manifest"] = "package-manifest"

    package_rows = {}
    for row in manifest["artifacts"]:
        require(isinstance(row, dict), "invalid installer artifact entry")
        source = (
            row.get("packagePath")
            if system == "linux"
            else row.get("bundlePath")
            if system == "darwin"
            else row.get("name")
        )
        require(
            isinstance(source, str) and source not in package_rows,
            "duplicate or invalid installer artifact path",
        )
        package_rows[source] = row

    def check_rows(rows: object, expected: dict[str, str], label: str) -> None:
        require(
            isinstance(rows, list) and len(rows) == len(expected),
            "missing or unexpected installed " + label,
        )
        roles = set()
        for entry in rows:
            require(isinstance(entry, dict), "invalid installed component entry")
            role = entry.get("component")
            require(
                isinstance(role, str) and role in expected and role not in roles,
                "duplicate or unexpected installed component: " + str(role),
            )
            roles.add(role)
            src = entry.get("sourcePath")
            dest = entry.get("targetPath")
            require(
                isinstance(src, str)
                and src
                and src == dest
                and not src.startswith("/")
                and "\\" not in src
                and all(part not in ("", ".", "..") for part in src.split("/")),
                "unsafe installed update path for " + role,
            )
            actual_member = prefix + src
            require(
                actual_member in members
                and isinstance(entry.get("sha256"), str)
                and SHA.fullmatch(entry["sha256"]) is not None
                and type(entry.get("size")) is int
                and entry["size"] > 0
                and entry.get("executable") is (role != "package-manifest")
                and len(members[actual_member]) == entry["size"]
                and hashlib.sha256(members[actual_member]).hexdigest()
                == entry["sha256"],
                "installed update component bytes differ: " + role,
            )
            if role == "package-manifest":
                expected_path = ("launcher/" if system == "linux" else "") + (
                    "LINUX_PACKAGE_MANIFEST.json"
                    if system == "linux"
                    else "WINDOWS_PACKAGE_MANIFEST.json"
                )
                require(
                    actual_member == expected_path,
                    "component update package manifest path mismatch",
                )
            else:
                matching = [
                    row
                    for path, row in package_rows.items()
                    if path == actual_member and row.get("component") == expected[role]
                ]
                require(
                    len(matching) == 1
                    and matching[0].get("sha256") == entry["sha256"]
                    and matching[0].get("size") == entry["size"],
                    "installer and updater component mapping differ: " + role,
                )

    check_rows(update.get("components"), expected_roles, "components")
    check_rows(update.get("supportFiles"), expected_support, "support files")
    # Signatures are verified by the updater's pinned trust policy, not by
    # trusting public keys transported inside the package. Require the sidecar
    # to bind exactly the same bytes that are installed, without treating this
    # hash consistency check as independent signature verification.
    signature_path = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_SET_SIGNATURE.json"
    )
    require(signature_path in members, "missing installed component-set signature")
    signature = json.loads(members[signature_path], object_pairs_hook=_no_dupes)
    require(
        isinstance(signature, dict)
        and signature.get("schemaVersion") == "1.0"
        and signature.get("algorithm") == "ed25519"
        and signature.get("manifestSha256") == hashlib.sha256(update_bytes).hexdigest()
        and isinstance(signature.get("signature"), str)
        and re.fullmatch("[a-f0-9]{128}", signature["signature"]) is not None,
        "component set signature does not bind installed update manifest",
    )
    v2_path = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_SET_SIGNATURE_V2.json"
    )
    require(v2_path in members, "missing installed delegated component-set signature")
    v2 = json.loads(members[v2_path], object_pairs_hook=_no_dupes)
    require(
        isinstance(v2, dict)
        and v2.get("schemaVersion") == "2.0"
        and v2.get("algorithm") == "ed25519"
        and v2.get("manifestSha256") == hashlib.sha256(update_bytes).hexdigest()
        and isinstance(v2.get("signature"), str)
        and re.fullmatch("[a-f0-9]{128}", v2["signature"]) is not None,
        "delegated component signature does not bind installed update manifest",
    )
    trust_policy = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_TRUST_POLICY.json"
    )
    require(
        trust_policy in members and 0 < len(members[trust_policy]) <= 128 * 1024,
        "missing installed delegated component trust policy",
    )
    # Verify both Ed25519 signatures using trust roots provided independently
    # by the release operator. Never take a public trust key from the ZIP.
    component_root = os.environ.get(
        "LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY", ""
    ).strip()
    delegation_root = os.environ.get(
        "LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY", ""
    ).strip()
    require(
        re.fullmatch("[0-9a-fA-F]{64}", component_root) is not None
        and re.fullmatch("[0-9a-fA-F]{64}", delegation_root) is not None,
        "release trusted component public keys are missing",
    )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(component_root)).verify(
            bytes.fromhex(signature["signature"]), update_bytes
        )
        envelope = json.loads(members[trust_policy], object_pairs_hook=_no_dupes)
        require(
            isinstance(envelope, dict) and envelope.get("schemaVersion") == "1.0",
            "invalid root-signed component trust policy envelope",
        )
        payload = base64.b64decode(envelope["payload"], validate=True)
        require(
            0 < len(payload) <= 128 * 1024
            and re.fullmatch("[0-9a-fA-F]{128}", envelope.get("rootSignature", ""))
            is not None,
            "invalid component trust policy payload/signature",
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(delegation_root)).verify(
            bytes.fromhex(envelope["rootSignature"]),
            b"Launcher-Trust-Policy-v1\n" + payload,
        )
        delegated_policy = json.loads(payload, object_pairs_hook=_no_dupes)
        require(
            isinstance(delegated_policy, dict)
            and delegated_policy.get("schemaVersion") == "1.0"
            and delegated_policy.get("domain") == "launcher.trust.v1"
            and type(delegated_policy.get("epoch")) is int
            and delegated_policy["epoch"] > 0
            and v2.get("trustEpoch") == delegated_policy["epoch"]
            and v2.get("policySha256") == hashlib.sha256(payload).hexdigest(),
            "component trust policy epoch or identity mismatch",
        )

        def date(value: str) -> datetime:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )

        current = datetime.now(timezone.utc)
        require(
            date(delegated_policy["issuedAt"])
            <= current
            < date(delegated_policy["expiresAt"]),
            "component trust policy is expired or not yet valid",
        )
        require(
            date(v2["signedAt"]) <= current
            and date(delegated_policy["issuedAt"])
            <= date(v2["signedAt"])
            < date(delegated_policy["expiresAt"]),
            "component delegated signature is not within policy validity",
        )
        matching = [
            key
            for key in delegated_policy.get("keys", [])
            if isinstance(key, dict)
            and key.get("id") == v2.get("keyId")
            and key.get("role") == "component"
            and key.get("status") == "active"
            and date(key["notBefore"]) <= date(v2["signedAt"])
            and isinstance(key.get("publicKey"), str)
            and re.fullmatch("[a-fA-F0-9]{64}", key["publicKey"]) is not None
        ]
        require(
            len(matching) == 1,
            "no independently trusted active delegated component key",
        )
        context = (
            "Launcher-Component-v2\n"
            + v2["keyId"]
            + "\n"
            + str(v2["trustEpoch"])
            + "\n"
            + v2["policySha256"]
            + "\n"
            + v2["manifestSha256"]
            + "\n"
            + v2["signedAt"]
            + "\n"
        ).encode()
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(matching[0]["publicKey"])
        ).verify(bytes.fromhex(v2["signature"]), context + update_bytes)
    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        base64.binascii.Error,
    ) as exc:
        raise Blocked(
            "installed component-set cryptographic trust verification failed"
        ) from exc


def exact_package(bundle: Path, version: str, target: str) -> dict:
    system, arch = target.split("-")
    binary_name, package_name = paths(version, target)
    binary = bundle / binary_name
    package = bundle / package_name
    architecture(binary.read_bytes(), target)
    members = unpack(package)
    if system == "windows":
        manifest_name = f"WINDOWS_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "WINDOWS_PACKAGE_MANIFEST.json"
        member = "launcher-desktop.exe"
    elif system == "linux":
        manifest_name = f"LINUX_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "launcher/LINUX_PACKAGE_MANIFEST.json"
        member = "launcher/launcher-desktop"
    else:
        manifest_name = f"MACOS_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "Launcher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json"
        member = "Launcher.app/Contents/MacOS/launcher-desktop"
    require(
        inner in members and member in members,
        target + ": missing packaged desktop/manifest",
    )
    # On macOS the .app's embedded manifest is sealed by codesign before the
    # final notarized bytes are copied back to the root manifest. Therefore
    # compare its identity but use the finalized top-level hash manifest to
    # verify the exact ZIP payload, never demand equal pre-/post-sign hashes.
    if system == "darwin":
        embedded = json.loads(members[inner], object_pairs_hook=_no_dupes)
        require(
            embedded.get("productVersion") == version
            and embedded.get("architecture") == arch,
            target + ": embedded macOS manifest identity mismatch",
        )
        manifest = json.loads(
            (bundle / manifest_name).read_bytes(), object_pairs_hook=_no_dupes
        )
    else:
        require(
            sha(bundle / manifest_name) == hashlib.sha256(members[inner]).hexdigest(),
            target + ": embedded package manifest differs from signed source",
        )
        manifest = json.loads(members[inner], object_pairs_hook=_no_dupes)
    require(
        manifest.get("productVersion") == version
        and manifest.get("architecture") == arch
        and isinstance(manifest.get("artifacts"), list),
        target + ": package manifest version/architecture mismatch",
    )
    require(
        hashlib.sha256(members[member]).hexdigest() == sha(binary),
        target + ": packaged executable differs from approved binary",
    )
    seen = set()
    for row in manifest["artifacts"]:
        name = (
            row.get("packagePath")
            if system == "linux"
            else (row.get("bundlePath") if system == "darwin" else row.get("name"))
        )
        require(
            isinstance(name, str)
            and name in members
            and name not in seen
            and isinstance(row.get("sha256"), str)
            and SHA.fullmatch(row["sha256"]) is not None
            and row.get("size") == len(members[name])
            and hashlib.sha256(members[name]).hexdigest() == row["sha256"],
            target + ": missing/altered package component: " + str(name),
        )
        seen.add(name)
        if row.get("component") == "desktop-launcher":
            require(name == member, target + ": unexpected desktop component mapping")
        if row.get("component") in ("desktop-launcher", "runtime", "guard", "cli"):
            architecture(members[name], target)
        if system == "windows":
            require(
                row.get("authenticodeStatus") == "Valid"
                and row.get("timestamped") is True
                and row.get("signtoolVerified") is True
                and re.fullmatch(
                    r"[a-fA-F0-9]{40}", str(row.get("signerThumbprint", ""))
                )
                is not None,
                target + ": native Authenticode signing evidence missing",
            )
        if system == "darwin":
            require(
                row.get("codeSigned") is True
                and row.get("hardenedRuntime") is True
                and re.fullmatch("[A-Z0-9]{10}", str(row.get("teamId", "")))
                is not None,
                target + ": native code-signing evidence missing",
            )
    require(
        member in seen and len(seen) >= 4, target + ": incomplete production package"
    )
    if tuple(int(v) for v in version.split(".")[:3]) >= (0, 41, 0):
        verify_update_payload_0410(members, manifest, system, arch, version)
    if system in ("linux", "windows"):
        require(
            (
                "launcher/COMPONENT_SET_SIGNATURE.json"
                if system == "linux"
                else "COMPONENT_SET_SIGNATURE.json"
            )
            in members,
            target + ": missing component set signature",
        )
    return {
        "target": target,
        "binary": binary_name,
        "binarySha256": sha(binary),
        "package": package_name,
        "packageSha256": sha(package),
        "packageMembers": len(members),
    }


def _no_dupes(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON field " + key)
        obj[key] = value
    return obj


def current_run() -> tuple[str, str]:
    run_id = os.environ.get("LAUNCHER_RELEASE_RUN_ID") or os.environ.get(
        "GITHUB_RUN_ID", ""
    )
    attempt = os.environ.get("LAUNCHER_RELEASE_RUN_ATTEMPT") or os.environ.get(
        "GITHUB_RUN_ATTEMPT", ""
    )
    require(
        re.fullmatch(r"[1-9][0-9]{0,29}", run_id) is not None
        and re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is not None,
        "production rehearsal requires the exact CI run ID and attempt",
    )
    return run_id, attempt


def certify(bundle: Path, evidence: Path, key: Path, version: str, commit: str) -> dict:
    run_id, run_attempt = current_run()
    receipt = verify(bundle, evidence, key, version, commit)
    require(requires_rehearsal(version), "rehearsal requires 0.36.5 or newer")
    allowed = {name for target in TARGETS for name in paths(version, target)}
    allowed.update(
        {
            f"launcher-desktop-{version}-windows-amd64.zip",
            f"launcher-desktop-{version}-macos-universal.zip",
            "launcher-desktop-windows-amd64.exe",
            "launcher-desktop-linux-amd64",
            "launcher-desktop-macos-universal",
        }
    )
    for entry in bundle.iterdir():
        name = entry.name
        target_shaped = name.startswith(
            (
                "launcher-desktop-windows-",
                "launcher-desktop-linux-",
                "launcher-desktop-macos-",
            )
        ) or name.startswith(
            (
                f"launcher-desktop-{version}-windows-",
                f"launcher-desktop-{version}-macos-",
                f"launcher-desktop-{version}-linux-",
                "launcher-linux-",
            )
        )
        if target_shaped and name not in allowed:
            raise Blocked("unapproved extra platform target: " + name)
    rows = [exact_package(bundle, version, target) for target in sorted(TARGETS)]
    require(
        [(r["target"], r["binarySha256"], r["packageSha256"]) for r in rows]
        == [
            (r["target"], r["binarySha256"], r["packageSha256"])
            for r in receipt["targets"]
        ],
        "rehearsal records are not the signed GA target set",
    )
    return {
        "schemaVersion": SCHEMA,
        "version": version,
        "commit": commit,
        "runId": run_id,
        "runAttempt": run_attempt,
        "status": "package-and-ga-verified",
        "gaApprovalSha256": receipt["approvalSha256"],
        "targets": rows,
    }


def dry_run(
    bundle: Path,
    cli: Path,
    public_key: Path,
    trust_policy: Path,
    trust_state: Path,
    evidence: Path,
    key: Path,
    version: str,
    commit: str,
    stage: Path,
) -> dict:
    require(
        stage.resolve() != bundle.resolve() and not stage.exists(),
        "dry-run staging must be a fresh distinct directory",
    )
    receipt = certify(bundle, evidence, key, version, commit)
    report = json.loads(
        (bundle / "RELEASE_REHEARSAL_0365.json").read_bytes(),
        object_pairs_hook=_no_dupes,
    )
    require(
        report == receipt, "signed release rehearsal receipt is stale or mismatched"
    )
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    expected = {}
    for line in sums.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        require(
            len(fields) == 2
            and SHA.fullmatch(fields[0]) is not None
            and fields[1] not in expected
            and "/" not in fields[1]
            and "\\" not in fields[1],
            "invalid SHA256SUMS entry",
        )
        expected[fields[1]] = fields[0]
    files = [p for p in bundle.iterdir() if p.is_file() and not p.is_symlink()]
    require(
        set(expected) == {p.name for p in files} - {"SHA256SUMS", "SHA256SUMS.sig"},
        "missing/unsigned/extra final release file",
    )
    # Never use a shared/production trust-state as writable dry-run state.
    independent_trust_state = stage.parent / (stage.name + "-trust-state.json")
    if trust_state.is_file():
        shutil.copy2(trust_state, independent_trust_state)
    stage.mkdir(parents=True)
    try:
        for source in files:
            target = stage / source.name
            with source.open("rb") as read, target.open("xb") as write:
                shutil.copyfileobj(read, write, 1024 * 1024)
            require(
                sha(target) == sha(source),
                "dry-run transport changed bytes " + source.name,
            )
            if source.name in expected:
                require(
                    sha(target) == expected[source.name],
                    "SHA256SUMS mismatch " + source.name,
                )
        copied_cli = stage / cli.name
        require(copied_cli.is_file(), "publication dry-run is missing its release CLI")
        copied_cli.chmod(cli.stat().st_mode & 0o777)
        argv = [
            str(copied_cli.resolve()),
            "release",
            "publish-check",
            str(stage),
            "--public-key",
            str(public_key.resolve()),
            "--trust-state",
            str(independent_trust_state.resolve()),
            "--trust-policy",
            str(trust_policy.resolve()),
        ]
        finished = subprocess.run(argv, capture_output=True, text=True, timeout=240)
        require(
            finished.returncode == 0,
            "staged release publish-check refused: "
            + (finished.stderr or finished.stdout)[-900:],
        )
        return {
            "schemaVersion": "launcher.release.publication-dry-run.v1",
            "version": version,
            "commit": commit,
            "status": "passed",
            "runId": receipt["runId"],
            "runAttempt": receipt["runAttempt"],
            "published": False,
            "filesCopied": len(files),
            "sha256sumsSha256": sha(stage / "SHA256SUMS"),
            "gaApprovalSha256": receipt["gaApprovalSha256"],
        }
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        independent_trust_state.unlink(missing_ok=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("certify", "dry-run"))
    for field in ("bundle", "evidence", "trusted-key", "version", "commit", "output"):
        p.add_argument("--" + field, required=True)
    for field in ("cli", "public-key", "trust-policy", "trust-state", "stage"):
        p.add_argument("--" + field)
    a = p.parse_args()
    output = Path(a.output)
    output.unlink(missing_ok=True)
    try:
        base = dict(
            bundle=Path(a.bundle),
            evidence=Path(a.evidence),
            key=Path(a.trusted_key),
            version=a.version,
            commit=a.commit,
        )
        if a.action == "certify":
            result = certify(**base)
        else:
            require(
                all((a.cli, a.public_key, a.trust_policy, a.trust_state, a.stage)),
                "dry-run requires cli, public key, trust policy, trust state and staging directory",
            )
            result = dry_run(
                base["bundle"],
                Path(a.cli),
                Path(a.public_key),
                Path(a.trust_policy),
                Path(a.trust_state),
                base["evidence"],
                base["key"],
                base["version"],
                base["commit"],
                Path(a.stage),
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(a.action + ": " + result["status"])
        return 0
    except (
        Blocked,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        struct.error,
        zipfile.BadZipFile,
        tarfile.TarError,
        subprocess.TimeoutExpired,
    ) as exc:
        print("release rehearsal BLOCKED: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
