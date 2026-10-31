#!/usr/bin/env python3
"""Build genuine OS installer artifacts from an Ed25519-verified branded bundle.

No platform artifact is reported as production signed unless its platform
signature (Authenticode, Apple Developer ID, detached GPG) verifies.
Windows is a single-file .exe with a compiled-in verified bundle. Linux builds
.deb; macOS builds a signed .app inside a signed .pkg. No Java is required.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = {"windows": "windows", "linux": "linux", "darwin": "macos"}
ARCH = {"amd64": "x64", "arm64": "arm64"}


def checked(*cmd, cwd=None, env=None):
    subprocess.run([str(a) for a in cmd], cwd=cwd, env=env, check=True)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def file_matches(path, art):
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size != art["size"]
        or digest(path) != art["sha256"]
    ):
        raise ValueError(f"object SHA-256/size mismatch: {path}")


def verify_config(path, key, policy_path=None):
    # Verify the exact signed payload. A delegated signer is admitted only by
    # root-signed trust policy, never by arbitrary bundle-provided public keys.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import datetime

    env = json.loads(path.read_text("utf-8"))
    payload = base64.b64decode(env["payload"], validate=True)
    if env.get("schemaVersion") == "2.0":
        policy_path = policy_path or path.with_name("trust-policy.signed.json")
        if not policy_path.is_file() or policy_path.is_symlink():
            raise ValueError("delegated config requires local signed trust policy")
        penv = json.loads(policy_path.read_text("utf-8"))
        if penv.get("schemaVersion") != "1.0":
            raise ValueError("unsupported trust policy envelope")
        pp = base64.b64decode(penv["payload"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(penv["rootSignature"]), b"Launcher-Trust-Policy-v1\n" + pp
        )
        policy = json.loads(pp)
        if (
            policy.get("schemaVersion") != "1.0"
            or policy.get("domain") != "launcher.trust.v1"
            or policy.get("epoch") != env.get("trustEpoch")
        ):
            raise ValueError("trust policy domain/epoch mismatch")
        now = datetime.datetime.now(datetime.timezone.utc)

        def utc(t):
            return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc
            )

        if not utc(policy["issuedAt"]) <= now < utc(policy["expiresAt"]):
            raise ValueError("stale trust policy")
        signer = next(
            (
                k
                for k in policy["keys"]
                if k["id"] == env.get("keyId")
                and k["role"] == "bootstrap"
                and k["status"] == "active"
            ),
            None,
        )
        if not signer or utc(signer["notBefore"]) > utc(env["signedAt"]):
            raise ValueError("bootstrap signer not delegated")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer["publicKey"])).verify(
            bytes.fromhex(env["signature"]),
            (
                "Launcher-Bootstrap-v2\n"
                + env["keyId"]
                + "\n"
                + str(env["trustEpoch"])
                + "\n"
                + env["signedAt"]
                + "\n"
            ).encode()
            + payload,
        )
    elif env.get("schemaVersion") == "1.0" and set(env) == {
        "schemaVersion",
        "payload",
        "signature",
    }:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(env["signature"]), payload
        )
    else:
        raise ValueError("invalid signed configuration envelope")
    config = json.loads(payload)
    if config["schemaVersion"] != "1.0":
        raise ValueError("unsupported config")
    if (
        env.get("schemaVersion") == "2.0"
        and config["profilePublicKey"].lower() != key.lower()
    ):
        raise ValueError("game trust root mismatches embedded root")
    return config


def check_binary_arch(path, osname, arch):
    with open(path, "rb") as f:
        head = f.read(4096)
        if osname == "linux":
            expect = 62 if arch == "amd64" else 183
            if (
                head[:5] != b"\x7fELF\x02"
                or struct.unpack_from("<H", head, 18)[0] != expect
            ):
                raise ValueError(f"{path}: wrong Linux ELF architecture")
        elif osname == "windows":
            if head[:2] != b"MZ":
                raise ValueError(f"{path}: not a PE executable")
            peoff = struct.unpack_from("<I", head, 0x3C)[0]
            if peoff + 6 > len(head):
                f.seek(peoff)
                pe = f.read(6)
            else:
                pe = head[peoff : peoff + 6]
            expect = 0x8664 if arch == "amd64" else 0xAA64
            if pe[:4] != b"PE\0\0" or struct.unpack_from("<H", pe, 4)[0] != expect:
                raise ValueError(f"{path}: wrong Windows PE architecture")
        elif osname == "darwin":
            expect = 0x01000007 if arch == "amd64" else 0x0100000C
            if (
                head[:4] != b"\xcf\xfa\xed\xfe"
                or struct.unpack_from("<I", head, 4)[0] != expect
            ):
                raise ValueError(f"{path}: wrong macOS Mach-O architecture")


def collect_bundle(args, stage):
    key = pathlib.Path(args.root_key_file).read_text().strip().lower()
    if not re.fullmatch("[0-9a-f]{64}", key):
        raise ValueError("required provisioned 32-byte Ed25519 key")
    cfg = verify_config(args.config, key, args.trust_policy)
    if args.platform not in TARGETS or args.arch not in ARCH:
        raise ValueError("unsupported target")
    if not any(
        t["os"] == args.platform and t["arch"] == args.arch for t in cfg["targets"]
    ):
        raise ValueError("platform absent from signed release configuration")
    match = [
        t
        for t in cfg.get("installerTargets", [])
        if t["os"] == args.platform and t["arch"] == args.arch
    ]
    if len(match) != 1:
        raise ValueError(
            "signed installerTargets must pin exactly one platform Prestarter"
        )
    check_binary_arch(args.prestarter, args.platform, args.arch)
    file_matches(args.prestarter, match[0]["prestarter"])
    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.config, stage / "bootstrap.signed.json")
    if args.trust_policy:
        shutil.copy2(args.trust_policy, stage / "trust-policy.signed.json")
    suffix = ".exe" if args.platform == "windows" else ""
    shutil.copy2(args.prestarter, stage / ("neverprestarter" + suffix))
    if args.offline_source:
        # Preserve only regular source files: symlinks, device nodes, nested
        # junctions and other escapes are rejected rather than followed.
        for p in args.offline_source.rglob("*"):
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError(f"unsafe offline source entry: {p}")
            relative = p.relative_to(args.offline_source)
            target = stage / relative
            if p.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if target.exists():
                    raise ValueError(
                        "offline source attempts to override signed installer files"
                    )
                if p.stat().st_size > 3 << 30:
                    raise ValueError("oversized offline object")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
        target = next(
            t
            for t in cfg["targets"]
            if t["os"] == args.platform and t["arch"] == args.arch
        )
        for component in target["components"]:
            art = component
            file_matches(stage / "objects" / art["sha256"], art)
        file_matches(stage / "objects" / cfg["manifest"]["sha256"], cfg["manifest"])
        file_matches(stage / "managed-jre" / "manifest.json", cfg["javaManifest"])
    return key, cfg


def package_windows(args, stage, key, out, version):
    if not shutil.which("go"):
        raise RuntimeError("Go toolchain required")
    # Use a fresh isolated Go module copy; source tree is never modified to
    # embed a customer's identity or their possibly large offline resources.
    with tempfile.TemporaryDirectory() as tmp:
        module = pathlib.Path(tmp) / "prestarter"
        shutil.copytree(
            ROOT / "prestarter",
            module,
            ignore=shutil.ignore_patterns("*.exe", "*.test"),
        )
        embedded = module / "cmd" / "neverinstaller" / "embedded.bundle.zip"
        with zipfile.ZipFile(
            embedded, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as z:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    z.write(path, path.relative_to(stage).as_posix())
        result = (
            out
            / f"launcher-{version}-{args.project}-{TARGETS[args.platform]}-{ARCH[args.arch]}.exe"
        )
        env = dict(os.environ, GOOS=args.platform, GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            result,
            "./cmd/neverinstaller",
            cwd=module,
            env=env,
        )
    check_binary_arch(result, args.platform, args.arch)
    if not args.unsigned_test:
        thumb = os.environ.get("NEVERLAUNCHER_WINDOWS_CERT_THUMBPRINT", "")
        if not thumb or not shutil.which("signtool"):
            raise RuntimeError(
                "Authenticode certificate and signtool required for production"
            )
        checked(
            "signtool",
            "sign",
            "/fd",
            "SHA256",
            "/sha1",
            thumb,
            "/tr",
            "http://timestamp.digicert.com",
            "/td",
            "SHA256",
            result,
        )
        checked("signtool", "verify", "/pa", "/v", result)
    return result


def package_linux(args, stage, key, out, version):
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("dpkg-deb required")
    with tempfile.TemporaryDirectory() as tmp:
        pkg = pathlib.Path(tmp) / "deb"
        bundled = pkg / "usr" / "lib" / "launcher" / "bundle"
        bundled.parent.mkdir(parents=True)
        shutil.copytree(stage, bundled)
        exe = bundled / "neverinstaller"
        env = dict(os.environ, GOOS="linux", GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            exe,
            "./cmd/neverinstaller",
            cwd=ROOT / "prestarter",
            env=env,
        )
        exe.chmod(0o755)
        launcher = pkg / "usr" / "bin" / "launcher"
        launcher.parent.mkdir(parents=True)
        launcher.write_text(
            '#!/bin/sh\nset -eu\nif [ "$#" -eq 0 ]; then set -- install; fi\nexec /usr/lib/launcher/bundle/neverinstaller "$@" --bundle /usr/lib/launcher/bundle\n'
        )
        launcher.chmod(0o755)
        desktop = pkg / "usr" / "share" / "applications" / "launcher.desktop"
        desktop.parent.mkdir(parents=True)
        name = "Launcher"
        if cfg := verify_config(stage / "bootstrap.signed.json", key):
            name = cfg.get("branding", {}).get("displayName", name)
        safe = name.replace("\r", " ").replace("\n", " ")
        desktop.write_text(
            f"[Desktop Entry]\nType=Application\nName={safe}\nExec=/usr/bin/launcher\nTerminal=false\nCategories=Game;\n"
        )
        ctrl = pkg / "DEBIAN"
        ctrl.mkdir()
        debarch = "amd64" if args.arch == "amd64" else "arm64"
        ctrl.joinpath("control").write_text(
            f"Package: launcher-{args.project}\nVersion: {version}\nArchitecture: {debarch}\nMaintainer: Launcher Release Engineering\nSection: games\nPriority: optional\nDescription: Native signed-config Minecraft launcher installer\n"
        )
        result = out / f"launcher-{version}-{args.project}-linux-{ARCH[args.arch]}.deb"
        checked("dpkg-deb", "--build", "--root-owner-group", pkg, result)
        checked("dpkg-deb", "--info", result)
    if not args.unsigned_test:
        gpg = os.environ.get("NEVERLAUNCHER_GPG_SIGNING_KEY", "")
        if not gpg or not shutil.which("gpg"):
            raise RuntimeError("Linux release needs a GPG signing key")
        checked(
            "gpg",
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            gpg,
            "--detach-sign",
            "--output",
            str(result) + ".asc",
            result,
        )
        checked("gpg", "--verify", str(result) + ".asc", result)
    return result


def package_macos(args, stage, key, out, version):
    if sys.platform != "darwin":
        raise RuntimeError("macOS signed package requires macOS runner")
    with tempfile.TemporaryDirectory() as tmp:
        app = pathlib.Path(tmp) / "Launcher.app"
        macos = app / "Contents" / "MacOS"
        resources = app / "Contents" / "Resources" / "bundle"
        macos.mkdir(parents=True)
        shutil.copytree(stage, resources)
        binary = macos / "Launcher"
        env = dict(os.environ, GOOS="darwin", GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            binary,
            "./cmd/neverinstaller",
            cwd=ROOT / "prestarter",
            env=env,
        )
        check_binary_arch(binary, "darwin", args.arch)
        binary.chmod(0o755)
        info = {
            "CFBundleExecutable": "Launcher",
            "CFBundleIdentifier": "org.launcher." + args.project,
            "CFBundleName": "Launcher",
            "CFBundleDisplayName": verify_config(stage / "bootstrap.signed.json", key)
            .get("branding", {})
            .get("displayName", "Launcher"),
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            "LSMinimumSystemVersion": "12.0",
        }
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
        result = out / f"launcher-{version}-{args.project}-macos-{ARCH[args.arch]}.pkg"
        signid = os.environ.get("NEVERLAUNCHER_MACOS_CODESIGN_ID", "")
        pkgid = os.environ.get("NEVERLAUNCHER_MACOS_INSTALLER_ID", "")
        if not args.unsigned_test and (not signid or not pkgid):
            raise RuntimeError(
                "Developer ID Application and Installer identities required"
            )
        if signid:
            # The pinned Prestarter SHA-256 is computed BEFORE bundle signing.
            # It MUST already be Developer-ID-signed; signing it now would
            # change the bytes and invalidate the signed bootstrap manifest.
            checked(
                "codesign",
                "--verify",
                "--strict",
                "--verbose=2",
                resources / "neverprestarter",
            )
            checked(
                "codesign",
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                signid,
                app,
            )
            checked("codesign", "--verify", "--deep", "--strict", "--verbose=2", app)
        cmd = [
            "pkgbuild",
            "--component",
            app,
            "--install-location",
            "/Applications",
            "--identifier",
            "org.launcher." + args.project,
            "--version",
            version,
        ]
        if not args.unsigned_test:
            cmd += ["--sign", pkgid]
        cmd += [result]
        checked(*cmd)
        if not args.unsigned_test:
            checked("pkgutil", "--check-signature", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform", choices=TARGETS, required=True)
    p.add_argument("--arch", choices=ARCH, required=True)
    p.add_argument(
        "--project", required=True, help="signed project name in package IDs"
    )
    p.add_argument("--version", required=True)
    p.add_argument("--config", type=pathlib.Path, required=True)
    p.add_argument(
        "--trust-policy",
        type=pathlib.Path,
        help="locally provisioned root-signed delegated trust policy for v2 config",
    )
    p.add_argument("--prestarter", type=pathlib.Path, required=True)
    p.add_argument("--root-key-file", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--offline-source", type=pathlib.Path)
    p.add_argument(
        "--unsigned-test",
        action="store_true",
        help="only for CI/test packages; NEVER a production release",
    )
    args = p.parse_args()
    if not re.fullmatch("[a-z0-9][a-z0-9-]{1,45}", args.project):
        p.error("project must be safe package ID")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        p.error("invalid semver")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = pathlib.Path(tmp) / "bundle"
        key, cfg = collect_bundle(args, stage)
        if cfg["projectId"].lower() != args.project:
            p.error("--project must match signed projectId")
        if args.platform == "windows":
            result = package_windows(args, stage, key, args.output, args.version)
        elif args.platform == "linux":
            result = package_linux(args, stage, key, args.output, args.version)
        else:
            result = package_macos(args, stage, key, args.output, args.version)
    print(
        json.dumps(
            {
                "artifact": str(result),
                "sha256": digest(result),
                "size": result.stat().st_size,
                "productionSigned": not args.unsigned_test,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("installer build failed:", e, file=sys.stderr)
        sys.exit(1)
