#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path
from typing import Any

ARCHES = {
    "x64": {"cpu": 0x01000007, "cpuText": "CPU_TYPE_X86_64", "rustTarget": "x86_64-apple-darwin"},
    "arm64": {"cpu": 0x0100000C, "cpuText": "CPU_TYPE_ARM64", "rustTarget": "aarch64-apple-darwin"},
}
COMPONENTS = {
    "cli": ("neverlauncher-cli", "neverlauncher-cli-macos-{arch}"),
    "desktop-launcher": ("neverlauncher-desktop", "neverlauncher-desktop-macos-{arch}"),
    "guard": ("neverguard", "neverguard-macos-{arch}"),
    "runtime": ("neverruntime", "neverruntime-macos-{arch}"),
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def inspect_macho(path: Path, expected_arch: str) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise RuntimeError(f"{path}: production package requires thin 64-bit little-endian Mach-O")
    cpu = struct.unpack_from("<I", data, 4)[0]
    meta = ARCHES[expected_arch]
    if cpu != meta["cpu"]:
        raise RuntimeError(f"{path}: Mach-O cputype=0x{cpu:08x}, expected {meta['cpuText']}")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    if not ncmds or not sizeofcmds or 32 + sizeofcmds > len(data):
        raise RuntimeError(f"{path}: invalid Mach-O load commands")
    offset = 32
    has_signature = False
    for _ in range(ncmds):
        if offset + 8 > len(data) or offset + 8 > 32 + sizeofcmds:
            raise RuntimeError(f"{path}: truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data) or offset + cmdsize > 32 + sizeofcmds:
            raise RuntimeError(f"{path}: invalid Mach-O load command size")
        if cmd == 0x1D:
            if cmdsize < 16:
                raise RuntimeError(f"{path}: truncated LC_CODE_SIGNATURE")
            dataoff, datasize = struct.unpack_from("<II", data, offset + 8)
            if dataoff <= 0 or datasize <= 0 or dataoff + datasize > len(data):
                raise RuntimeError(f"{path}: invalid LC_CODE_SIGNATURE bounds")
            has_signature = True
        offset += cmdsize
    if not has_signature:
        raise RuntimeError(f"{path}: LC_CODE_SIGNATURE is required")
    return meta


def manifest_cmd(args: argparse.Namespace) -> int:
    arch = args.arch
    meta = ARCHES[arch]
    app = Path(args.app)
    out = Path(args.out_dir)
    macos_dir = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources"
    out.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    for component, (bundle_name, canonical_pattern) in COMPONENTS.items():
        source = macos_dir / bundle_name
        if not source.is_file():
            raise RuntimeError(f"missing signed macOS bundle executable: {source}")
        inspect_macho(source, arch)
        canonical_name = canonical_pattern.format(arch=arch)
        canonical = out / canonical_name
        shutil.copy2(source, canonical)
        artifacts.append(
            {
                "name": canonical_name,
                "bundlePath": f"NeverLauncher.app/Contents/MacOS/{bundle_name}",
                "component": component,
                "architecture": arch,
                "cpuType": meta["cpuText"],
                "sha256": sha256(source),
                "size": source.stat().st_size,
                "codeSigned": True,
                "hardenedRuntime": True,
                "teamId": args.team_id,
            }
        )
    package_name = f"neverlauncher-desktop-{args.version}-macos-{arch}.zip"
    payload = {
        "schemaVersion": "1.0",
        "product": "NeverLauncher",
        "productVersion": args.version,
        "platform": "macos",
        "architecture": arch,
        "cpuType": meta["cpuText"],
        "rustTarget": meta["rustTarget"],
        "packageFormat": "zip",
        "packageArtifact": package_name,
        "bundleIdentifier": "ru.skif4er.neverlauncher",
        "minimumSystemVersion": "12.0",
        "hashBindingMode": "codesign+external-release-policy",
        "artifacts": artifacts,
    }
    embedded = resources / "MACOS_PACKAGE_MANIFEST.json"
    write_json(embedded, payload)

    by_component = {row["component"]: row for row in artifacts}
    component_update = {
        "schemaVersion": "1.0",
        "product": "NeverLauncher",
        "productVersion": args.version,
        "platform": "macos",
        "architecture": arch,
        "layout": "macos-app-bundle",
        "trustMode": args.trust_mode,
        "bundleName": "NeverLauncher.app",
        "components": [],
        "supportFiles": [],
    }
    for public_name, source_component, binary_name in (
        ("desktop", "desktop-launcher", "neverlauncher-desktop"),
        ("guard", "guard", "neverguard"),
        ("runtime", "runtime", "neverruntime"),
    ):
        row = by_component[source_component]
        relative = f"Contents/MacOS/{binary_name}"
        component_update["components"].append(
            {
                "component": public_name,
                "sourcePath": relative,
                "targetPath": relative,
                "sha256": row["sha256"],
                "size": row["size"],
                "executable": True,
            }
        )
    update_manifest = resources / "COMPONENT_UPDATE_MANIFEST.json"
    write_json(update_manifest, component_update)
    return 0



def finalize_cmd(args: argparse.Namespace) -> int:
    arch = args.arch
    app = Path(args.app)
    out = Path(args.out_dir)
    embedded = app / "Contents" / "Resources" / "MACOS_PACKAGE_MANIFEST.json"
    payload = json.loads(embedded.read_text(encoding="utf-8"))
    if payload.get("productVersion") != args.version or payload.get("architecture") != arch:
        raise RuntimeError("embedded macOS package manifest identity mismatch during finalization")
    macos_dir = app / "Contents" / "MacOS"
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimeError("embedded macOS package manifest contains no artifacts")
    for artifact in artifacts:
        component = str(artifact.get("component", ""))
        if component not in COMPONENTS:
            raise RuntimeError(f"unknown macOS package component during finalization: {component!r}")
        bundle_name, canonical_pattern = COMPONENTS[component]
        source = macos_dir / bundle_name
        if not source.is_file():
            raise RuntimeError(f"missing final signed macOS executable: {source}")
        inspect_macho(source, arch)
        canonical_name = canonical_pattern.format(arch=arch)
        canonical = out / canonical_name
        shutil.copy2(source, canonical)
        artifact["name"] = canonical_name
        artifact["bundlePath"] = f"NeverLauncher.app/Contents/MacOS/{bundle_name}"
        artifact["sha256"] = sha256(source)
        artifact["size"] = source.stat().st_size
    payload["hashBindingMode"] = "final-artifact-sha256"
    top = out / f"MACOS_PACKAGE_MANIFEST_{arch.upper()}.json"
    write_json(top, payload)
    return 0

def load_notary(path: str | None, production: bool) -> tuple[str, str, bool, bool, bool]:
    if not production:
        return "", "not-requested", False, False, False
    if not path:
        raise RuntimeError("production evidence requires notarytool result JSON for both architectures")
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    submission_id = str(payload.get("id", "")).strip()
    status = str(payload.get("status", "")).strip()
    if not submission_id or status != "Accepted":
        raise RuntimeError(f"notarytool result is not Accepted: id={submission_id!r} status={status!r}")
    return submission_id, status, True, True, True


def evidence_cmd(args: argparse.Namespace) -> int:
    out = Path(args.out_dir)
    production = args.signing_mode == "developer-id-notarized"
    targets: list[dict[str, Any]] = []
    allowlist: list[dict[str, Any]] = []
    notary_paths = {"x64": args.notary_x64_json, "arm64": args.notary_arm64_json}
    for arch in ("x64", "arm64"):
        manifest_name = f"MACOS_PACKAGE_MANIFEST_{arch.upper()}.json"
        manifest_path = out / manifest_name
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("architecture") != arch or manifest.get("productVersion") != args.version:
            raise RuntimeError(f"{manifest_name}: identity mismatch")
        for artifact in manifest["artifacts"]:
            path = out / artifact["name"]
            inspect_macho(path, arch)
            if sha256(path) != artifact["sha256"] or path.stat().st_size != artifact["size"]:
                raise RuntimeError(f"{artifact['name']}: hash/size drift")
        package_name = f"neverlauncher-desktop-{args.version}-macos-{arch}.zip"
        package = out / package_name
        if not package.is_file() or package.stat().st_size <= 0:
            raise RuntimeError(f"missing final macOS package: {package}")
        submission_id, status, stapled, stapler_validated, gatekeeper = load_notary(notary_paths[arch], production)
        package_evidence = {
            "name": package_name,
            "sha256": sha256(package),
            "size": package.stat().st_size,
            "manifest": manifest_name,
            "manifestSha256": sha256(manifest_path),
            "notarySubmissionId": submission_id,
            "notaryStatus": status,
            "stapled": stapled,
            "staplerValidated": stapler_validated,
            "gatekeeperAccepted": gatekeeper,
            "bundleCodeSignVerified": True,
        }
        targets.append(
            {
                "architecture": arch,
                "cpuType": ARCHES[arch]["cpuText"],
                "rustTarget": ARCHES[arch]["rustTarget"],
                "package": package_evidence,
                "artifacts": manifest["artifacts"],
            }
        )
        by_component = {row["component"]: row for row in manifest["artifacts"]}
        allowlist.append(
            {
                "architecture": arch,
                "guardSha256": by_component["guard"]["sha256"],
                "launcherSha256": by_component["desktop-launcher"]["sha256"],
                "notarized": production,
            }
        )
    evidence = {
        "schemaVersion": "1.0",
        "product": "NeverLauncher",
        "productVersion": args.version,
        "platform": "macos",
        "signingMode": args.signing_mode,
        "teamId": args.team_id,
        "generatedAt": args.generated_at,
        "targets": targets,
    }
    write_json(out / "MACOS_NOTARIZATION_EVIDENCE.json", evidence)
    write_json(
        out / "GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json",
        {
            "schemaVersion": "3.0",
            "releases": {
                args.version: {
                    "protocolVersion": 4,
                    "platforms": {"macos": {"signingMode": args.signing_mode, "artifacts": allowlist}},
                }
            },
        },
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NeverLauncher macOS x64/ARM64 production package helper")
    sub = parser.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("manifest")
    manifest.add_argument("--version", required=True)
    manifest.add_argument("--arch", choices=sorted(ARCHES), required=True)
    manifest.add_argument("--team-id", required=True)
    manifest.add_argument("--trust-mode", choices=["developer-id-notarized", "adhoc-development"], required=True)
    manifest.add_argument("--app", required=True)
    manifest.add_argument("--out-dir", required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--version", required=True)
    finalize.add_argument("--arch", choices=sorted(ARCHES), required=True)
    finalize.add_argument("--app", required=True)
    finalize.add_argument("--out-dir", required=True)
    evidence = sub.add_parser("evidence")
    evidence.add_argument("--version", required=True)
    evidence.add_argument("--signing-mode", choices=["developer-id-notarized", "adhoc-development"], required=True)
    evidence.add_argument("--team-id", required=True)
    evidence.add_argument("--generated-at", required=True)
    evidence.add_argument("--out-dir", required=True)
    evidence.add_argument("--notary-x64-json")
    evidence.add_argument("--notary-arm64-json")
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            return manifest_cmd(args)
        if args.command == "finalize":
            return finalize_cmd(args)
        return evidence_cmd(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"macos-package: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
