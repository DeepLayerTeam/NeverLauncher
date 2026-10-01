#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r'version\s+"([^"]+)"')
PROPERTY_RE = re.compile(r"\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")


def normalize_os(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("windows"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value.startswith("mac") or value.startswith("darwin"):
        return "macos"
    return value


def normalize_arch(value: str) -> str:
    value = value.strip().lower()
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(value, value)


def parse_major(version: str) -> int | None:
    parts = version.split(".")
    try:
        return int(parts[1] if parts and parts[0] == "1" else parts[0])
    except (ValueError, IndexError):
        return None


def executable_path(value: str) -> Path:
    raw = value.strip()
    if os.name == "nt":
        # GitHub Actions uses Git Bash for the compatibility script; `command -v`
        # may therefore return /c/... while this verifier runs under native Python.
        match = re.fullmatch(r"/([A-Za-z])/(.+)", raw)
        if match:
            raw = f"{match.group(1)}:/{match.group(2)}"
    return Path(raw).expanduser().resolve(strict=True)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def certify(java: str, expected_major: int, expected_os: str, expected_arch: str) -> dict[str, Any]:
    if expected_major <= 0:
        raise ValueError("expected Java major must be positive")
    expected_os = normalize_os(expected_os)
    expected_arch = normalize_arch(expected_arch)
    if expected_os not in {"linux", "windows", "macos"}:
        raise ValueError(f"unsupported expected OS: {expected_os}")
    if expected_arch not in {"x86_64", "aarch64"}:
        raise ValueError(f"unsupported expected architecture: {expected_arch}")

    resolved = executable_path(java)
    if not resolved.is_file():
        raise ValueError(f"Java executable is not a regular file: {resolved}")

    proc = subprocess.run(
        [str(resolved), "-XshowSettings:properties", "-version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    text = proc.stdout or ""
    version_match = VERSION_RE.search(text)
    version_string = version_match.group(1) if version_match else ""
    detected_major = parse_major(version_string) if version_string else None

    properties: dict[str, str] = {}
    for line in text.splitlines():
        match = PROPERTY_RE.match(line)
        if match:
            properties[match.group(1)] = match.group(2)

    executable_sha256, executable_size = sha256_file(resolved)
    java_home_raw = properties.get("java.home", "").strip()
    java_home = str(Path(java_home_raw).expanduser().resolve()) if java_home_raw else ""
    vendor = properties.get("java.vendor", "").strip()
    runtime_version = (properties.get("java.runtime.version") or properties.get("java.version") or version_string).strip()
    vm_name = properties.get("java.vm.name", "").strip()
    detected_os = normalize_os(properties.get("os.name", ""))
    detected_arch = normalize_arch(properties.get("os.arch", ""))

    certified = all(
        [
            proc.returncode == 0,
            detected_major == expected_major,
            detected_os == expected_os,
            detected_arch == expected_arch,
            executable_size > 0,
            bool(SHA256_RE.fullmatch(executable_sha256)),
            bool(vendor),
            bool(runtime_version),
            bool(java_home),
            bool(vm_name),
        ]
    )
    return {
        "schemaVersion": "1.0",
        "status": "passed" if certified else "failed",
        "java": java,
        "resolvedExecutable": str(resolved),
        "executableSha256": executable_sha256,
        "executableSize": executable_size,
        "expectedMajor": expected_major,
        "detectedMajor": detected_major,
        "expectedOS": expected_os,
        "detectedOS": detected_os,
        "expectedArch": expected_arch,
        "detectedArch": detected_arch,
        "vendor": vendor,
        "runtimeVersion": runtime_version,
        "vmName": vm_name,
        "javaHome": java_home,
        "exitCode": proc.returncode,
        "matched": proc.returncode == 0 and detected_major == expected_major,
        "certified": certified,
        "versionOutput": text.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Certify the exact JRE binary used by a NeverLauncher compatibility target")
    parser.add_argument("--java", required=True)
    parser.add_argument("--major", required=True, type=int)
    parser.add_argument("--os", required=True, dest="expected_os")
    parser.add_argument("--arch", required=True, dest="expected_arch")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = certify(args.java, args.major, args.expected_os, args.expected_arch)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"jre-certification: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not payload["certified"]:
        print(
            "jre-certification: mismatch "
            f"major={payload['detectedMajor']}/{payload['expectedMajor']} "
            f"os={payload['detectedOS']}/{payload['expectedOS']} "
            f"arch={payload['detectedArch']}/{payload['expectedArch']}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
