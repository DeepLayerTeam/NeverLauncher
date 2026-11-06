#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import io
import hashlib
import json
import os
import struct
import tarfile

from component_set_sign import signed_set, sign_delegated_set
from guard_manifest_sign_0437 import sign_manifest
from pathlib import Path

MACHINES = {
    "x64": (62, "EM_X86_64"),
    "arm64": (183, "EM_AARCH64"),
}
COMPONENTS = {
    "cli": ("launcher-cli-linux-{arch}", "launcher/launcher-cli"),
    "api": ("launcher-api-linux-{arch}", "launcher/launcher-api"),
    "desktop-launcher": (
        "launcher-desktop-linux-{arch}",
        "launcher/launcher-desktop",
    ),
    "guard": ("guard-linux-{arch}", "launcher/guard"),
    "runtime": ("runtime-linux-{arch}", "launcher/runtime"),
}


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def inspect_elf(path: Path, expected_arch: str) -> str:
    data = path.read_bytes()[:64]
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise SystemExit(f"{path}: файл не является ELF")
    if data[4] != 2 or data[5] != 1:
        raise SystemExit(f"{path}: для рабочего пакета требуется ELF64 с порядком байтов little-endian")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type not in (2, 3):
        raise SystemExit(f"{path}: неподдерживаемый тип ELF {elf_type}")
    expected_machine, machine_name = MACHINES[expected_arch]
    if machine != expected_machine:
        raise SystemExit(
            f"{path}: ELF machine={machine}, ожидалось {expected_machine} ({machine_name})"
        )
    return machine_name


def tar_info(name: str, size: int, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def write_package(out: Path, version: str, arch: str) -> None:
    _, machine_name = MACHINES[arch]
    package_name = f"launcher-linux-{arch}-{version}.tar.gz"
    manifest_name = f"LINUX_PACKAGE_MANIFEST_{arch.upper()}.json"
    artifacts: list[dict[str, object]] = []
    payloads: list[tuple[Path, str]] = []

    for component, (pattern, package_path) in COMPONENTS.items():
        name = pattern.format(arch=arch)
        path = out / name
        if not path.is_file():
            raise SystemExit(f"Отсутствует: «рабочий артефакт Linux»: {path}")
        machine = inspect_elf(path, arch)
        digest, size = sha256_file(path)
        artifacts.append(
            {
                "name": name,
                "packagePath": package_path,
                "component": component,
                "architecture": arch,
                "elfMachine": machine,
                "sha256": digest,
                "size": size,
                "mode": "0755",
            }
        )
        payloads.append((path, package_path))

    artifacts.sort(key=lambda item: str(item["component"]))
    manifest = {
        "schemaVersion": "1.0",
        "product": "Launcher",
        "productVersion": version,
        "platform": "linux",
        "architecture": arch,
        "elfMachine": machine_name,
        "packageFormat": "tar.gz",
        "packageArtifact": package_name,
        "artifacts": artifacts,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    manifest_path = out / manifest_name
    manifest_path.write_bytes(manifest_bytes)
    os.chmod(manifest_path, 0o644)
    guard_signature = (sign_manifest(manifest_bytes)
        if tuple(int(x) for x in version.split(".")[:3]) >= (0, 43, 7) else None)
    if guard_signature is not None:
        signature_path = out / (manifest_name + ".ed25519")
        signature_path.write_bytes(guard_signature)
        os.chmod(signature_path, 0o644)

    by_component = {item["component"]: item for item in artifacts}
    update_components = []
    for component, update_name in (
        ("desktop-launcher", "desktop"),
        ("guard", "guard"),
        ("runtime", "runtime"),
    ):
        item = by_component[component]
        update_components.append(
            {
                "component": update_name,
                "sourcePath": str(item["packagePath"]).removeprefix("launcher/"),
                "targetPath": str(item["packagePath"]).removeprefix("launcher/"),
                "sha256": item["sha256"],
                "size": item["size"],
                "executable": True,
            }
        )
    update_manifest = {
        "schemaVersion": "1.0",
        "product": "Launcher",
        "productVersion": version,
        "platform": "linux",
        "architecture": arch,
        "layout": "adjacent-files",
        "trustMode": "sha256-delivery",
        "components": update_components,
        "supportFiles": [
            {
                "component": "package-manifest",
                "sourcePath": "LINUX_PACKAGE_MANIFEST.json",
                "targetPath": "LINUX_PACKAGE_MANIFEST.json",
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "size": len(manifest_bytes),
                "executable": False,
            }
        ],
    }
    update_manifest["supportFiles"].append(
        {
            "component": "updater",
            "sourcePath": "launcher-cli",
            "targetPath": "launcher-cli",
            "sha256": by_component["cli"]["sha256"],
            "size": by_component["cli"]["size"],
            "executable": True,
        }
    )
    if guard_signature is not None:
        update_manifest["supportFiles"].append({
            "component": "guard-manifest-signature",
            "sourcePath": "LINUX_PACKAGE_MANIFEST.json.ed25519",
            "targetPath": "LINUX_PACKAGE_MANIFEST.json.ed25519",
            "sha256": hashlib.sha256(guard_signature).hexdigest(),
            "size": len(guard_signature),
            "executable": False,
        })
    update_manifest_bytes, component_sig = signed_set(update_manifest)
    # Промышленный обновлятор проверяет делегированную подпись компонентов по
    # закреплённой политике, подписанной корневым ключом. Поставляйте эти данные
    # вместе с точным манифестом обновления, а не только со старой подписью
    # компонента.
    delegated_sig = None
    delegated_policy = None
    if tuple(int(x) for x in version.split(".")[:3]) >= (0, 41, 0):
        delegated_sig, delegated_policy = sign_delegated_set(update_manifest_bytes)

    package_path = out / package_name
    tmp = package_path.with_suffix(package_path.suffix + ".tmp")
    with tmp.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
        ) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                for path, package_entry in sorted(payloads, key=lambda item: item[1]):
                    with path.open("rb") as f:
                        tf.addfile(
                            tar_info(package_entry, path.stat().st_size, 0o755), f
                        )
                tf.addfile(
                    tar_info(
                        "launcher/LINUX_PACKAGE_MANIFEST.json",
                        len(manifest_bytes),
                        0o644,
                    ),
                    io.BytesIO(manifest_bytes),
                )
                if guard_signature is not None:
                    tf.addfile(
                        tar_info("launcher/LINUX_PACKAGE_MANIFEST.json.ed25519",
                                 len(guard_signature), 0o644),
                        io.BytesIO(guard_signature),
                    )
                tf.addfile(
                    tar_info(
                        "launcher/COMPONENT_UPDATE_MANIFEST.json",
                        len(update_manifest_bytes),
                        0o644,
                    ),
                    io.BytesIO(update_manifest_bytes),
                )
                if component_sig is not None:
                    tf.addfile(
                        tar_info(
                            "launcher/COMPONENT_SET_SIGNATURE.json",
                            len(component_sig),
                            0o644,
                        ),
                        io.BytesIO(component_sig),
                    )
                if delegated_sig is not None and delegated_policy is not None:
                    tf.addfile(
                        tar_info(
                            "launcher/COMPONENT_SET_SIGNATURE_V2.json",
                            len(delegated_sig),
                            0o644,
                        ),
                        io.BytesIO(delegated_sig),
                    )
                    tf.addfile(
                        tar_info(
                            "launcher/COMPONENT_TRUST_POLICY.json",
                            len(delegated_policy),
                            0o644,
                        ),
                        io.BytesIO(delegated_policy),
                    )
    os.replace(tmp, package_path)
    os.chmod(package_path, 0o644)
    digest, size = sha256_file(package_path)
    print(
        json.dumps(
            {
                "package": package_name,
                "sha256": digest,
                "size": size,
                "manifest": manifest_name,
            },
            separators=(",", ":"),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Собрать детерминированный производственный пакет Launcher Linux tar.gz"
    )
    parser.add_argument("--out", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", required=True, choices=sorted(MACHINES))
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    write_package(out, args.version.strip(), args.architecture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
