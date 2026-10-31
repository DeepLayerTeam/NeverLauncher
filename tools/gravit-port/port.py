#!/usr/bin/env python3
"""Compile an explicitly source-ported Gravit module into a real Never Extension.

Does not load arbitrary Gravit JARs or attempt unsafe Java API emulation.
Published packages must be signed and independently verified by Never CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+")


class PortError(Exception):
    pass


def run(*cmd: str, cwd: Path = ROOT) -> None:
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        raise PortError(f"tool failed: {cmd[0]} ({exc})") from exc


def sources_in(directory: Path) -> list[Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise PortError("source must be a real directory")
    source = directory.resolve(strict=True)
    result: list[Path] = []
    for p in sorted(source.rglob("*")):
        if p.is_symlink():
            raise PortError(f"source symlink forbidden: {p}")
        if p.is_file():
            if p.suffix != ".java":
                continue  # Non-Java assets are deliberately not embedded.
            if p.stat().st_size > 1 << 20 or not p.resolve().is_relative_to(source):
                raise PortError(f"unsafe source file: {p}")
            result.append(p)
        elif not p.is_dir():
            raise PortError(f"unsupported source entry: {p}")
    if not result or len(result) > 1000:
        raise PortError("expected 1..1000 Java source files")
    return result


def validate_manifest(raw: bytes, entrypoint: str) -> None:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PortError(f"invalid extension manifest: {exc}") from exc
    if (
        not isinstance(doc, dict)
        or doc.get("schemaVersion") != "2.0"
        or doc.get("api") != "1.0"
    ):
        raise PortError("expected a schemaVersion 2.0 / api 1.0 extension manifest")
    targets = doc.get("targets")
    if not isinstance(targets, list) or not targets:
        raise PortError("extension manifest requires backend/cli target")
    if any(
        not isinstance(t, dict)
        or t.get("kind") not in ("backend", "cli")
        or t.get("entrypoint") != entrypoint
        for t in targets
    ):
        raise PortError(
            "ported Java module must use its built JAR for backend/cli targets"
        )
    if len({t["kind"] for t in targets}) != len(targets):
        raise PortError("duplicate Java target")
    if not isinstance(doc.get("permissions"), list):
        raise PortError("permissions must be declared in the signed manifest")


def ensure_clean_destination(path: Path) -> None:
    if path.is_symlink() or path.exists():
        raise PortError(f"destination already exists (refusing overwrite): {path}")
    path.parent.mkdir(parents=True, exist_ok=True)


def build(args: argparse.Namespace) -> None:
    if not IDENT.fullmatch(args.module_class) or args.module_class.startswith(
        ("pro.gravit.", "ru.launcher.sdk.")
    ):
        raise PortError("invalid or reserved Gravit module class name")
    entrypoint = "backend/gravit-port.jar"
    if args.manifest.is_symlink():
        raise PortError("manifest symlink forbidden")
    manifest_file = args.manifest.resolve(strict=True)
    if not manifest_file.is_file() or manifest_file.stat().st_size > 1 << 20:
        raise PortError("manifest must be a regular non-symlink file under 1 MiB")
    raw_manifest = manifest_file.read_bytes()
    validate_manifest(raw_manifest, entrypoint)
    sources = sources_in(args.source)
    if args.output.is_symlink() or (
        args.package is not None and args.package.is_symlink()
    ):
        raise PortError("output symlink forbidden")
    destination = args.output.resolve()
    ensure_clean_destination(destination)
    if args.private_key is not None:
        if args.package is None or args.public_key is None or args.nl is None:
            raise PortError("signing requires --package, --nl and --public-key")
        ensure_clean_destination(args.package.resolve())
    elif args.package is not None or args.public_key is not None or args.nl is not None:
        raise PortError(
            "a .nlext needs all of --private-key, --public-key, --package and --nl"
        )

    # The official source-port subset is built against our exact SDK, upstream Gravit JARs.
    run("sh", "sdk/java/gravit-compat/build.sh")
    core = ROOT / "sdk/java/core/build/classes"
    adapter = ROOT / "sdk/java/gravit-compat/build/classes"
    if not (core / "ru/launcher/sdk/host/JavaExtensionHost.class").is_file():
        raise PortError("Java SDK host did not build")
    with tempfile.TemporaryDirectory(
        prefix="gravit-port-", dir=destination.parent
    ) as tmp:
        work = Path(tmp)
        classes = work / "compiled"
        classes.mkdir()
        javac = (
            str(Path(os.environ["JAVA_HOME"]) / "bin/javac")
            if os.environ.get("JAVA_HOME")
            else "javac"
        )
        jar = (
            str(Path(os.environ["JAVA_HOME"]) / "bin/jar")
            if os.environ.get("JAVA_HOME")
            else "jar"
        )
        run(
            javac,
            "--release",
            "17",
            "-proc:none",
            "-encoding",
            "UTF-8",
            "-cp",
            os.pathsep.join((str(core), str(adapter))),
            "-d",
            str(classes),
            *map(str, sources),
        )
        main = classes.joinpath(*args.module_class.split(".")).with_suffix(".class")
        if not main.is_file():
            raise PortError(f"module class not generated: {args.module_class}")
        # javap inspects bytecode without initializing or executing an untrusted class.
        javap = (
            str(Path(os.environ["JAVA_HOME"]) / "bin/javap")
            if os.environ.get("JAVA_HOME")
            else "javap"
        )
        try:
            details = subprocess.run(
                [
                    javap,
                    "-classpath",
                    os.pathsep.join((str(classes), str(core), str(adapter))),
                    "-public",
                    args.module_class,
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        except (subprocess.CalledProcessError, OSError) as exc:
            raise PortError(f"unable to inspect compiled module class: {exc}") from exc
        if not re.search(
            r"\bclass\s+"
            + re.escape(args.module_class)
            + r"\s+extends\s+pro\.gravit\.launcher\.base\.modules\.LauncherModule\b",
            details,
        ):
            raise PortError(
                "ported entrypoint must directly extend the supported LauncherModule class"
            )
        for p in classes.rglob("*.class"):
            rel = p.relative_to(classes).as_posix()
            if (
                (core / rel).exists()
                or (adapter / rel).exists()
                or rel.startswith(("pro/gravit/", "ru/launcher/sdk/"))
            ):
                raise PortError(f"module attempts to override host/SDK class: {rel}")
        stage = work / "package"
        (stage / "backend").mkdir(parents=True)
        mf = work / "MANIFEST.MF"
        mf.write_text(
            "Manifest-Version: 1.0\nMain-Class: ru.launcher.sdk.host.JavaExtensionHost\nLauncher-Extension-Class: ru.launcher.sdk.gravit.GravitCompatExtension\nLauncher-Gravit-Module-Class: "
            + args.module_class
            + "\n",
            encoding="utf-8",
        )
        jpath = stage / entrypoint
        run(
            jar,
            "--create",
            "--file",
            str(jpath),
            "--manifest",
            str(mf),
            "-C",
            str(core),
            ".",
            "-C",
            str(adapter),
            ".",
            "-C",
            str(classes),
            ".",
        )
        with zipfile.ZipFile(jpath) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise PortError("duplicate JAR entries")
            for name in (
                "ru/launcher/sdk/host/JavaExtensionHost.class",
                "ru/launcher/sdk/gravit/GravitCompatExtension.class",
                args.module_class.replace(".", "/") + ".class",
            ):
                if name not in names:
                    raise PortError("missing executable JAR class: " + name)
        (stage / "launcher-extension.json").write_bytes(raw_manifest)
        # Publish the build directory only after the actual compilation and JAR verification.
        stage.rename(destination)

    # No signing key -> only an untrusted staging directory. Never represent that as an installable package.
    if args.private_key is not None:
        pkg = args.package.resolve()
        try:
            run(
                str(args.nl.resolve()),
                "extension",
                "pack",
                str(destination),
                "--output",
                str(pkg),
                "--private-key",
                str(args.private_key.resolve()),
            )
            run(
                str(args.nl.resolve()),
                "extension",
                "verify",
                str(pkg),
                "--public-key",
                str(args.public_key.resolve()),
            )
        except Exception:
            pkg.unlink(missing_ok=True)
            raise
    print(
        json.dumps(
            {
                "module": args.module_class,
                "jarSHA256": hashlib.sha256(
                    (destination / entrypoint).read_bytes()
                ).hexdigest(),
                "staged": str(destination),
                "signedPackage": str(args.package.resolve())
                if args.private_key is not None
                else None,
            },
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile an explicitly ported Gravit Java module to executable Never Extension"
    )
    parser.add_argument(
        "--source", type=Path, required=True, help="directory with ported .java sources"
    )
    parser.add_argument(
        "--module-class", required=True, help="concrete LauncherModule FQCN"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="approved extension manifest, no implicit permissions",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new package directory; overwritten"
    )
    parser.add_argument(
        "--nl", type=Path, help="compiled Never CLI executable for signing"
    )
    parser.add_argument(
        "--private-key", type=Path, help="existing publisher private Ed25519 key"
    )
    parser.add_argument(
        "--public-key", type=Path, help="matching trusted publisher public key"
    )
    parser.add_argument("--package", type=Path, help="new signed .nlext output")
    args = parser.parse_args()
    try:
        build(args)
        return 0
    except (OSError, PortError) as exc:
        print(f"gravit-port: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
