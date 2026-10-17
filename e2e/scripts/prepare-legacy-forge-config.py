#!/usr/bin/env python3
"""Seed Forge 1.14.4's first-launch FML config before NightConfig 3.6.0 loads it.

This old NightConfig release may throw ConcurrentModificationException when
correcting a missing defaultConfigPath on a fresh client. Only create a missing
file; never overwrite an existing player's Forge configuration.
"""
import argparse
from pathlib import Path
import sys

FORGE_1144_FML_DEFAULTS = ("versionCheck = true\n"
                           "splashscreen = true\n"
                           'defaultConfigPath = "defaultconfigs"\n'
                           "maxThreads = -1\n")


def prepare(root: Path, minecraft_version: str) -> bool:
    if minecraft_version != "1.14.4":
        return False
    if not root.is_dir() or root.is_symlink():
        raise ValueError("client root must be a real directory")
    config_dir = root / "config"
    if config_dir.is_symlink():
        raise ValueError("Forge config directory may not be a symlink")
    config_dir.mkdir(exist_ok=True)
    if not config_dir.is_dir() or config_dir.is_symlink():
        raise ValueError("Forge config path is not a real directory")
    output = config_dir / "fml.toml"
    if output.is_symlink():
        raise ValueError("Forge fml.toml may not be a symlink")
    if output.exists():
        if not output.is_file():
            raise ValueError("Forge fml.toml is not a regular file")
        return False
    try:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(FORGE_1144_FML_DEFAULTS)
    except FileExistsError:
        # A concurrent writer must not cause us to overwrite its file.
        if output.is_symlink() or not output.is_file():
            raise ValueError("Forge fml.toml was replaced with an unsafe path")
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-root", type=Path, required=True)
    parser.add_argument("--minecraft", required=True)
    args = parser.parse_args()
    try:
        created = prepare(args.client_root, args.minecraft)
    except (OSError, ValueError) as error:
        print(f"[forge-cert] cannot prepare legacy FML config: {error}", file=sys.stderr)
        return 1
    if created:
        print("[forge-cert] seeded Forge 1.14.4 FML first-launch configuration")
    return 0


if __name__ == "__main__":
    sys.exit(main())
