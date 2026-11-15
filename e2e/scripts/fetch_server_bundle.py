#!/usr/bin/env python3
"""Materialize one independently pinned server bundle from a GitHub release.

The release tag selects storage only. The operator-pinned manifest SHA-256 and
per-target ZIP SHA-256 establish the trust boundary; no digest is inferred from
an untrusted download. No archive is extracted here.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

from live_join import ID, SHA, file_sha256, load_pinned_bundle, read_json, require

ASSET = 'compatibility-server-pins.json'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip\Z')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z')


def download(repo, tag, name, destination):
    subprocess.run(['gh', 'release', 'download', tag, '--repo', repo,
                    '--pattern', name, '--dir', str(destination)],
                   check=True, timeout=900)


def fetch(repo, tag, manifest_sha, target, directory, *, downloader=download):
    require(REPO.fullmatch(repo) is not None, 'Invalid GitHub repository')
    require(TAG.fullmatch(tag) is not None and '..' not in tag, 'Invalid release tag')
    require(SHA.fullmatch(manifest_sha) is not None, 'Expected independently approved manifest SHA-256')
    require(ID.fullmatch(target) is not None, 'Invalid compatibility target')
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    pins = directory / ASSET
    downloader(repo, tag, ASSET, directory)
    require(pins.is_file() and not pins.is_symlink() and pins.stat().st_size <= 8 * 1024 * 1024,
            'Missing or unsafe server pin manifest')
    require(file_sha256(pins) == manifest_sha, 'Server pin manifest SHA-256 mismatch')
    manifest = read_json(pins)
    require(manifest.get('schema') == 'launcher.compatibility-server/0.52.4', 'Invalid server pin schema')
    targets = manifest.get('targets')
    require(type(targets) is dict, 'Invalid server pin targets')
    # Official Mojang metadata remains independently verified by vanilla-server.
    # Never allow a missing modded or malformed existing entry to fall back.
    if target.startswith('vanilla-') and target not in targets:
        return pins, directory
    require(type(targets.get(target)) is dict, 'No approved server bundle for ' + target)
    entry = targets[target]
    name = entry.get('file')
    require(type(name) is str and NAME.fullmatch(name) and '..' not in name, 'Unsafe server bundle asset name')
    downloader(repo, tag, name, directory)
    # Apply exactly the same constraints as the runtime verifier before making
    # paths available to the matrix. The actual client loader version is checked
    # again by live_join when it resolves the real installation.
    load_pinned_bundle(SimpleNamespace(target=target, loader=entry.get('loader'),
        minecraft=entry.get('minecraft'), loader_version=entry.get('loaderVersion', ''),
        pins=str(pins), bundle_dir=str(directory)))
    return pins, directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    pins, directory = fetch(args.repo, args.tag, args.manifest_sha256, args.target, args.directory)
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as stream:
            stream.write(f'pins={pins}\nbundle_dir={directory}\n')
    print(f'Verified server pin manifest for {args.target}')


if __name__ == '__main__':
    main()
