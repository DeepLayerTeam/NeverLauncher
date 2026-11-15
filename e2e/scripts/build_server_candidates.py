#!/usr/bin/env python3
"""Build reviewable server distributions in disposable, digest-pinned installer containers.

This is an acquisition step, NOT an approval or gameplay certificate. No release is published.
The operator must review each distribution before preparing the trusted pin manifest.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from prepare_server_bundle import VERSION, ENTRY, FORBIDDEN, prepare
from live_join import ID, read_json, require

IMAGE = re.compile(r'(?:docker\.io/)?itzg/minecraft-server@sha256:[0-9a-f]{64}\Z')
LOADER_ENV = {'fabric': 'FABRIC_LOADER_VERSION', 'quilt': 'QUILT_LOADER_VERSION',
              'forge': 'FORGE_VERSION', 'neoforge': 'NEOFORGE_VERSION'}


def candidate_command(row, spec, destination):
    require(row['scope'] == 'client' and not row.get('matchingServer') and row['os'] == 'linux',
            'Candidate installer supports ordinary Linux client targets only')
    require(set(spec) == {'image', 'loaderVersion', 'serverEntry'}, 'Unexpected candidate fields')
    image, version, entry = spec['image'], spec['loaderVersion'], spec['serverEntry']
    require(type(image) is str and IMAGE.fullmatch(image), 'Installer image must be pinned by SHA-256')
    require(type(version) is str and ((row['loader'] == 'vanilla' and version == '') or
            (row['loader'] in LOADER_ENV and VERSION.fullmatch(version) and version not in ('latest', 'latest-stable'))),
            'Exact resolved loader version required')
    require(type(entry) is str and ENTRY.fullmatch(entry) and entry.endswith(('.jar', '.sh')), 'Invalid server entry')
    require(row.get('loaderVersion', '') in ('', 'latest', 'latest-stable', version), 'Loader selector mismatch')
    require(VERSION.fullmatch(row['minecraft']), 'Invalid Minecraft version')
    cmd = ['docker', 'run', '--rm', '--platform', 'linux/amd64' if row['arch'] == 'x86_64' else 'linux/arm64',
           '--mount', f'type=bind,source={destination},target=/data',
           '-e', 'EULA=TRUE', '-e', 'SETUP_ONLY=TRUE', '-e', 'TYPE='+row['loader'].upper(),
           '-e', 'VERSION='+row['minecraft'], '-e', f'UID={os.getuid()}', '-e', f'GID={os.getgid()}']
    if version:
        # Legacy loader resolvers can include the Minecraft release in the exact ID.
        # Retain the exact ID in the candidate pin; the upstream installer expects the loader component.
        installer_version = version
        if row['loader'] == 'forge' and version.endswith('-'+row['minecraft']):
            installer_version = version.removesuffix('-'+row['minecraft'])
        if row['loader'] == 'neoforge' and version.startswith(row['minecraft']+'-'):
            installer_version = version.removeprefix(row['minecraft']+'-')
        cmd += ['-e', LOADER_ENV[row['loader']]+'='+installer_version]
    return cmd + [image]


def build(targets_path, spec_path, output, *, run=subprocess.run):
    targets = {r['id']: r for r in read_json(targets_path)['targets']}
    specs = read_json(spec_path)
    require(type(specs) is dict and specs, 'Expected nonempty target specification')
    output = Path(output).absolute()
    require(not output.exists(), 'Output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nl-server-candidates-', dir=output.parent) as tmp:
        root = Path(tmp)
        sources = {}
        for target, spec in sorted(specs.items()):
            require(type(target) is str and ID.fullmatch(target) and target in targets and type(spec) is dict, 'Invalid target specification')
            destination = root / target
            destination.mkdir()
            command = candidate_command(targets[target], spec, destination)
            run(command, check=True, timeout=1800)
            # Only remove generated top-level configuration; never package player/world data.
            # Any nested private files or symlinks are rejected by prepare_server_bundle.
            for name in FORBIDDEN | {'eula.txt'}:
                path = destination / name
                if path.is_symlink():
                    raise RuntimeError('Unexpected symbolic link: '+name)
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.is_file():
                    path.unlink()
            sources[target] = {'directory': str(destination), 'loaderVersion': spec['loaderVersion'],
                               'serverEntry': spec['serverEntry']}
        source_spec = root / 'sources.json'
        source_spec.write_text(json.dumps(sources), encoding='utf-8')
        return prepare(targets_path, source_spec, output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--targets', type=Path, default=Path('compatibility/targets.json'))
    p.add_argument('--spec', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--accept-minecraft-eula', action='store_true', required=True)
    args = p.parse_args()
    print('UNAPPROVED candidate manifest SHA-256:', build(args.targets, args.spec, args.output))


if __name__ == '__main__':
    main()
