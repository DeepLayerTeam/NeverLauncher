#!/usr/bin/env python3
"""Package operator-reviewed, real server installations for compatibility CI.

This does not download servers, approve their provenance, or certify gameplay.
The operator must review the source distributions and independently approve
(and publish) the resulting manifest SHA-256 before using it in Actions.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile
from types import SimpleNamespace

from live_join import ID, file_sha256, load_pinned_bundle, read_json, require
from fetch_server_bundle import ASSET

VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z')
ENTRY = re.compile(r'[A-Za-z0-9._-]{1,80}\Z')
MAX_FILES = 50000
MAX_BYTES = 8 * 1024**3
# Only a fresh server distribution is suitable: never publish live player data,
# access lists, logs, credentials or previously generated world state.
FORBIDDEN = {'world', 'world_nether', 'world_the_end', 'logs', 'crash-reports',
             'server.properties', 'ops.json', 'whitelist.json', 'banned-ips.json',
             'banned-players.json', 'usercache.json', '.env', 'playerdata'}


def pack_source(source, destination, entry):
    source = Path(source).absolute()
    require(source.is_dir() and not source.is_symlink(), 'Server source must be a real directory')
    source = source.resolve(strict=True)
    require(not Path(destination).resolve().is_relative_to(source), "Output must be outside the reviewed server source")
    executable = source / entry
    require(executable.is_file() and not executable.is_symlink(), 'Missing server entry: ' + entry)
    if entry.endswith('.jar'):
        require(zipfile.is_zipfile(executable), 'Server JAR is not a ZIP archive')
    files = []
    seen = set()
    total = 0
    for folder, dirs, names in os.walk(source, followlinks=False):
        dirs.sort(); names.sort()
        for name in dirs + names:
            path = Path(folder) / name
            rel = path.relative_to(source).as_posix()
            info = path.lstat()
            require(not path.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'Unsafe source entry: ' + rel)
            require(not any(part.lower() in FORBIDDEN or part.startswith('.') for part in Path(rel).parts), 'Live/private server data: ' + rel)
            require(not any(c in rel for c in ('\\', ':', '\x00')) and rel.casefold() not in seen, 'Unsafe or colliding source path: ' + rel)
            seen.add(rel.casefold())
            require(len(seen) <= MAX_FILES, 'Too many source entries')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                require(total <= MAX_BYTES, 'Server installation exceeds size limit')
                files.append((rel, path, info.st_size))
    require(files, 'Empty server installation')
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for rel, path, size in sorted(files):
            info = zipfile.ZipInfo(rel, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.file_size = size
            with path.open('rb') as src, archive.open(info, 'w', force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
    require(destination.stat().st_size <= 3 * 1024**3, 'Server ZIP exceeds consumer size limit')


def prepare(targets_path, spec_path, output):
    targets = {row['id']: row for row in read_json(targets_path)['targets']}
    spec = read_json(spec_path)
    require(type(spec) is dict and spec, 'Expected a nonempty object keyed by target ID')
    output = Path(output).absolute()
    require(not output.exists(), 'Output directory already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nl-server-pins-', dir=output.parent) as tmp:
        stage = Path(tmp) / 'release'
        stage.mkdir()
        rows = {}
        for target, source in sorted(spec.items()):
            require(type(target) is str and ID.fullmatch(target) and target in targets, 'Unknown target: ' + str(target))
            require(type(source) is dict and set(source) == {'directory', 'loaderVersion', 'serverEntry'}, 'Invalid source specification: ' + target)
            row = targets[target]
            require(row.get('scope') == 'client' and not row.get('matchingServer'), 'Not an ordinary client target: ' + target)
            loader = row['loader']; version = source['loaderVersion']; entry = source['serverEntry']
            require(type(version) is str and ((loader == 'vanilla' and version == '') or (loader != 'vanilla' and VERSION.fullmatch(version) and version not in ('latest', 'latest-stable'))), 'Exact resolved loader version required: ' + target)
            selector = row.get('loaderVersion', '')
            require(selector in ('', 'latest', 'latest-stable') or selector == version, 'Pinned target loader version mismatch: ' + target)
            require(type(entry) is str and ENTRY.fullmatch(entry) and entry not in ('.', '..') and entry.endswith(('.jar', '.sh', '.bat')), 'Invalid server entry: ' + target)
            require((row['os'] == 'windows' and not entry.endswith('.sh')) or (row['os'] != 'windows' and not entry.endswith('.bat')), 'Server entry OS mismatch: ' + target)
            directory = Path(source['directory'])
            if not directory.is_absolute():
                directory = Path(spec_path).resolve().parent / directory
            name = target + '.zip'
            pack_source(directory, stage / name, entry)
            rows[target] = dict(loader=loader, minecraft=row['minecraft'], loaderVersion=version, file=name, sha256=file_sha256(stage / name), serverEntry=entry)
        manifest = stage / ASSET
        manifest.write_text(json.dumps({'schema': 'launcher.compatibility-server/0.52.4', 'targets': rows}, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        for target, row in rows.items():
            load_pinned_bundle(SimpleNamespace(target=target, loader=row['loader'], minecraft=row['minecraft'], loader_version=row['loaderVersion'], pins=str(manifest), bundle_dir=str(stage)))
        digest = file_sha256(manifest)
        stage.rename(output)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--targets', type=Path, default=Path('compatibility/targets.json'))
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print('Candidate manifest SHA-256 (operator review required):', prepare(args.targets, args.spec, args.output))


if __name__ == '__main__':
    main()
