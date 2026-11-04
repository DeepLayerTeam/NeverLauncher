#!/usr/bin/env python3
"""Capture and independently re-read a *real* 0.36.0/0.46.0 NeverLauncher migration.

Capture is performed on an isolated ORIGINAL install before freezing writers;
verify is performed on the migrated running 0.52.8 Backend. No mock, no
``status: passed`` from untrusted input, and no credentials in reports. A
historical source without the real API routes fails closed (not compatible).
This is an acceptance witness, not a data migrator or a GA signature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/integration'))
sys.path.insert(0, str(ROOT / 'scripts/operations'))
import live_upgrade_0480 as live
from sqlite_pg_cutover_0475 import storage_fingerprint, write_secure

SCHEMA = 'neverlauncher.legacy-live-upgrade-0528/v1'
ORIGINAL = ('0.36.0', '0.46.0')
SHA = re.compile(r'[a-f0-9]{64}\Z')


class Blocked(ValueError):
    pass


def require(value, message):
    if not value:
        raise Blocked(message)


def private_json(path):
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
            'private path must be absolute with no symlink components')
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1
            and not st.st_mode & 0o077 and 0 < st.st_size <= 131072,
            'private input must be owner-only nonlinked regular JSON (<=128 KiB)')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as f:
        first = os.fstat(f.fileno())
        require((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_nlink)
                == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_nlink),
                'private input replaced before reading')
        data = f.read(131073)
        last = os.fstat(f.fileno())
        require(len(data) == st.st_size and
                (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns, last.st_nlink)
                == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_nlink),
                'private input changed during reading')
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'duplicate JSON field')
            result[name] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    require(type(value) is dict, 'private document must be an object')
    return value


def sha_file(name, *, max_size=8 << 30):
    require(type(name) is str and name.startswith('/'), 'absolute file path required')
    path = Path(name)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'linked file path')
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= max_size,
            'invalid or linked source file')
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as f:
        first = os.fstat(f.fileno())
        require((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns)
                == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), 'source file replaced')
        for part in iter(lambda: f.read(1 << 20), b''):
            h.update(part)
        last = os.fstat(f.fileno())
        require((last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns)
                == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), 'source file mutated')
    return h.hexdigest()


def source_snapshot(cfg):
    paths = cfg.get('sourceFiles')
    require(type(paths) is dict and 1 <= len(paths) <= 24 and
            all(type(k) is str and re.fullmatch('[a-z][a-z0-9_-]{2,50}', k) for k in paths),
            'source files and stable labels required')
    fingerprints = {key: sha_file(path) for key, path in sorted(paths.items())}
    source = cfg.get('storageRoot')
    require(type(source) is str and source.startswith('/'), 'absolute original storage required')
    path = Path(source)
    require(path.is_dir() and not any(p.is_symlink() for p in (path, *path.parents)),
            'original storage cannot be symlinked')
    store_sha, count, size = storage_fingerprint(path)
    require(count > 0, 'real stored files required for acceptance')
    return {'files': fingerprints, 'storage': {'sha256': store_sha, 'count': count, 'size': size}}


def live_snapshot(cfg):
    base, creds = cfg['baseUrl'], Path(cfg['ownerCredentials'])
    require(base.startswith('https://') or base.startswith('http://127.0.0.1:'),
            'HTTPS or explicit loopback acceptance Backend required')
    require(type(cfg.get('projectId')) is str and type(cfg.get('profileId')) is str and
            type(cfg.get('channelId')) is str, 'project/profile/channel identity required')
    token, owner = live.owner_login(base, creds)
    rows = live.snapshot_api(base, token, cfg['projectId'], cfg['profileId'], cfg['channelId'])
    return {'owner': owner, 'project': cfg['projectId'], 'profile': cfg['profileId'],
            'channel': cfg['channelId'], 'api': rows}


def capture(cfg):
    require(cfg.get('sourceVersion') in ORIGINAL, 'unsupported legacy source version')
    actual = live.running_version(cfg['baseUrl'])
    require(actual == cfg['sourceVersion'], 'original Backend version differs from actual running version')
    return {'schema': SCHEMA, 'phase': 'original', 'sourceVersion': actual,
            'identity': live_snapshot(cfg), 'source': source_snapshot(cfg)}


def verify(cfg, baseline):
    require(baseline.get('schema') == SCHEMA and baseline.get('phase') == 'original'
            and baseline.get('sourceVersion') == cfg.get('sourceVersion') in ORIGINAL,
            'capture must originate from approved historical version')
    current = live.running_version(cfg['baseUrl'])
    require(current == (ROOT/'VERSION').read_text().strip() == '0.52.8',
            'migration target must be the running 0.52.8 Backend')
    # Snapshot old sources again; old writers must be stopped through cutover.
    require(source_snapshot(cfg) == baseline['source'], 'original source files changed during migration')
    now = live_snapshot(cfg)
    require(now == baseline['identity'], 'user UUID/roles, project, profile, channel or API state changed')
    target = cfg.get('targetStorageRoot')
    require(type(target) is str and target.startswith('/'),
            'absolute target storage required')
    original_root = Path(cfg['storageRoot']).resolve(strict=True)
    target_root = Path(target).resolve(strict=True)
    require(original_root != target_root and not target_root.is_relative_to(original_root)
            and not original_root.is_relative_to(target_root),
            'original and migrated storage must be distinct, non-nested roots')
    source = dict(cfg)
    source['storageRoot'] = target
    require(source_snapshot(source)['storage'] == baseline['source']['storage'],
            'target storage differs from original file hashes')
    return {'schema': SCHEMA, 'phase': 'migrated', 'sourceVersion': baseline['sourceVersion'],
            'targetVersion': current, 'sourceCaptureSha256': cfg['sourceCaptureSha256'],
            'ownerId': now['owner']['id'], 'projectId': now['project'],
            'sourceSha256': baseline['source']['storage']['sha256'],
            'status': 'LIVE_CHECKS_PASSED_REVIEW_REQUIRED', 'gaCertified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'verify'))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-capture', type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        cfg = private_json(args.config)
        require(not args.output.exists() and args.output.is_absolute() and args.output.parent.is_dir()
                and not args.output.parent.is_symlink() and not args.output.is_symlink(),
                'new private output in existing directory required')
        require(cfg.get('format') == SCHEMA, 'wrong config format')
        if args.action == 'capture':
            result = capture(cfg)
        else:
            require(args.source_capture is not None, 'original immutable capture required')
            baseline = private_json(args.source_capture)
            cfg['sourceCaptureSha256'] = sha_file(str(args.source_capture))
            result = verify(cfg, baseline)
        write_secure(args.output, (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
        print('LIVE historical migration', args.action, 'completed; independent review still required')
        return 0
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        print('BLOCKED legacy migration: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
