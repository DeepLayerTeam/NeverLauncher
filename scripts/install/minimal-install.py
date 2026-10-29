#!/usr/bin/env python3
"""Native, single-host SQLite installer for the NeverLauncher API.

Requires an already-built API binary and actual platform policy JSON files.
This program does not manufacture signing evidence or turn off production gates.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from urllib.parse import urlsplit


def reject(message):
    raise ValueError(message)


def owned_directory(path: Path):
    if not path.is_absolute() or path.is_symlink():
        reject(f"directory must be absolute and not a symlink: {path}")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            reject(f"directory must be owned by installer and private (0700): {path}")
    else:
        path.mkdir(mode=0o700, parents=True)
        os.chmod(path, 0o700)
    return path


def policy(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 1024 * 1024:
        reject(f"policy must be a regular, non-group-writable JSON file <= 1 MiB: {path}")
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or not value:
        reject(f"policy must be a nonempty JSON object: {path}")
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def check_binary(path: Path):
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        reject('--binary must point to an existing absolute executable (not a symlink)')
    if path.stat().st_mode & 0o022:
        reject('API binary is writable by group or others')


def generate(root: Path, public: str, binary: Path, guard: Path, bridge: Path, listen: str):
    check_binary(binary)
    url = urlsplit(public)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment or url.port == 0:
        reject('public URL must be a clean HTTPS origin, without path, credentials or query')
    if not listen.startswith('127.0.0.1:'):
        reject('minimal API HTTP listener must bind to 127.0.0.1 behind HTTPS proxy')
    port = listen.removeprefix('127.0.0.1:')
    if not port.isdecimal() or not (1 <= int(port) <= 65535):
        reject('invalid HTTP listen port')
    guard_policy = policy(guard)
    bridge_policy = policy(bridge)
    root = root.resolve(strict=False)
    if not root.is_absolute() or root == Path('/'):
        reject('root must be an absolute private directory')
    envfile = root / 'config' / 'backend.env'
    if envfile.exists() or envfile.is_symlink():
        reject('installation exists; refusing to overwrite secrets or state')
    if root.exists():
        owned_directory(root)
    else:
        owned_directory(root)
    for part in ('config', 'db', 'storage', 'backups', 'extensions'):
        owned_directory(root / part)
    config = {
        'NEVERLAUNCHER_ENV': 'production',
        'NEVERLAUNCHER_HTTP_ADDR': listen,
        'NEVERLAUNCHER_PUBLIC_URL': public,
        'NEVERLAUNCHER_DEPLOYMENT_MODE': 'single-node',
        'NEVERLAUNCHER_REPOSITORY_DRIVER': 'sqlite',
        'NEVERLAUNCHER_DATABASE_DSN': str(root/'db'/'http.sqlite'),
        'NEVERLAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH': str(root/'db'/'coordinator.sqlite'),
        'NEVERLAUNCHER_STORAGE_DRIVER': 'local',
        'NEVERLAUNCHER_STORAGE_LOCAL_PATH': str(root/'storage'),
        'NEVERLAUNCHER_BACKUP_ROOT': str(root/'backups'),
        'NEVERLAUNCHER_EXTENSION_ROOT': str(root/'extensions'),
        'NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED': 'false',
        'NEVERLAUNCHER_RATE_LIMIT_ENABLED': 'true',
        'NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED': 'true',
        'NEVERLAUNCHER_RATE_LIMIT_GLOBAL_PER_MINUTE': '1200',
        'NEVERLAUNCHER_RATE_LIMIT_AUTH_PER_MINUTE': '20',
        'NEVERLAUNCHER_RATE_LIMIT_SERVERBRIDGE_PER_MINUTE': '6000',
        'NEVERLAUNCHER_PERSISTENT_SESSIONS': 'true',
        'NEVERLAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION': 'true',
        'NEVERLAUNCHER_BOOTSTRAP_TOKEN': secrets.token_urlsafe(48),
        'NEVERLAUNCHER_AUTH_TOKEN_SECRET': secrets.token_urlsafe(64),
        'NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY': secrets.token_hex(32),
        'NEVERLAUNCHER_EXTENSION_SECRETS_KEY': secrets.token_hex(32),
        'NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON': guard_policy,
        'NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON': bridge_policy,
        'NEVERLAUNCHER_WEBAUTHN_RP_ID': url.hostname.lower(),
        'NEVERLAUNCHER_WEBAUTHN_RP_NAME': 'NeverLauncher',
        'NEVERLAUNCHER_WEBAUTHN_ORIGINS': public,
        'NEVERLAUNCHER_CORS_ALLOWED_ORIGINS': public,
    }
    if any('\n' in value or '\r' in value or '\x00' in value for value in config.values()):
        reject('configuration contains unsupported control characters')
    content = ''.join(f'{key}={value}\n' for key,value in sorted(config.items()))
    fd = os.open(envfile, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        dfd = os.open(envfile.parent, os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except BaseException:
        envfile.unlink(missing_ok=True)
        raise
    return envfile


def read_env(file: Path):
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        reject('configuration file must be owned by current user and mode 0600')
    values = {}
    for line in file.read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'): continue
        if '=' not in line: reject('invalid config line')
        key,value = line.split('=',1)
        if not key.startswith('NEVERLAUNCHER_') or key in values: reject('invalid config key')
        values[key] = value
    if values.get('NEVERLAUNCHER_REPOSITORY_DRIVER') != 'sqlite' or values.get('NEVERLAUNCHER_DEPLOYMENT_MODE') != 'single-node':
        reject('not a minimal SQLite config')
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='create private, persistent minimal installation')
    init.add_argument('--root', type=Path, required=True)
    init.add_argument('--binary', type=Path, required=True)
    init.add_argument('--public-url', required=True)
    init.add_argument('--guard-policy', type=Path, required=True)
    init.add_argument('--bridge-policy', type=Path, required=True)
    init.add_argument('--listen', default='127.0.0.1:8080')
    for name in ('check', 'run'):
        p = sub.add_parser(name, help='verify deployment configuration' if name=='check' else 'run API in foreground')
        p.add_argument('--env-file', type=Path, required=True)
        p.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'init':
        result = generate(args.root,args.public_url,args.binary,args.guard_policy,args.bridge_policy,args.listen)
        print(f'Created private minimal install: {result}')
        print('Keep backend.env safe, configure HTTPS reverse proxy, run check, then run the API and complete /api/v1/install/bootstrap-admin and /api/v1/install/first-project.')
        return 0
    check_binary(args.binary)
    environment = {key:value for key,value in os.environ.items() if not key.startswith('NEVERLAUNCHER_')}
    environment.update(read_env(args.env_file))
    # No inherited external Redis/PostgreSQL settings may change the selected topology.
    environment.pop('NEVERLAUNCHER_REDIS_URL', None)
    environment.pop('NEVERLAUNCHER_REDIS_ADDR', None)
    command = [str(args.binary), 'diagnose', 'deployment'] if args.command=='check' else [str(args.binary)]
    if args.command == 'check':
        return subprocess.run(command,env=environment,check=False).returncode
    os.execve(str(args.binary),command,environment)


if __name__=='__main__':
    try: sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'minimal install: {exc}',file=sys.stderr)
        sys.exit(2)
