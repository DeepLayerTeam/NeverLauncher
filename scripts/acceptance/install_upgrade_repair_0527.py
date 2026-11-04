#!/usr/bin/env python3
"""Destructive *physical* 0.52.7 E2E for two real signed offline installers.

Runs inside a new, private tmpfs mount on a dedicated Linux runner. A release
binary with its embedded production trust root is mandatory; this script never
supplies a replacement key, bypasses signature checks or forges a game run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
import time


class AcceptanceError(RuntimeError):
    pass


def require(condition: bool, message: str):
    if not condition:
        raise AcceptanceError(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def pinned(path: Path, digest: str):
    require(path.is_absolute() and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
            'absolute source and lowercase SHA-256 required')
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not st.st_mode & 0o022,
            'source must be immutable regular file')
    require(sha256(path) == digest, 'release input SHA-256 mismatch')


def run(argv: list[str], *, expect_ok: bool, timeout: int = 900) -> dict:
    started = time.monotonic()
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout, check=False)
    require(len(completed.stdout) < 128 * 1024 and len(completed.stderr) < 128 * 1024,
            'native process produced oversized logs')
    if expect_ok:
        require(completed.returncode == 0, f'{Path(argv[0]).name} failed (exit={completed.returncode})')
    else:
        require(completed.returncode != 0, f'{Path(argv[0]).name} incorrectly succeeded under fault')
    # Do not publish stdout/stderr: upstream tools may emit private credentials.
    return {'exitCode': completed.returncode, 'durationMs': round((time.monotonic() - started) * 1000),
            'stdoutSHA256': hashlib.sha256(completed.stdout).hexdigest(),
            'stderrSHA256': hashlib.sha256(completed.stderr).hexdigest()}


def valid_rel(value: str) -> Path:
    parsed = PurePosixPath(value)
    require(not parsed.is_absolute() and '..' not in parsed.parts and value not in ('', '.')
            and '\\' not in value and '\x00' not in value, 'unsafe relative managed file')
    return Path(*parsed.parts)


def active(root: Path) -> dict:
    base = root / '.launcher-installer'
    rows = []
    for slot in ('active-0.json', 'active-1.json'):
        path = base / slot
        if path.is_file() and not path.is_symlink():
            value = json.loads(path.read_text(encoding='utf-8'))
            require(isinstance(value.get('generation'), int) and value['generation'] > 0,
                    'invalid installed generation')
            rows.append(value)
    require(rows, 'missing durable activation receipts')
    return max(rows, key=lambda r: r['generation'])


def add_event(events: list, name: str, record: dict):
    events.append({'step': name, **record})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer', type=Path, required=True)
    parser.add_argument('--installer-sha256', required=True)
    parser.add_argument('--old-bundle', type=Path, required=True)
    parser.add_argument('--old-config-sha256', required=True)
    parser.add_argument('--new-bundle', type=Path, required=True)
    parser.add_argument('--new-config-sha256', required=True)
    parser.add_argument('--managed-repair-file', required=True,
                        help='relative path of installed verified game/Runtime file to corrupt and repair')
    parser.add_argument('--managed-repair-sha256', required=True)
    parser.add_argument('--tmpfs-mib', type=int, required=True)
    parser.add_argument('--scratch-parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--confirm', required=True)
    args = parser.parse_args()
    require(os.name == 'posix' and os.uname().sysname == 'Linux' and os.geteuid() == 0,
            'real ENOSPC acceptance requires privileged isolated Linux runner')
    require(args.confirm == 'DESTRUCTIVE-ISOLATED-0527', 'explicit isolated runner confirmation missing')
    require(1024 <= args.tmpfs_mib <= 65536, 'tmpfs size must be explicitly bounded (1–64 GiB)')
    require(args.scratch_parent.is_absolute() and args.scratch_parent.is_dir()
            and not args.scratch_parent.is_symlink(), 'scratch parent must be real absolute directory')
    require(args.output.is_absolute() and not args.output.exists() and args.output.parent.is_dir(),
            'output receipt must be a new absolute path')
    require(args.old_bundle.is_absolute() and args.new_bundle.is_absolute()
            and args.old_bundle != args.new_bundle, 'two different absolute signed bundle directories required')
    pinned(args.installer, args.installer_sha256)
    require(os.access(args.installer, os.X_OK), 'signed installer not executable')
    for bundle, expected in ((args.old_bundle,args.old_config_sha256),(args.new_bundle,args.new_config_sha256)):
        require(bundle.is_dir() and not bundle.is_symlink(), 'signed bundle directory missing or symlink')
        pinned(bundle / 'bootstrap.signed.json', expected)
    relative = valid_rel(args.managed_repair_file)
    require(len(relative.parts) >= 3 and relative.parts[0] in ('launcher', 'profiles')
            and not set(part.lower() for part in relative.parts).intersection({
                'saves', 'screenshots', 'resourcepacks', 'shaderpacks', 'user-files',
                'config.json', 'options.txt', '.launcher-installer',
            }), 'repair target must be signed-managed game/runtime bytes, not a world, user file or installer control')
    require(len(args.managed_repair_sha256) == 64, 'managed repair checksum required')
    # These are real existing release packages: fail before changing any state.
    for bundle in (args.old_bundle,args.new_bundle):
        run([str(args.installer),'verify','--bundle',str(bundle),'--offline'], expect_ok=True)

    events = []
    with tempfile.TemporaryDirectory(prefix='nl-real-0527-',dir=args.scratch_parent) as folder:
        mountpoint = Path(folder) / 'private-tmpfs'
        mountpoint.mkdir(mode=0o700)
        mounted = False
        try:
            run(['mount','-t','tmpfs','-o',f'size={args.tmpfs_mib}m,mode=0700',
                 'tmpfs',str(mountpoint)],expect_ok=True)
            mounted = True
            root = mountpoint / 'installation'
            def native(action: str, bundle: Path | None = None, offline: bool = True,
                       *, fail: bool = False):
                argv = [str(args.installer), action, '--root', str(root), '--no-start']
                if bundle is not None:
                    argv += ['--bundle',str(bundle)]
                if offline:
                    argv += ['--offline']
                return run(argv,expect_ok=not fail)
            add_event(events,'install-old',native('install',args.old_bundle))
            native('verify-installed')
            old = active(root)
            save = root / 'profiles' / 'acceptance' / 'saves' / 'world.dat'
            save.parent.mkdir(parents=True,mode=0o700)
            save.write_bytes(os.urandom(128))
            user_digest = sha256(save)
            def preserved():
                require(save.is_file() and sha256(save)==user_digest, 'user save unexpectedly changed')
            # A real untrusted modified package must fail before provisioning.
            with tempfile.TemporaryDirectory(prefix='nl-corrupt-0527-',dir=args.scratch_parent) as bad_dir:
                copy = Path(bad_dir) / 'untrusted'
                shutil.copytree(args.new_bundle,copy,symlinks=True)
                binary = copy / ('neverprestarter.exe' if os.name == 'nt' else 'neverprestarter')
                require(binary.is_file() and not binary.is_symlink(), 'new native Prestarter missing')
                with binary.open('ab') as out:
                    out.write(b'corrupt-package-0527')
                add_event(events,'corrupt-signed-package-rejected',native('update',copy,fail=True))
            require(active(root)==old,'bad package changed active release')
            preserved()
            # First prove that an isolated network namespace was *actually*
            # created. An EPERM/unshare failure is not a network fault PASS.
            run(['unshare','-n','--','python3','-c',
                 "import socket; assert {name for _,name in socket.if_nameindex()} <= {'lo'}"],
                expect_ok=True)
            # A real network namespace with no external interfaces forces a
            # *real* offline failure, provided new release needs remote inputs.
            network_argv=['unshare','-n','--',str(args.installer),'update','--root',str(root),
                          '--bundle',str(args.new_bundle),'--no-start']
            add_event(events,'disconnected-network-rejected',run(network_argv,expect_ok=False))
            require(active(root)==old,'network failure switched active release')
            preserved()
            # Physically consume available tmpfs blocks; this is kernel ENOSPC,
            # not an artificial error returned by a fake filesystem or test hook.
            free = shutil.disk_usage(mountpoint).free
            reserve = 128 * 1024  # enough for an error journal, not a real release
            require(free > reserve + (32 << 20),'insufficient scratch to create disk-full test')
            filler = mountpoint / '.disk-full-filler'
            try:
                with filler.open('wb') as fh:
                    os.posix_fallocate(fh.fileno(),0,free-reserve)
                require(shutil.disk_usage(mountpoint).free < (1<<20), 'real tmpfs capacity was not exhausted')
                add_event(events,'kernel-enospc-update-rejected',native('update',args.new_bundle,fail=True))
                require(active(root)==old,'disk-full failure switched active release')
                preserved()
            finally:
                filler.unlink(missing_ok=True)
            native('verify-installed')
            add_event(events,'update-new',native('update',args.new_bundle))
            native('verify-installed')
            current = active(root)
            require(current['generation'] > old['generation'] and current['release'] != old['release'],
                    'real update did not activate distinct signed release')
            preserved()
            managed = root / relative
            require(managed.is_file() and not managed.is_symlink() and sha256(managed)==args.managed_repair_sha256,
                    'original managed file not present with expected SHA-256')
            managed.write_bytes(b'corrupted-installed-game-file-0527')
            require(sha256(managed)!=args.managed_repair_sha256,'corruption fault did not occur')
            add_event(events,'repair-managed-file',native('repair',args.new_bundle))
            native('verify-installed')
            require(sha256(managed)==args.managed_repair_sha256,'repair did not restore exact managed bytes')
            preserved()
            add_event(events,'rollback-to-old',native('rollback'))
            native('verify-installed')
            rolled = active(root)
            require(rolled['generation'] > current['generation'] and rolled['release'] == old['release'],
                    'rollback did not activate previously signed release')
            preserved()
            add_event(events,'uninstall-preserve-saves',native('uninstall'))
            preserved()
            require(not (root/'.launcher-installer').exists(),'uninstall retained installer internals')
            report = {'schemaVersion':'1.0','version':'0.52.7', 'status':'PASS',
                      'installerSHA256':args.installer_sha256,'oldConfigSHA256':args.old_config_sha256,
                      'newConfigSHA256':args.new_config_sha256,'managedFileSHA256':args.managed_repair_sha256,
                      'checks':events,'finalSavedFileSHA256':user_digest}
            args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            os.chmod(args.output,0o600)
        finally:
            if mounted:
                # Never remove files while the private filesystem is mounted.
                subprocess.run(['umount',str(mountpoint)],check=True,stdout=subprocess.DEVNULL)
    print('0.52.7 real physical installer acceptance PASS; receipt saved privately')
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, subprocess.SubprocessError) as err:
        # Do not expose full subprocess diagnostics or raw provider tokens.
        print(f'0.52.7 physical acceptance BLOCKED/FAIL: {err.__class__.__name__}: {err}',file=__import__('sys').stderr)
        raise SystemExit(1)
