#!/usr/bin/env python3
"""Upload only existing, reproducibly built Sentry artifacts; fail closed on mismatches.

Supply credentials through environment SENTRY_AUTH_TOKEN, SENTRY_ORG, SENTRY_PROJECT.
No credentials, symbols or source maps are ever written into a release archive.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

RELEASE_RE = re.compile(r'^neverlauncher@\d+\.\d+\.\d+\+[a-f0-9]{7,40}$')

def release_id(version: str, commit: str) -> str:
    result = f'neverlauncher@{version}+{commit}'
    if not RELEASE_RE.fullmatch(result):
        raise ValueError('release must include an exact SemVer and a 7..40 digit git SHA')
    return result

def command(cli: str, *args: str) -> None:
    subprocess.run([cli, *args], check=True, timeout=180)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True, help='Full git SHA from the build being published')
    parser.add_argument('--js-dist', type=Path, help='Vite dist/ with hidden .js.map files')
    parser.add_argument('--native-symbols', type=Path, help='Path to unstripped PDB, dSYM or ELF symbols')
    parser.add_argument('--jvm-mapping', type=Path, help='Actual ProGuard/R8 mapping.txt, if obfuscation was used')
    parser.add_argument('--mapping-uuid', help='UUID embedded in the matching JVM build; required for --jvm-mapping')
    parser.add_argument('--jvm-jar', type=Path, help='Built JVM JAR containing META-INF/sentry-debug-meta.properties')
    parser.add_argument('--cli', default='sentry-cli')
    args = parser.parse_args(argv)
    release = release_id(args.version, args.commit)
    if not any((args.js_dist, args.native_symbols, args.jvm_mapping)):
        parser.error('at least one artifact is required')
    for env in ('SENTRY_AUTH_TOKEN', 'SENTRY_ORG', 'SENTRY_PROJECT'):
        if not os.environ.get(env):
            parser.error(f'{env} is required for a real upload')
    if args.jvm_mapping and (not args.mapping_uuid or not re.fullmatch(r'[0-9a-fA-F-]{32,36}', args.mapping_uuid) or not args.jvm_jar):
        parser.error('--jvm-mapping requires a UUID and --jvm-jar with embedded matching metadata')
    if args.jvm_mapping:
        try:
            with zipfile.ZipFile(args.jvm_jar) as bundle:
                names = [name for name in bundle.namelist() if name.endswith('sentry-debug-meta.properties')]
                if len(names) != 1 or bundle.getinfo(names[0]).file_size > 65536:
                    parser.error('JVM JAR must contain exactly one bounded Sentry UUID metadata entry')
                metadata = bundle.read(names[0]).decode('utf-8')
                fields = dict(line.split('=', 1) for line in metadata.splitlines() if '=' in line and not line.lstrip().startswith('#'))
                if fields.get('io.sentry.proguard.uuid', '').lower() != args.mapping_uuid.lower():
                    parser.error('mapping UUID does not match built JAR: refuse upload')
        except (OSError, zipfile.BadZipFile, UnicodeError) as exc:
            parser.error(f'cannot validate JVM mapping/build pair: {exc}')
        sample = args.jvm_mapping.read_text(encoding='utf-8')[:8192]
        if ' -> ' not in sample:
            parser.error('JVM mapping file does not look like a ProGuard mapping')
    root = Path(__file__).resolve().parents[2]
    if args.version != (root / 'VERSION').read_text().strip():
        parser.error('version differs from VERSION; refusing artifact mismatch')
    try:
        checked = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        checked = ''
    if checked and not checked.startswith(args.commit):
        parser.error('commit does not match the checkout used to build artifacts')
    js_maps = []
    if args.js_dist:
        dist = args.js_dist.resolve(strict=True)
        assets = dist / 'assets'
        js_maps = sorted(assets.glob('*.js.map'))
        if not js_maps:
            parser.error('Vite JS source maps missing: build production assets before upload')
        for sm in js_maps:
            js = sm.with_suffix('')
            if not js.is_file() or js.is_symlink() or sm.is_symlink():
                parser.error(f'map is not paired with an actual non-symlink bundle: {sm}')
            try:
                data = json.loads(sm.read_text())
            except (OSError, ValueError) as exc:
                parser.error(f'invalid source map {sm}: {exc}')
            if data.get('version') != 3 or not data.get('sources') or not data.get('mappings'):
                parser.error(f'invalid or empty source map {sm}')
    for name, path in (('native debug symbols', args.native_symbols),('JVM obfuscation mapping', args.jvm_mapping)):
        if path and (not path.exists() or path.is_symlink() or (path.is_file() and path.stat().st_size == 0)):
            parser.error(f'{name} not available: {path}')
    # Upload before stripping maps; failed uploads retain artifacts for retry.
    command(args.cli, 'releases', 'new', release)
    if args.js_dist:
        command(args.cli, 'sourcemaps', 'upload', str(assets), '--release', release, '--url-prefix', '~/assets')
    if args.native_symbols:
        command(args.cli, 'debug-files', 'upload', str(args.native_symbols.resolve()))
    if args.jvm_mapping:
        command(args.cli, 'upload-proguard', '--uuid', args.mapping_uuid, str(args.jvm_mapping.resolve()))
    command(args.cli, 'releases', 'finalize', release)
    # Only after *all* uploads completed successfully; source maps cannot leak in distributed bundles.
    for sm in js_maps:
        sm.unlink()
    print(f'Sentry release {release} uploaded; removed {len(js_maps)} private JS maps')
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f'Upload failed: {exc}; debug artifacts were retained for retry', file=sys.stderr)
        raise SystemExit(1)
