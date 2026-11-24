#!/usr/bin/env python3
"""Publishable Tauri feed from final, version-signed component archives.

Does not create or replace the underlying platform signatures. Run after
existing release verification with the independently pinned updater public key.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
from urllib.parse import quote, urlsplit
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_PACKAGE = 512 * 1024 * 1024
TARGETS = {(os, arch): f'{tauri_os}-{tauri_arch}'
           for os, tauri_os in [('windows', 'windows'), ('linux', 'linux'), ('macos', 'darwin')]
           for arch, tauri_arch in [('x64', 'x86_64'), ('arm64', 'aarch64')]}
MODES = {'windows': 'authenticode-rfc3161', 'linux': 'sha256-delivery', 'macos': 'developer-id-notarized'}


def read_manifest(path):
    if not 0 < path.stat().st_size <= MAX_PACKAGE:
        raise ValueError('Invalid package size')
    name = 'COMPONENT_UPDATE_MANIFEST.json'
    def decode(entries, read):
        matches = [(entry, size) for entry, filename, size in entries if filename.rsplit('/', 1)[-1] == name]
        if len(matches) != 1 or not 0 < matches[0][1] <= 1024 * 1024:
            raise ValueError('Missing, duplicated or oversized component manifest')
        return json.loads(read(matches[0][0]))
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path) as z:
            return decode(((e, e.filename, e.file_size) for e in z.infolist() if not e.is_dir()), z.read)
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'r:gz') as t:
            return decode(((e, e.name, e.size) for e in t if e.isfile()), lambda e: t.extractfile(e).read())
    raise ValueError('Unsupported package format')


def verify_signature(path, signature, public_key, version):
    key_lines = base64.b64decode(public_key, validate=True).decode().splitlines()
    sig_lines = base64.b64decode(signature, validate=True).decode().splitlines()
    if len(key_lines) != 2 or len(sig_lines) != 4 or not sig_lines[2].startswith('trusted comment: '):
        raise ValueError('Malformed Tauri minisign data')
    key = base64.b64decode(key_lines[1], validate=True)
    sig = base64.b64decode(sig_lines[1], validate=True)
    global_sig = base64.b64decode(sig_lines[3], validate=True)
    if len(key) != 42 or key[:2] != b'Ed' or len(sig) != 74 or sig[:2] != b'ED' or key[2:10] != sig[2:10] or len(global_sig) != 64:
        raise ValueError('Unexpected minisign algorithm or signing key')
    trusted = sig_lines[2][len('trusted comment: '):]
    if [field for field in trusted.split('\t') if field.startswith('version:')] != [f'version:{version}']:
        raise ValueError('Signature version does not match release')
    digest = hashlib.blake2b()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    verifier = Ed25519PublicKey.from_public_bytes(key[10:])
    verifier.verify(sig[10:], digest.digest())
    verifier.verify(global_sig, sig[10:] + trusted.encode())


def release_notes(version, changelog):
    """Extract exactly the requested release section, not the newest section."""
    sections = re.split(r'^##\s+', changelog, flags=re.MULTILINE)
    matches = [section.partition('\n')[2].strip() for section in sections[1:]
               if re.match(rf'^{re.escape(version)}(?:\s|$)', section)]
    if len(matches) != 1 or not matches[0] or len(matches[0]) > 16000:
        raise ValueError(f'Missing, duplicate or oversized release notes for {version}')
    return matches[0]


def build_feed(version, base_url, packages, public_key, notes=None):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Only stable SemVer is publishable')
    u = urlsplit(base_url)
    if u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment:
        raise ValueError('Asset base URL must be HTTPS without credentials/query/fragment')
    platforms = {}
    for path in packages:
        manifest = read_manifest(path)
        os_name, arch = manifest['platform'], manifest['architecture']
        target = TARGETS.get((os_name, arch))
        if (not target or target in platforms or manifest.get('product') != 'Launcher' or
                manifest.get('productVersion') != version or manifest.get('trustMode') != MODES[os_name] or
                (os_name != 'linux' and not path.name.endswith('.zip'))):
            raise ValueError(f'Invalid or duplicate component target: {path.name}')
        roles = {item['component'] for item in manifest['components']}
        if roles != ({'desktop', 'guard', 'runtime', 'sensor'} if os_name == 'windows' else {'desktop', 'guard', 'runtime'}):
            raise ValueError('Incomplete component set')
        if not any(item['component'] == 'updater' for item in manifest.get('supportFiles', [])):
            raise ValueError('Missing transactional helper')
        signature = Path(str(path) + '.sig').read_text(encoding='utf-8').strip()
        verify_signature(path, signature, public_key, version)
        platforms[target] = {'url': base_url.rstrip('/') + '/' + quote(path.name, safe=''), 'signature': signature}
    if not platforms:
        raise ValueError('At least one signed platform is required')
    feed = {'version': version, 'platforms': platforms}
    if notes is not None:
        if not isinstance(notes, str) or not notes.strip() or len(notes) > 16000:
            raise ValueError('Invalid release notes')
        feed['notes'] = notes
    return feed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--changelog', type=Path, default=Path(__file__).resolve().parents[2] / 'CHANGELOG.md')
    parser.add_argument('packages', type=Path, nargs='+')
    args = parser.parse_args()
    public_key = os.environ.get('NL_UPDATER_PUBLIC_KEY', '').strip()
    if not public_key:
        parser.error('NL_UPDATER_PUBLIC_KEY is required')
    feed = build_feed(args.version, args.base_url, args.packages, public_key,
                      notes=release_notes(args.version, args.changelog.read_text(encoding='utf-8')))
    tmp = args.output.with_name(args.output.name + '.tmp')
    tmp.write_text(json.dumps(feed, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(tmp, args.output)

if __name__ == '__main__':
    main()
