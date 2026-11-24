#!/usr/bin/env python3
"""Build and publish a complete, immutable-name GitHub Desktop release.

The signing stage has no repository write token. The publishing stage has no
private signing keys and independently verifies every asset before admission.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET

from native_updater_feed import build_feed, read_manifest, verify_signature, release_notes, TARGETS
from delivery_verify import verify_target, read_archive

STABLE = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
COMMIT = re.compile(r'[a-f0-9]{40}')
ARCHES = ('x64', 'arm64')


def version_tuple(version):
    if not STABLE.fullmatch(version):
        raise ValueError('Expected stable SemVer')
    return tuple(map(int, version.split('.')))


def package_name(version, platform, arch):
    if platform == 'linux':
        return f'launcher-linux-{arch}-{version}.tar.gz'
    return f'launcher-desktop-{version}-{platform}-{arch}.zip'


def installer_name(version, platform, arch):
    return f'NeverLauncher-{version}-{platform}-{arch}.' + {'windows': 'msi', 'linux': 'deb', 'macos': 'pkg'}[platform]


def digest(path):
    if not path.is_file() or path.is_symlink() or not path.stat().st_size:
        raise ValueError(f'Missing or invalid asset: {path.name}')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run(*args, capture=False):
    result = subprocess.run([str(a) for a in args], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else None


def required_env(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise ValueError(f'Missing required release configuration: {name}')
    return value


def prepare_trust():
    """Write only public signed trust material to the runner's temporary dir."""
    key = required_env('NL_UPDATER_PUBLIC_KEY')
    # Validate the actual minisign public-key encoding before starting costly builds.
    lines = base64.b64decode(key, validate=True).decode().splitlines()
    if len(lines) != 2:
        raise ValueError('Malformed updater public key')
    raw = base64.b64decode(lines[1], validate=True)
    if len(raw) != 42 or raw[:2] != b'Ed':
        raise ValueError('Invalid updater public key')
    for name in ('LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY', 'LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY'):
        if not re.fullmatch(r'[a-fA-F0-9]{64}', required_env(name)):
            raise ValueError(f'Invalid {name}')
    generation = required_env('LAUNCHER_COMPONENT_SECURITY_GENERATION')
    if not generation.isascii() or not generation.isdecimal() or not 0 < int(generation) < 2**64:
        raise ValueError('Invalid security generation')
    required_env('LAUNCHER_COMPONENT_DELEGATED_KEY_ID')
    policy = base64.b64decode(required_env('NL_COMPONENT_TRUST_POLICY_BASE64'), validate=True)
    if not 0 < len(policy) <= 128 * 1024:
        raise ValueError('Invalid trust policy length')
    # Verify root signature now; existing component signer also verifies active delegation and expiry.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    envelope = json.loads(policy)
    if envelope.get('schemaVersion') != '1.0':
        raise ValueError('Unknown trust policy schema')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(required_env('LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY'))).verify(
        bytes.fromhex(envelope['rootSignature']), b'Launcher-Trust-Policy-v1\n' + base64.b64decode(envelope['payload'], validate=True))
    path = Path(required_env('RUNNER_TEMP')) / 'nl-component-trust-policy.json'
    path.write_bytes(policy)
    with open(required_env('GITHUB_ENV'), 'a', encoding='utf-8') as out:
        out.write(f'LAUNCHER_COMPONENT_TRUST_POLICY_FILE={path}\n')


def extract_package(path, root):
    # Existing archive reader rejects traversal, special files and duplicate names.
    files = read_archive(path)
    seen = set()
    for name, data in files.items():
        parts = name.split('/')
        if any(part in ('', '.', '..') or part.endswith(('.', ' ')) or '\x00' in part for part in parts):
            raise ValueError('Unsafe installer archive path')
        normalized = name.casefold()
        if normalized in seen:
            raise ValueError('Case-colliding installer archive paths')
        seen.add(normalized)
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o755 if dest.name in ('launcher-cli', 'launcher-api', 'launcher-desktop', 'guard', 'runtime') else 0o644)


def wix_source(version, arch, payload, output):
    """Stable MSI upgrade identities; install the exact Authenticode-signed files."""
    ns = 'http://wixtoolset.org/schemas/v4/wxs'
    ET.register_namespace('', ns)
    def node(parent, name, **attrs):
        return ET.SubElement(parent, '{'+ns+'}'+name, attrs)
    root = ET.Element('{'+ns+'}Wix')
    upgrade = str(uuid.uuid5(uuid.NAMESPACE_URL, f'https://id.skif4er.ru/neverlauncher/msi/{arch}'))
    pkg = node(root, 'Package', Name='NeverLauncher', Manufacturer='SkiF4er', Version=version,
               UpgradeCode=upgrade, Scope='perMachine')
    node(pkg, 'MajorUpgrade', DowngradeErrorMessage='A newer NeverLauncher is already installed.')
    node(pkg, 'MediaTemplate', EmbedCab='yes')
    folder = node(pkg, 'StandardDirectory', Id='ProgramFiles64Folder')
    install = node(folder, 'Directory', Id='INSTALLFOLDER', Name='NeverLauncher-'+arch)
    feature = node(pkg, 'Feature', Id='Main', Title='NeverLauncher', Level='1')
    if not (payload / 'launcher-desktop.exe').is_file():
        raise ValueError('Windows Desktop executable is missing')
    for file in sorted(payload.iterdir()):
        if not file.is_file() or file.is_symlink():
            raise ValueError('Unexpected nested Windows package payload')
        suffix = hashlib.sha256(file.name.lower().encode()).hexdigest()[:24]
        comp_id = 'Payload'+suffix
        # Windows Installer identities are stable across versions, even if file order changes.
        guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'{upgrade}/{file.name.lower()}'))
        comp = node(install, 'Component', Id=comp_id, Guid=guid, Bitness='always64')
        node(comp, 'File', Id='File'+suffix, Source=str(file.resolve()), KeyPath='yes')
        node(feature, 'ComponentRef', Id=comp_id)
        if file.name == 'launcher-desktop.exe':
            # Advertised shortcut is owned and removed by MSI.
            node(comp[-1], 'Shortcut', Id='LaunchNeverLauncher', Directory='ProgramMenuFolder',
                 Name='NeverLauncher ('+arch+')', WorkingDirectory='INSTALLFOLDER', Advertise='yes')
    node(pkg, 'StandardDirectory', Id='ProgramMenuFolder')
    ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)


def native_installer(bundle, version, platform, arch):
    archive = bundle / package_name(version, platform, arch)
    target = ('darwin' if platform == 'macos' else platform) + '-' + arch
    verify_target(bundle, target, archive.name, version)
    result = bundle / installer_name(version, platform, arch)
    if result.exists():
        raise ValueError('Refusing to replace existing installer')
    with tempfile.TemporaryDirectory(prefix='nl-installer-') as tmp:
        work = Path(tmp)
        if platform == 'macos':
            # ditto preserves Apple resource forks and the notarized bundle's metadata.
            run('ditto', '-x', '-k', archive, work)
            app = work / 'Launcher.app'
            run('codesign', '--verify', '--deep', '--strict', app)
            run('xcrun', 'stapler', 'validate', app)
            identity = required_env('NL_MACOS_INSTALLER_IDENTITY')
            if not identity.startswith('Developer ID Installer:'):
                raise ValueError('Expected Developer ID Installer identity')
            run('productbuild', '--component', app, '/Applications', '--sign', identity, result)
            run('xcrun', 'notarytool', 'submit', result, '--keychain-profile', 'launcher-ci-notary', '--wait')
            run('xcrun', 'stapler', 'staple', result)
            run('xcrun', 'stapler', 'validate', result)
            run('pkgutil', '--check-signature', result)
            run('spctl', '--assess', '--type', 'install', result)
        elif platform == 'windows':
            payload = work / 'payload'
            extract_package(archive, payload)
            source = work / 'installer.wxs'
            wix_source(version, arch, payload, source)
            run('wix', 'build', '-arch', arch, '-o', result, source)
            # Authenticode is applied by the Windows workflow with the same release certificate.
        else:
            dest = work / 'deb'
            payload = dest / 'opt' / 'neverlauncher'
            extract_package(archive, work / 'unpacked')
            payload.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(work / 'unpacked' / 'launcher'), str(payload))
            control = dest / 'DEBIAN'
            control.mkdir()
            (control / 'control').write_text(
                f'Package: neverlauncher\nVersion: {version}\nArchitecture: {"amd64" if arch == "x64" else "arm64"}\n'
                'Maintainer: NeverLauncher Release Engineering\nSection: games\nPriority: optional\n'
                'Depends: libgtk-3-0t64 | libgtk-3-0, libwebkit2gtk-4.1-0, libsecret-1-0\n'
                'Description: NeverLauncher Desktop, Guard and Runtime\n', encoding='utf-8')
            desktop = dest / 'usr' / 'share' / 'applications' / 'neverlauncher.desktop'
            desktop.parent.mkdir(parents=True)
            desktop.write_text('[Desktop Entry]\nType=Application\nName=NeverLauncher\nExec=/opt/neverlauncher/launcher-desktop\nTerminal=false\nCategories=Game;\n', encoding='utf-8')
            run('dpkg-deb', '--build', '--root-owner-group', dest, result)
            run('dpkg-deb', '--info', result)
            run('dpkg-deb', '--extract', result, work / 'verify')
            for path in payload.iterdir():
                if digest(path) != digest(work / 'verify' / 'opt' / 'neverlauncher' / path.name):
                    raise ValueError('Debian package payload mismatch')
            fingerprint = required_env('NL_LINUX_GPG_FINGERPRINT').upper()
            if not re.fullmatch(r'[A-F0-9]{40}|[A-F0-9]{64}', fingerprint):
                raise ValueError('Expected full GPG fingerprint')
            asc = Path(str(result) + '.asc')
            run('gpg', '--batch', '--local-user', fingerprint, '--armor', '--detach-sign', '--output', asc, result)
            run('gpg', '--batch', '--verify', asc, result)
    digest(result)


def expected_names(version):
    packages = [package_name(version, p, a) for p, a in TARGETS]
    installers = [installer_name(version, p, a) for p, a in TARGETS]
    asc = [installer_name(version, 'linux', a) + '.asc' for a in ARCHES]
    return packages, installers, asc


def collect(source, output, version):
    """Only exact named assets from the six successful same-run build jobs."""
    packages, installers, asc = expected_names(version)
    output.mkdir(parents=True, exist_ok=False)
    for name in packages + installers + asc:
        matches = list(source.rglob(name))
        if len(matches) != 1:
            raise ValueError(f'Expected exactly one asset {name}, found {len(matches)}')
        digest(matches[0])
        shutil.copyfile(matches[0], output / name)


def asset_url(repo, version):
    if not REPO.fullmatch(repo):
        raise ValueError('Invalid GitHub repository')
    version_tuple(version)
    return f'https://github.com/{repo}/releases/download/v{version}'


def metadata(directory, version, repo, commit, key, write=False):
    """Verify exact filenames, all updater/installer signatures and complete target set."""
    if not COMMIT.fullmatch(commit):
        raise ValueError('Invalid source commit')
    packages, installers, asc = expected_names(version)
    signed = packages + installers + asc
    asset_names = sorted(signed + [name + '.sig' for name in signed])
    expected = set(asset_names) | (set() if write else {'latest.json', 'SHA256SUMS', 'RELEASE_DELIVERY.json'})
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError('Incomplete or unexpected release asset inventory')
    for platform, arch in TARGETS:
        manifest = read_manifest(directory / package_name(version, platform, arch))
        if (manifest.get('platform'), manifest.get('architecture')) != (platform, arch):
            raise ValueError('Package filename and signed target disagree')
    notes = release_notes(version, (Path(__file__).resolve().parents[2] / "CHANGELOG.md").read_text(encoding="utf-8"))
    feed = build_feed(version, asset_url(repo, version), [directory / n for n in packages], key, notes=notes)
    if set(feed['platforms']) != set(TARGETS.values()):
        raise ValueError('Release does not cover all six targets')
    for name in signed:
        sig = (directory / (name + '.sig')).read_text(encoding='utf-8').strip()
        # The feed builder already verifies update archive bytes. Verify the
        # remaining assets, and require the authenticated file name on all of them.
        if name not in packages:
            verify_signature(directory / name, sig, key, version)
        lines = base64.b64decode(sig, validate=True).decode().splitlines()
        comment = lines[2].removeprefix('trusted comment: ')
        if [v for v in comment.split('\t') if v.startswith('file:')] != ['file:'+name]:
            raise ValueError(f'Signed filename does not match asset: {name}')
    feed_text = json.dumps(feed, indent=2, sort_keys=True) + '\n'
    rows = [{'name': n, 'sha256': digest(directory / n), 'size': (directory / n).stat().st_size} for n in asset_names]
    receipt = {'version': version, 'tag': 'v'+version, 'sourceCommit': commit, 'repository': repo, 'assets': rows}
    texts = {'latest.json': feed_text, 'RELEASE_DELIVERY.json': json.dumps(receipt, indent=2, sort_keys=True)+'\n'}
    sums = {r['name']:r['sha256'] for r in rows}
    sums.update({n: hashlib.sha256(t.encode()).hexdigest() for n,t in texts.items()})
    texts['SHA256SUMS'] = ''.join(f'{v}  {n}\n' for n,v in sorted(sums.items()))
    for name, text in texts.items():
        if write:
            (directory / name).write_bytes(text.encode())
        elif (directory / name).read_bytes() != text.encode():
            raise ValueError(f'Release metadata mismatch: {name}')
    return sorted(expected | set(texts))


def sign(directory, version, repo, commit):
    packages, installers, asc = expected_names(version)
    private = required_env('NL_UPDATER_PRIVATE_KEY_BASE64')
    env = dict(os.environ)
    env.pop('TAURI_SIGNING_PRIVATE_KEY', None)
    # Do not expose the private key in command arguments or the artifact directory.
    with tempfile.TemporaryDirectory(prefix='nl-updater-sign-') as tmp:
        path = Path(tmp) / 'updater.key'
        path.write_bytes(base64.b64decode(private, validate=True))
        path.chmod(0o600)
        env['TAURI_SIGNING_PRIVATE_KEY_PATH'] = str(path)
        env.pop('NL_UPDATER_PRIVATE_KEY_BASE64', None)
        for name in packages + installers + asc:
            digest(directory / name)
            subprocess.run(['cargo', 'tauri', 'signer', 'sign', '--app-version', version,
                            str(directory / name)], env=env, check=True)
    metadata(directory, version, repo, commit, required_env('NL_UPDATER_PUBLIC_KEY'), write=True)


def gh_json(*args):
    return json.loads(run('gh', *args, capture=True))


def releases(repo):
    return [row for page in gh_json('api', '--paginate', '--slurp', f'repos/{repo}/releases?per_page=100') for row in page]


def check_release_order(rows, version, allow_draft=False):
    target = version_tuple(version)
    for row in rows:
        tag = row['tag_name']
        if tag == 'v'+version and not (allow_draft and row['draft']):
            raise ValueError('Release already exists; never replace it')
        if not row['draft'] and not row['prerelease'] and STABLE.fullmatch(tag.removeprefix('v')):
            if version_tuple(tag.removeprefix('v')) >= target:
                raise ValueError('Release is not newer than the published stable channel')


def check_remote_assets(remote, directory, names):
    if len(remote) != len(names) or {a['name'] for a in remote} != set(names):
        raise ValueError('Draft asset inventory does not match the verified release')
    for asset in remote:
        path = directory / asset['name']
        if (asset['state'] != 'uploaded' or asset['size'] != path.stat().st_size or
                asset.get('digest') != 'sha256:'+digest(path)):
            raise ValueError(f'GitHub upload digest/state mismatch: {path.name}')


def publish(directory, version, repo, commit):
    names = metadata(directory, version, repo, commit, required_env('NL_UPDATER_PUBLIC_KEY'))
    if required_env('GITHUB_REF') != 'refs/heads/main' or required_env('GITHUB_SHA') != commit:
        raise ValueError('Only the exact main workflow commit may publish')
    if gh_json('api', f'repos/{repo}')['visibility'] != 'public':
        raise ValueError('Native updater requires a public release repository')
    check_release_order(releases(repo), version)
    tag = 'v'+version
    ref = 'refs/tags/'+tag
    matching = gh_json('api', f'repos/{repo}/git/matching-refs/tags/{tag}')
    if not any(item['ref'] == ref for item in matching):
        run('gh', 'api', '--method', 'POST', f'repos/{repo}/git/refs', '-f', f'ref={ref}', '-f', f'sha={commit}')
    if gh_json('api', f'repos/{repo}/commits/{tag}')['sha'] != commit:
        raise ValueError('Existing release tag points to different source')
    run('gh', 'release', 'create', tag, '--repo', repo, '--verify-tag', '--draft', '--title', f'NeverLauncher {version}', '--notes', json.loads((directory / 'latest.json').read_text(encoding='utf-8'))['notes'])
    # Never clobber an asset. Any error leaves a draft, not a broken public feed.
    run('gh', 'release', 'upload', tag, '--repo', repo, *[directory / n for n in names])
    rows = releases(repo)
    check_release_order(rows, version, allow_draft=True)
    draft = [row for row in rows if row['tag_name'] == tag and row['draft']]
    if len(draft) != 1:
        raise ValueError('Expected exactly one unpublished draft')
    remote = [a for page in gh_json('api', '--paginate', '--slurp', f'repos/{repo}/releases/{draft[0]["id"]}/assets?per_page=100') for a in page]
    check_remote_assets(remote, directory, names)
    if gh_json('api', f'repos/{repo}/commits/{tag}')['sha'] != commit:
        raise ValueError('Release tag changed during upload')
    check_release_order(releases(repo), version, allow_draft=True)
    run('gh', 'release', 'edit', tag, '--repo', repo, '--draft=false', '--latest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('prepare-trust')
    p = sub.add_parser('installer')
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--platform', choices=['windows', 'linux', 'macos'], required=True)
    p.add_argument('--arch', choices=ARCHES, required=True)
    p = sub.add_parser('collect')
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version', required=True)
    for command in ('sign', 'verify', 'publish'):
        p = sub.add_parser(command)
        p.add_argument('--directory', type=Path, required=True)
        p.add_argument('--version', required=True)
        p.add_argument('--repo', required=True)
        p.add_argument('--commit', required=True)
    args = parser.parse_args()
    if args.command == 'prepare-trust':
        prepare_trust()
        return
    version_tuple(args.version)
    if args.command == 'installer':
        native_installer(args.bundle.resolve(), args.version, args.platform, args.arch)
    elif args.command == 'collect':
        collect(args.source, args.output, args.version)
    elif args.command == 'sign':
        sign(args.directory, args.version, args.repo, args.commit)
    elif args.command == 'verify':
        metadata(args.directory, args.version, args.repo, args.commit, required_env('NL_UPDATER_PUBLIC_KEY'))
    else:
        publish(args.directory, args.version, args.repo, args.commit)


if __name__ == '__main__':
    main()
