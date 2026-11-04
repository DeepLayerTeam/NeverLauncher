#!/usr/bin/env python3
"""Destructive 0.52.6 acceptance using real HTTPS API, signed native Runtime and a Minecraft JVM.

Requires an isolated project with an already-uploaded v3/schema-5 draft (real
files), recent phishing-resistant/MFA administrator token, a local Minecraft
player, and independent SHA-256 pins for native binaries. It does not create
attestations or bypass release policy. Incomplete validation remains BLOCKED.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text().strip()
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[a-z0-9][a-z0-9._-]{1,95}\Z')


class Blocked(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise Blocked(reason)
    return value


def strict_object(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result, 'duplicate field in JSON evidence')
        result[k] = v
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeError, ValueError, TypeError):
        raise Blocked('invalid JSON from an external component') from None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path, *, limit=1024 * 1024 * 1024):
    need(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
         'expected pinned regular file is unavailable/unsafe')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(part)
    return digest.hexdigest()


def private_file(path: Path, *, limit=65536):
    need(path.is_absolute() and not path.is_symlink(), 'private input must be an absolute non-symlink path')
    st = path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
         not st.st_mode & 0o077 and 0 < st.st_size <= limit, 'private input owner/mode/size invalid')
    return path.read_bytes()


def atomic_private_json(path: Path, doc):
    need(path.is_absolute() and not path.is_symlink(), 'output must be an absolute non-symlink path')
    path.parent.mkdir(parents=True, exist_ok=True)
    need(not path.parent.is_symlink(), 'output parent cannot be a symlink')
    tmp = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(doc, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *unused):
        return None


class API:
    def __init__(self, origin):
        parts = urlsplit(origin)
        try:
            port = parts.port
        except ValueError:
            raise Blocked('invalid HTTPS origin port') from None
        need(port is None or 1 <= port <= 65535, 'invalid HTTPS origin port')
        need(parts.scheme == 'https' and parts.hostname and not parts.username and not parts.password
             and parts.path in ('', '/') and not parts.query and not parts.fragment,
             'production acceptance requires a clean HTTPS origin')
        self.origin = origin.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def request(self, method, route, *, token='', body=None, content_type='application/json', expected=(200,), limit=5 << 20):
        need(route.startswith('/api/v1/') and not route.startswith('//') and
             not any(ch in route for ch in ('\\', '#', '\r', '\n')),
             'unsafe API path')
        need(method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'), 'invalid HTTP method')
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if body is not None:
            if not isinstance(body, bytes):
                body = json.dumps(body, separators=(',', ':')).encode()
            headers['Content-Type'] = content_type
        req = Request(self.origin + route, headers=headers, data=body, method=method)
        try:
            with self.opener.open(req, timeout=90) as resp:
                status, raw = resp.status, resp.read(limit + 1)
        except HTTPError as exc:
            status, raw = exc.code, exc.read(min(limit, 4096) + 1)
        except (OSError, URLError, TimeoutError):
            raise Blocked('TLS/HTTPS Backend request failed') from None
        need(status in expected and len(raw) <= limit,
             f'{method} {route.split("?")[0]} returned unexpected HTTP status {status} / size')
        return raw

    def json(self, method, route, **kwargs):
        value = parse_json(self.request(method, route, **kwargs))
        need(isinstance(value, dict), 'Backend returned a non-object JSON document')
        return value


def multipart_png(kind, content, revision):
    need(kind in ('skin', 'cape') and len(content) <= 4 << 20, 'invalid PNG upload size or kind')
    boundary = 'nl-0526-' + secrets.token_hex(18)
    body = bytearray()
    for name, value in [('expectedRevision', str(revision)), ('model', 'classic'), ('visibility', 'public')]:
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{kind}.png"\r\nContent-Type: image/png\r\n\r\n'.encode())
    body.extend(content)
    body.extend(f'\r\n--{boundary}--\r\n'.encode())
    return bytes(body), f'multipart/form-data; boundary={boundary}'


def check_png(content, kind):
    need(content.startswith(b'\x89PNG\r\n\x1a\n') and len(content) >= 33 and len(content) <= 4 << 20,
         f'{kind} is not a bounded PNG')
    width, height = __import__('struct').unpack('>II', content[16:24])
    need(width >= 64 and width <= 1024 and width % 64 == 0 and
         (height in (width // 2, width) if kind == 'skin' else height == width // 2),
         f'unsupported {kind} PNG geometry')


def upload_texture(api: API, token: str, kind: str, png: bytes):
    check_png(png, kind)
    listing = api.json('GET', '/api/v1/me/textures', token=token).get('data', {})
    need(isinstance(listing.get('profileUuid'), str), 'no canonical local Minecraft profile')
    existing = [x for x in listing.get('items', []) if x.get('kind') == kind and not x.get('projectId')]
    need(len(existing) <= 1, 'ambiguous local texture assignment')
    revision = existing[0]['revision'] if existing else 0
    body, content_type = multipart_png(kind, png, revision)
    updated = api.json('POST', f'/api/v1/me/textures/{kind}/upload', body=body,
                       content_type=content_type, token=token, expected=(200, 201))
    selected = updated.get('data', {})
    digest = selected.get('blobDigest') or selected.get('digest')
    need(isinstance(digest, str) and HEX.fullmatch(digest), f'{kind} upload lacks a real blob digest')
    observed = api.request('GET', f'/api/v1/me/textures/{kind}/image', token=token, limit=4 << 20)
    need(sha(observed) == digest, f'{kind} bytes served to player do not match selected digest')
    check_png(observed, kind)
    current = api.json('GET', '/api/v1/me/textures', token=token).get('data', {})
    need(current.get('profileUuid') == listing['profileUuid'] and any(
        item.get('kind') == kind and item.get('blobDigest') == digest for item in current.get('items', [])),
        f'{kind} assignment did not persist on the Backend')
    return {'kind': kind, 'blobSha256': digest, 'profileUuid': listing['profileUuid'],
            'byteSize': len(observed)}


def native(binary: Path, args, *, timeout=660):
    completed = subprocess.run([str(binary), *map(str, args)], timeout=timeout,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(completed.returncode == 0 and len(completed.stdout) <= 2 << 20,
         'native Runtime execution did not complete successfully')
    return parse_json(completed.stdout)


def assert_native_ready(result):
    need(isinstance(result, dict) and result.get('status') == 'ready',
         'native Runtime did not verify/synchronize the signed game files')
    for item in result.get('files', []):
        need(item.get('status') == 'ok', 'selected optional game file is absent or corrupt')


def selected_catalog_files(catalog, component_id):
    matches = [c for c in catalog.get('components', []) if c.get('id') == component_id]
    need(len(matches) == 1 and matches[0].get('files') and
         all(isinstance(x, str) and x.startswith('mods/') and '..' not in x.split('/') for x in matches[0]['files']),
         'selected test component must own real signed mods/*.jar files')
    return matches[0]['files']


def confirm_local_files(manifest, root, paths, should_exist):
    signed = {f['path']: f for f in manifest['files']}
    for rel in paths:
        need(rel in signed and HEX.fullmatch(signed[rel]['sha256']), 'unsigned optional mod file')
        path = root.joinpath(*rel.split('/'))
        need(not path.is_symlink() and root.resolve() in path.resolve().parents,
             'unsafe mod materialization path')
        if should_exist:
            need(path.is_file() and sha_file(path) == signed[rel]['sha256'],
                 'selected signed optional mod was not installed with original bytes')
        else:
            need(not path.exists(), 'unselected optional mod was installed')


def run_real_game(binary, manifest_file, pinned_key, root, preset, java, server, report):
    # Вызывает поставляемый нативный Runtime, настоящий локальный совместимый Minecraft-сервер и JVM.
    # Никакого имитированного клиентского процесса или вымышленной успешной квитанции.
    from staged_matching_0344 import JOIN, player_online, parse_gametime, CRASH
    username = 'NL_Cert_Client'
    server.prepare().start(timeout=200)
    launched = False
    observed = False
    try:
        command = [str(binary), 'launch', '--manifest', str(manifest_file),
                   '--pinned-public-key', pinned_key, '--root', str(root),
                   '--preset', preset, '--java', str(java), '--username', username,
                   '--matching-server-port', str(server.port), '--max-runtime-seconds', '120']
        with tempfile.TemporaryDirectory(prefix='nl-client-0526-') as temp:
            # Сохраняйте вывод процесса в закрытый файл, а не в приёмочный JSON.
            with open(Path(temp) / 'client-result.json', 'xb') as output:
                proc = subprocess.Popen(command, stdout=output, stderr=subprocess.DEVNULL)
                launched = True
                deadline = time.monotonic() + 150
                while time.monotonic() < deadline:
                    need(server.process.poll() is None, 'matching Minecraft server died')
                    log = server.log_text()
                    need(not CRASH.search(log), 'Minecraft server crash')
                    if username in JOIN.findall(log) and player_online(server.rcon.query('list'), username):
                        before = parse_gametime(server.rcon.query('time query gametime'))
                        time.sleep(1.2)
                        after = parse_gametime(server.rcon.query('time query gametime'))
                        if after > before and player_online(server.rcon.query('list'), username):
                            observed = True
                            break
                    if proc.poll() is not None:
                        break
                    time.sleep(.5)
                need(observed, 'no server-log + online-RCON + advancing-ticks game join')
                try:
                    proc.wait(timeout=150)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=20)
                    raise Blocked('client launch exceeded native Runtime deadline')
                need(proc.returncode == 0, 'native game launcher failed after join')
            response = parse_json((Path(temp) / 'client-result.json').read_bytes())
            need(isinstance(response, dict) and response.get('success') is True,
                 'native Runtime did not confirm successful real client launch')
        # Запросите настоящее сохранение мира и остановку, затем проверьте успешное завершение JVM.
        try:
            server.rcon.query('save-all flush')
        except (OSError, ValueError, RuntimeError):
            raise Blocked('Minecraft world save through RCON was not acknowledged') from None
        try:
            server.rcon.query('stop')
        except (OSError, ValueError, RuntimeError):
            pass  # сокет может закрыться, потому что реальный сервер останавливается
        need(server.process.wait(timeout=40) == 0, 'Minecraft server did not stop cleanly')
        report['serverArtifactSha256'] = server.artifact_sha
        report['observedOnlineTicks'] = True
    finally:
        if launched and 'proc' in locals() and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        server.close()
        if observed and server.log_file.is_file():
            report['serverLogSha256'] = sha_file(server.log_file, limit=32 << 20)
    need(observed, 'no live game join')


def execute(args, report):
    need(args.destructive_isolated_run, 'explicit permission to mutate isolated project required')
    need(HEX.fullmatch(args.runtime_sha256) and HEX.fullmatch(args.cli_sha256), 'independent executable SHA-256 pins required')
    need(sha_file(args.runtime) == args.runtime_sha256 and sha_file(args.cli) == args.cli_sha256,
         'native Runtime/CLI does not match externally pinned release payload')
    need(args.java.is_file() and not args.java.is_symlink(), 'real installed Java executable required')
    need(all(ID.fullmatch(x) for x in (args.project, args.profile, args.channel, args.package_id, args.component)),
         'invalid exact project/profile/channel/package/component identity')
    need(args.selected_preset != args.excluded_preset and
         all(ID.fullmatch(x) for x in (args.selected_preset, args.excluded_preset)),
         'two different signed presets required')
    need(HEX.fullmatch(args.pinned_manifest_public_key), 'independently pinned signing key required')
    secrets_doc = parse_json(private_file(args.secrets.absolute()))
    need(isinstance(secrets_doc, dict) and all(secrets_doc.get(k) for k in
         ('origin', 'playerEmail', 'playerPassword')), 'player login secrets unavailable')
    operator_token = private_file(args.operator_token.absolute(), limit=16384).decode().strip()
    need(len(operator_token) > 24 and '\n' not in operator_token, 'recent operator MFA session unavailable')
    api = API(secrets_doc['origin'])
    report['originHost'] = urlsplit(secrets_doc['origin']).hostname
    report['sourceCommit'] = os.environ.get('GITHUB_SHA', '')
    package_route = f'/api/v1/packages/{quote(args.package_id)}'
    package = api.json('GET', package_route, token=operator_token).get('data', {})
    need(package.get('packageId') == args.package_id and package.get('projectId') == args.project
         and package.get('profileId') == args.profile and package.get('channel') == args.channel
         and package.get('status') == 'draft' and package.get('manifestSchemaVersion') == '3.0',
         'test package is not a fresh, exact, schema-v3 draft')
    catalog = api.json('GET', package_route + '/component-catalog', token=operator_token).get('data', {}).get('catalog')
    need(isinstance(catalog, dict) and catalog.get('schemaVersion') == '5.0' and
         all(any(p.get('id') == name for p in catalog.get('presets', [])) for name in
             (args.selected_preset, args.excluded_preset)), 'signed component catalog and presets unavailable')
    paths = selected_catalog_files(catalog, args.component)
    selected_def = next(p for p in catalog['presets'] if p['id'] == args.selected_preset)
    excluded_def = next(p for p in catalog['presets'] if p['id'] == args.excluded_preset)
    need(args.component in selected_def['components'] and args.component not in excluded_def['components'],
         'test presets do not positively toggle the selected mod')
    validation = api.json('POST', package_route + '/validate', token=operator_token).get('data', {})
    need(validation.get('status') == 'valid' and len(validation.get('checks', [])) > 0 and
         all(x.get('status') == 'ok' for x in validation['checks']), 'storage/package prepublication validation failed')
    report['checks'].append('real_draft_storage_and_catalog_validation')
    signed = api.json('POST', package_route + '/sign', token=operator_token).get('data', {})
    need(signed.get('signatureStatus') == 'verified-ed25519' and signed.get('status') == 'signed' and
         signed.get('publicKey') == args.pinned_manifest_public_key, 'unexpected package Ed25519 signing identity')
    staged = api.json('POST', package_route + '/stage', token=operator_token).get('data', {})
    need(staged.get('status') == 'staged', 'real package stage failed')
    integrity = api.json('POST', package_route + '/integrity-check', token=operator_token).get('data', {})
    need(integrity.get('status') == 'integrity-passed' and
         integrity.get('result', {}).get('result') == 'passed' and
         integrity.get('result', {}).get('filesVerified') is True and
         integrity.get('result', {}).get('signatureVerified') is True,
         'package integrity check did not verify signed files and signature')
    report['checks'].append('real_signature_stage_and_integrity')
    # Существующая политика готовности авторитетна: никакой поддельной или неявной проверки.
    api.json('POST', package_route + '/publish', token=operator_token, expected=(200, 201, 202))
    current = {}
    for _ in range(40):
        current = api.json('GET', package_route, token=operator_token).get('data', {})
        if current.get('status') == 'published':
            break
        need(current.get('status') not in ('failed', 'rejected', 'cancelled'), 'durable publication failed')
        time.sleep(3)
    need(current.get('status') == 'published', 'durable channel publication not completed')
    uri = (f'/api/v1/projects/{quote(args.project)}/profiles/{quote(args.profile)}/manifest'
           f'?channel={quote(args.channel)}')
    raw = api.request('GET', uri, limit=4 << 20)
    manifest = parse_json(raw)
    need(isinstance(manifest, dict) and manifest.get('schemaVersion') == '3.0' and
         manifest.get('projectId') == args.project and manifest.get('profileId') == args.profile and
         manifest.get('channel') == args.channel and manifest.get('version') == package.get('version') and
         manifest.get('signature', {}).get('publicKey') == args.pinned_manifest_public_key and
         manifest.get('componentCatalog', {}).get('digest') == catalog['digest'],
         'publicly served manifest differs from approved signed package')
    report['manifestSha256'] = sha(raw)
    report['checks'].append('published_immutable_manifest_readback')
    player = api.json('POST', '/api/v1/admin/login', body={
        'email': secrets_doc['playerEmail'], 'password': secrets_doc['playerPassword']})
    token = player.get('token')
    need(isinstance(token, str) and len(token) >= 20, 'real player login failed')
    for kind, local in [('skin', args.skin), ('cape', args.cape)]:
        texture = upload_texture(api, token, kind, local.read_bytes())
        report['textures'].append(texture)
        report['checks'].append('real_' + kind + '_upload_and_binary_readback')
    # Используйте независимый HTTPS-ответ с манифестом, а не локальный черновик оператора.
    with tempfile.TemporaryDirectory(prefix='nl-0526-acceptance-') as temp:
        folder = Path(temp)
        mf = folder / 'published.json'
        mf.write_bytes(raw)
        for preset, select in [(args.selected_preset, True), (args.excluded_preset, False)]:
            root = folder / ('selected' if select else 'excluded')
            root.mkdir(mode=0o700)
            marker = root / 'options.txt'
            marker.write_bytes(b'neverlauncher user-owned configuration 0.52.6\n')
            manifest_url = api.origin + uri
            synced = native(args.runtime, ['sync', '--manifest-url', manifest_url, '--pinned-public-key',
                                           args.pinned_manifest_public_key, '--root', root, '--preset', preset])
            assert_native_ready(synced)
            result = native(args.runtime, ['verify', '--manifest', mf, '--pinned-public-key',
                                           args.pinned_manifest_public_key, '--root', root, '--preset', preset])
            assert_native_ready(result)
            need(marker.read_bytes() == b'neverlauncher user-owned configuration 0.52.6\n',
                 'download erased or modified user-owned game configuration')
            confirm_local_files(manifest, root, paths, select)
            report['checks'].append(('selected' if select else 'unselected') + '_mods_native_sync_and_verify')
        # Выбранный JAR должен быть реально восстанавливаемым, а не только указанным в JSON.
        root = folder / 'selected'
        jar = root.joinpath(*paths[0].split('/'))
        jar.unlink()
        failed = native(args.runtime, ['verify', '--manifest', mf, '--pinned-public-key',
                                       args.pinned_manifest_public_key, '--root', root,
                                       '--preset', args.selected_preset])
        need(failed.get('status') == 'invalid', 'missing selected mod was wrongly accepted by native verify')
        recovered = native(args.runtime, ['sync-local', '--manifest', mf, '--pinned-public-key',
                                         args.pinned_manifest_public_key, '--root', root,
                                         '--preset', args.selected_preset])
        assert_native_ready(recovered)
        confirm_local_files(manifest, root, paths, True)
        report['checks'].append('selected_mod_deleted_then_recovered_from_signed_release')
        # Докажите НАСТОЯЩИЙ вход клиента и игрока по этому опубликованному манифесту на совпадающий
        # сервер vanilla или с модами; одного успешного завершения недостаточно.
        sys.path.insert(0, str(ROOT / 'e2e' / 'scripts'))
        from staged_matching_0344 import MatchingServer
        game = manifest.get('minecraft', {})
        mc, loader, loader_version = game.get('version'), game.get('loader'), game.get('loaderVersion', '')
        need(mc and loader in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'), 'manifest lacks real Minecraft identity')
        bundle = args.server_bundle
        if loader != 'vanilla':
            need(bundle and args.server_bundle_sha256 and HEX.fullmatch(args.server_bundle_sha256),
                 'modded server requires independent SHA-256 pinned real server bundle')
        if bundle:
            need(sha_file(bundle, limit=3 << 30) == args.server_bundle_sha256,
                 'matching server distribution differs from operator pin')
        server = MatchingServer(folder / 'game', args.java, args.cli, mc, loader, loader_version,
                                bundle=str(bundle) if bundle else '', bundle_sha=args.server_bundle_sha256 or '',
                                server_entry=args.server_entry, require_bridge=False)
        (folder / 'game').mkdir(mode=0o700)
        run_real_game(args.runtime, mf, args.pinned_manifest_public_key, root,
                      args.selected_preset, args.java, server, report)
        report['checks'].append('real_published_modpack_minecraft_join_and_game_ticks')
    report['componentId'] = args.component
    report['packageId'] = args.package_id
    report['projectId'] = args.project
    report['profileId'] = args.profile
    report['channel'] = args.channel


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('secrets', 'operator-token', 'runtime', 'cli', 'java', 'skin', 'cape', 'report'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('runtime-sha256', 'cli-sha256', 'pinned-manifest-public-key', 'project',
                 'profile', 'channel', 'package-id', 'component', 'selected-preset', 'excluded-preset'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--server-bundle', type=Path)
    p.add_argument('--server-bundle-sha256', default='')
    p.add_argument('--server-entry', default='')
    p.add_argument('--destructive-isolated-run', action='store_true')
    args = p.parse_args(argv)
    report = {'schemaVersion': 'neverlauncher.modpacks-textures-game-publication/0.52.6',
              'version': VERSION, 'status': 'blocked', 'gaCertified': False,
              'startedAt': datetime.now(timezone.utc).isoformat(), 'checks': [], 'textures': []}
    try:
        execute(args, report)
        need(len(report['checks']) == 9 and len(report['textures']) == 2,
             'incomplete real modpack/texture/publication/game E2E')
        report['status'] = 'passed'
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired,
            subprocess.SubprocessError, RuntimeError) as err:
        report['failureType'] = type(err).__name__
        report['failure'] = 'live acceptance incomplete; inspect private runner diagnostics'
        print('BLOCKED 0.52.6: ' + type(err).__name__, file=sys.stderr)
        return 1
    finally:
        report['finishedAt'] = datetime.now(timezone.utc).isoformat()
        atomic_private_json(args.report.absolute(), report)


if __name__ == '__main__':
    sys.exit(main())
