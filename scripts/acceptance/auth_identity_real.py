#!/usr/bin/env python3
"""0.52.5 live authentication/identity acceptance against an existing HTTPS API.

No local/mock provider and no PASS inferred from a fixture or a self-reported flag.
Use dedicated operator-owned disposable test accounts; writes real identity links,
refreshes sessions and revokes tokens. Secrets are read from mode-0600 files only.
The two-phase OIDC flow requires a real browser authorization from the issuer.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import struct
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'e2e' / 'scripts'))
from staged_auth_0347 import official_probe, ProviderUnavailable, ProviderRejected, ProviderMisconfigured

VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
HEXUUID = re.compile(r'^[0-9a-fA-F]{32}$')
PROVIDER_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')

class Blocked(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise Blocked(why)


def private_json(path: Path, max_size=32768):
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'private input file must be an absolute regular file')
    info = path.stat()
    require(info.st_uid == os.geteuid() and stat.S_ISREG(info.st_mode) and
            info.st_mode & 0o077 == 0 and 0 < info.st_size <= max_size,
            'private input file owner/mode/size invalid (require 0600)')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        real = os.fstat(fd)
        require(real.st_uid == os.geteuid() and stat.S_ISREG(real.st_mode) and
                real.st_mode & 0o077 == 0 and 0 < real.st_size <= max_size,
                'private file changed during validation')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(max_size + 1)
        require(len(raw) <= max_size, 'private input exceeded maximum size')
    finally:
        os.close(fd)
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'duplicate private JSON field')
            result[name] = value
        return result
    try:
        parsed = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda item: (_ for _ in ()).throw(Blocked('invalid JSON constant')))
    except (UnicodeError, ValueError):
        raise Blocked('invalid private JSON input') from None
    require(isinstance(parsed, dict), 'private JSON must be an object')
    return parsed


def private_write(path: Path, data: dict):
    require(path.is_absolute() and path.parent.is_dir() and not path.parent.is_symlink(), 'output parent must exist and be an absolute directory')
    require(not path.exists() and not path.is_symlink(), 'output already exists; refusing to overwrite evidence')
    tmp = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, path)  # эксклюзивное создание: результат конкурирующего процесса нельзя перезаписывать
        d = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        tmp.unlink(missing_ok=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class LiveAPI:
    def __init__(self, origin):
        parsed = urlsplit(origin)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
                not parsed.password and parsed.path in ('', '/') and not parsed.query and
                not parsed.fragment, 'live acceptance requires exact HTTPS origin')
        self.origin = origin.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def request(self, method, route, *, data=None, token=None, expected=(200,)):
        require(route.startswith('/api/v1/') and not route.startswith('//') and
                not any(c in route for c in ('\\', '#', '\r', '\n')),
                'invalid API path')
        body = json.dumps(data, separators=(',', ':')).encode() if data is not None else None
        headers = {'Accept': 'application/json', 'Cache-Control': 'no-store'}
        if body is not None: headers['Content-Type'] = 'application/json'
        if token: headers['Authorization'] = 'Bearer ' + token
        req = Request(self.origin + route, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=25) as response:
                status, raw = response.status, response.read(262145)
        except HTTPError as error:
            status, raw = error.code, error.read(262145)
        except (URLError, OSError, TimeoutError):
            raise Blocked('real HTTPS Backend transport/certificate failed') from None
        require(len(raw) <= 262144, 'oversized Backend response')
        require(status in expected, f'{method} {route.split("?")[0]} returned HTTP {status}, expected {expected}')
        try:
            parsed = json.loads(raw)
        except (UnicodeError, ValueError):
            raise Blocked('Backend returned non-JSON response') from None
        require(isinstance(parsed, dict), 'Backend returned non-object response')
        return parsed


def user_digest(user_id):
    return hashlib.sha256(('never-auth-0525-user\0' + user_id).encode()).hexdigest()


def safe_provider(raw):
    require(isinstance(raw, str) and PROVIDER_ID.fullmatch(raw), 'invalid provider ID')
    return raw


def credentials(value, name):
    require(isinstance(value, dict) and isinstance(value.get('identifier'), str) and
            isinstance(value.get('password'), str) and value['identifier'] and
            value['password'] and len(value['password']) <= 4096,
            'missing private ' + name + ' test credentials')
    return value


def auth_login(api, entry, provider):
    payload = {
        'providerId': safe_provider(provider), 'identifier': entry['identifier'],
        'password': entry['password'], 'deviceId': 'auth-accept-0525-' + secrets.token_hex(6),
    }
    if 'totpSecret' in entry:
        secret = entry['totpSecret'].replace(' ', '').upper()
        try:
            key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
            step = int(time.time()) // 30
            digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
            offset = digest[-1] & 15
            payload['totp'] = str((int.from_bytes(digest[offset:offset+4], 'big') & 0x7fffffff) % 1000000).zfill(6)
        except (ValueError, TypeError):
            raise Blocked('invalid private test-account TOTP secret') from None
    doc = api.request('POST', '/api/v1/auth/login', data=payload)
    data = doc.get('data') or {}
    user = data.get('user') or {}
    tokens = data.get('tokens') or {}
    require(isinstance(user.get('id'), str) and user['id'] and user.get('status') == 'active',
            'login missing active canonical Never identity')
    require(isinstance(tokens.get('accessToken'), str) and len(tokens['accessToken']) >= 32 and
            isinstance(tokens.get('refreshToken'), str) and len(tokens['refreshToken']) >= 32,
            'login did not issue real Never access/refresh pair')
    require(data.get('provider') == provider, 'provider routing crossed issuer/provider boundary')
    return user, tokens


def expect_denied(api, method, route, *, data=None, token=None, codes=(401, 403)):
    return api.request(method, route, data=data, token=token, expected=codes)


def record(report, name, observations=None):
    require(name not in (e['id'] for e in report['checks']), 'duplicate acceptance result')
    report['checks'].append({'id': name, 'status': 'passed', 'observations': observations or {}})
    print('PASS', name, flush=True)


def check_input(raw):
    require(raw.get('scope') == 'dedicated-disposable-accounts' and raw.get('allowIdentityMutation') is True,
            'explicit opt-in for dedicated disposable test identities required')
    local = credentials(raw.get('local'), 'local')
    secondary = credentials(raw.get('secondary'), 'secondary')
    sql = credentials(raw.get('sql'), 'SQL')
    for key in ('local', 'secondary', 'sql'):
        safe_provider(raw[key].get('providerId'))
    require(local['identifier'] != secondary['identifier'], 'secondary identity must be independent')
    require(raw['sql']['providerId'] != local['providerId'], 'SQL test must use a different provider')
    oidc = raw.get('oidc')
    require(isinstance(oidc, dict), 'live OIDC configuration required')
    safe_provider(oidc.get('providerId'))
    require(oidc.get('kind') in ('generic', 'microsoft'), 'OIDC kind must be generic or microsoft')
    official = raw.get('official')
    require(isinstance(official, dict) and official.get('userType') == 'msa' and
            official.get('authServerBaseUrl') == '' and
            isinstance(official.get('uuid'), str) and HEXUUID.fullmatch(official['uuid'].replace('-', '')),
            'official Minecraft credentials/UUID required')
    require(all(isinstance(official.get(k), str) and official[k] for k in ('username', 'accessToken')),
            'official Minecraft bearer/profile required')
    return local, secondary, sql, oidc, official


def oidc_link_route(oidc, mode):
    provider = quote(safe_provider(oidc['providerId']), safe='')
    if oidc['kind'] == 'microsoft':
        return '/api/v1/auth/microsoft/' + provider + '/link/' + mode
    return '/api/v1/auth/providers/' + provider + '/link/' + mode


def prepare(api, raw, output):
    local, _, _, oidc, _ = check_input(raw)
    user, tokens = auth_login(api, local, local['providerId'])
    # Нужны ДВЕ разные авторизации в браузере: одна явная привязка и отдельный вход,
    # доказывающие сопоставление итоговой идентичности с тем же UUID.
    link = api.request('POST', oidc_link_route(oidc, 'begin'), data={}, token=tokens['accessToken'])['data']
    login = api.request('POST', '/api/v1/auth/oidc/' + quote(oidc['providerId']) + '/begin', data={})['data']
    for item in (link, login):
        require(all(isinstance(item.get(k), str) and item[k] for k in ('authorizationUrl', 'transaction', 'state')),
                'OIDC issuer did not return PKCE browser transaction')
        require(item['authorizationUrl'].startswith('https://'), 'browser auth URL must be HTTPS')
    require(link['state'] != login['state'], 'distinct OIDC flows reused the state')
    private_write(output, {'version': VERSION, 'origin': api.origin, 'providerId': oidc['providerId'],
                           'ownerSha256': user_digest(user['id']), 'generatedAt': int(time.time()),
                           'link': {**link, 'code': ''}, 'login': {**login, 'code': ''}})
    print('OIDC authorization URLs and sealed transactions written to private 0600 file. Complete both browser flows and add each code to the file.')


def live_run(api, raw, proof, source_commit='', api_package_sha256=''):
    local, secondary, sql, oidc, official = check_input(raw)
    require(isinstance(source_commit, str) and COMMIT.fullmatch(source_commit), 'exact source commit required')
    require(isinstance(api_package_sha256, str) and SHA256.fullmatch(api_package_sha256), 'exact backend release package SHA-256 required')
    issued = proof.get('generatedAt')
    age = int(time.time()) - issued if isinstance(issued, int) else 1000000
    require(proof.get('version') == VERSION and proof.get('origin') == api.origin and
            proof.get('providerId') == oidc['providerId'] and 0 <= age < 600,
            'OIDC browser proof is stale or belongs to another release/origin')
    for key in ('link', 'login'):
        flow = proof.get(key)
        require(isinstance(flow, dict) and all(isinstance(flow.get(f), str) and flow[f] for f in ('state', 'transaction', 'code')),
                'OIDC browser proof missing verified authorization code for ' + key)
    caps = api.request('GET', '/api/v1/auth/capabilities').get('data', {})
    require(caps.get('toolVersion') == VERSION, 'live Backend release version does not match exact acceptance candidate')
    report = {'schema': 'neverlauncher.auth-identity-live.0525', 'productVersion': VERSION,
              'sourceCommit':source_commit, 'apiPackageSha256':api_package_sha256,
              'originSha256': hashlib.sha256(api.origin.encode()).hexdigest(), 'checks': [],
              'status': 'blocked', 'startedAt': int(time.time())}
    user, local_tokens = auth_login(api, local, local['providerId'])
    owner = user['id']
    require(proof.get('ownerSha256') == user_digest(owner), 'OIDC proof belongs to another Never owner')
    record(report, 'AUTH-LOCAL', {'canonicalUserSha256': user_digest(owner), 'role': user['roleId']})
    secondary_user, secondary_tokens = auth_login(api, secondary, secondary['providerId'])
    require(secondary_user['id'] != owner, 'second account maps to same Never UUID')
    record(report, 'AUTH-SEPARATE-ACCOUNT', {'canonicalUserSha256': user_digest(secondary_user['id'])})
    expect_denied(api, 'POST', '/api/v1/auth/login', data={
        'providerId': local['providerId'], 'identifier': local['identifier'],
        'password': 'invalid-' + secrets.token_hex(12)}, codes=(401, 403))
    record(report, 'AUTH-INVALID-PASSWORD')
    # Идентичность SQL-провайдера подтверждается его НАСТОЯЩИМ настроенным механизмом паролей; запрещены
    # сопоставление по email, предположения об автоматическом создании и поддельные провайдеры.
    api.request('POST', '/api/v1/auth/providers/' + quote(sql['providerId']) + '/link/password',
                token=local_tokens['accessToken'], data={'identifier':sql['identifier'], 'password':sql['password']})
    sql_user, sql_tokens = auth_login(api, sql, sql['providerId'])
    require(sql_user['id'] == owner, 'SQL login did not resolve the same explicitly linked canonical identity')
    identities = api.request('GET','/api/v1/auth/identities',token=sql_tokens['accessToken'])['data']['items']
    require(any(row.get('provider') == sql['providerId'] and row.get('subject') for row in identities),
            'SQL provider proof did not persist a scoped linked identity')
    record(report,'AUTH-SQL-LINK-AND-LOGIN', {'canonicalUserSha256':user_digest(owner)})
    link = proof['link']
    api.request('POST', oidc_link_route(oidc, 'complete'), token=local_tokens['accessToken'],
                data={'state':link['state'], 'transaction':link['transaction'], 'code':link['code']})
    expect_denied(api,'POST',oidc_link_route(oidc, 'complete'),token=local_tokens['accessToken'],
                  data={'state':link['state'],'transaction':link['transaction'],'code':link['code']})
    record(report,'AUTH-OIDC-PROOF-AND-REPLAY-DENIED')
    login = proof['login']
    oidc_result = api.request('POST','/api/v1/auth/oidc/' + quote(oidc['providerId']) + '/complete',
                data={'state':login['state'],'transaction':login['transaction'],'code':login['code']})
    require(oidc_result.get('data',{}).get('user',{}).get('id') == owner,
            'OIDC login changed the canonical Never UUID')
    expect_denied(api,'POST','/api/v1/auth/oidc/' + quote(oidc['providerId']) + '/complete',
                  data={'state':login['state'],'transaction':login['transaction'],'code':login['code']})
    record(report,'AUTH-OIDC-CANONICAL-ID-AND-REPLAY')
    # Официальные profile + join + hasJoined должны проверяться по реальным
    # api.minecraftservices.com И sessionserver.mojang.com, не через локальную имитацию.
    proof_data = official_probe(official,'official')
    require(proof_data.get('providerJoin') == 'passed' and proof_data.get('providerHasJoined') == 'passed',
            'real Microsoft/Minecraft online-mode join failed')
    record(report,'AUTH-OFFICIAL-MINECRAFT-JOIN', {'profileSha256':proof_data['profileSha256']})
    game_uuid = official['uuid'].replace('-','').lower()
    wrong_uuid = ('1' if game_uuid[0] != '1' else '2') + game_uuid[1:]
    expect_denied(api,'POST','/api/v1/minecraft/official/link', token=local_tokens['accessToken'],
                  data={'minecraftAccessToken':official['accessToken'],'expectedUuid':wrong_uuid,'confirm':True})
    linked = api.request('POST','/api/v1/minecraft/official/link',token=local_tokens['accessToken'],
            data={'minecraftAccessToken':official['accessToken'],'expectedUuid':game_uuid,'confirm':True})
    require(game_uuid in json.dumps(linked).lower(), 'verified official UUID not present in link response')
    list_a = api.request('GET','/api/v1/minecraft/official/link',token=local_tokens['accessToken'])
    require(game_uuid in json.dumps(list_a).lower(), 'official identity link not durably readable')
    list_b = api.request('GET','/api/v1/minecraft/official/link',token=secondary_tokens['accessToken'])
    require(game_uuid not in json.dumps(list_b).lower(), 'official UUID leaked into a different owner listing')
    record(report,'AUTH-OFFICIAL-UUID-OWNERSHIP')
    expect_denied(api,'POST','/api/v1/minecraft/official/link', token=secondary_tokens['accessToken'],
                  data={'minecraftAccessToken':official['accessToken'],'expectedUuid':game_uuid,'confirm':True},codes=(409,))
    expect_denied(api,'DELETE','/api/v1/minecraft/official/link/'+game_uuid,
                  token=secondary_tokens['accessToken'],codes=(404,))
    record(report,'AUTH-CROSS-ACCOUNT-LINK-AND-UNLINK-DENIED')
    # Проверяйте, что аутентифицированные роли определяет сервер, а не утверждения провайдера.
    if user['roleId'] in ('owner', 'admin'):
        roles = api.request('GET','/api/v1/auth/roles',token=local_tokens['accessToken'])
        require(isinstance(roles.get('data',{}).get('items'), list) and roles['data']['items'],
                'privileged canonical role could not list roles')
    else:
        expect_denied(api,'GET','/api/v1/auth/roles',token=local_tokens['accessToken'],codes=(403,))
    if secondary_user.get('roleId') == 'player':
        expect_denied(api,'GET','/api/v1/auth/roles',token=secondary_tokens['accessToken'],codes=(403,))
    record(report,'AUTH-ROLE-ENFORCEMENT', {'primaryRole':user['roleId'], 'secondaryRole':secondary_user['roleId']})
    # Очистка — настоящая привилегированная операция, а не сброс состояния тестовым кодом.
    api.request('DELETE','/api/v1/minecraft/official/link/'+game_uuid,token=local_tokens['accessToken'])
    removed = api.request('GET','/api/v1/minecraft/official/link',token=local_tokens['accessToken'])
    require(game_uuid not in json.dumps(removed).lower(), 'official link persisted after owner unlink')
    record(report,'AUTH-OFFICIAL-UNLINK-PERSISTENCE')
    refresh = api.request('POST','/api/v1/auth/refresh',data={'refreshToken':local_tokens['refreshToken']})['data']['tokens']
    require(isinstance(refresh.get('refreshToken'),str) and refresh['refreshToken'] != local_tokens['refreshToken'],
            'refresh did not rotate token')
    expect_denied(api,'POST','/api/v1/auth/refresh',data={'refreshToken':local_tokens['refreshToken']})
    expect_denied(api,'GET','/api/v1/auth/sessions',token=refresh['accessToken'])
    api.request('GET','/api/v1/auth/sessions',token=secondary_tokens['accessToken'])
    record(report,'AUTH-REFRESH-REPLAY-REVOKES-FAMILY')
    api.request('POST','/api/v1/auth/logout',token=secondary_tokens['accessToken'])
    expect_denied(api,'GET','/api/v1/auth/sessions',token=secondary_tokens['accessToken'])
    record(report,'AUTH-LOGOUT-REVOKES-SESSION')
    require(len(report['checks']) == 13, 'a required auth acceptance check was skipped')
    report['finishedAt'] = int(time.time())
    report['status'] = 'passed-live-operator-observations-not-independent-ga'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare-oidc','run'))
    parser.add_argument('--secrets', type=Path, required=True, help='absolute mode-0600 JSON with dedicated credentials')
    parser.add_argument('--oidc-proof', type=Path, help='absolute private JSON generated by prepare-oidc, filled with real codes')
    parser.add_argument('--output',type=Path,required=True,help='new private mode-0600 output file')
    parser.add_argument('--source-commit', default='', help='required for run: exact immutable source commit')
    parser.add_argument('--api-package-sha256', default='', help='required for run: independently pinned backend package digest')
    args = parser.parse_args(argv)
    try:
        raw = private_json(args.secrets)
        check_input(raw)
        api = LiveAPI(raw['origin'])
        if args.action == 'prepare-oidc':
            prepare(api,raw,args.output)
        else:
            require(args.oidc_proof is not None, 'live OIDC browser proof file required')
            proof = private_json(args.oidc_proof)
            result = live_run(api,raw,proof, args.source_commit, args.api_package_sha256)
            private_write(args.output,result)
            print('REAL AUTH E2E OBSERVATIONS PASSED; independent native/release GA remains BLOCKED')
        return 0
    except (Blocked, ProviderUnavailable, ProviderRejected, ProviderMisconfigured, KeyError, TypeError, ValueError) as error:
        # Не печатайте тела исключений источника, bearer-токены и идентичности.
        if isinstance(error, Blocked):
            message = str(error)
        else:
            message = type(error).__name__
        print('BLOCKED: '+message, file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
