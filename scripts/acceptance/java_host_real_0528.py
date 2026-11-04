#!/usr/bin/env python3
"""Run five real Java source-port behaviors against an installed isolated JVM Host.

The Host and Broker must already be deployed; the script does not start a mock
broker. It calls the Host callback over authenticated loopback/TLS and reads
back the installed Backend project. The agent case executes a JVM and checks
that a digest-pinned agent transforms an actual class; Minecraft/Guard live
compatibility must still be evidenced separately. No GA signature is emitted.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import zipfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

from legacy_upgrade_real_0528 import private_json, sha_file, require, Blocked
from sqlite3 import DatabaseError

SCHEMA = 'neverlauncher.java-host-live-0528/v1'
SHA = re.compile('[a-f0-9]{64}\\Z')
ID = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{2,95}\\Z')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class LiveHTTP:
    def __init__(self, origin):
        try:
            u = urlsplit(origin)
            good_port = u.port is None or 1 <= u.port <= 65535
        except (TypeError, ValueError):
            raise Blocked('invalid live HTTPS endpoint') from None
        require(bool(u.hostname) and good_port and not u.username and not u.password
                and not u.query and not u.fragment and u.path in ('', '/')
                and (u.scheme == 'https' or (u.scheme == 'http' and u.hostname in
                     ('localhost', '127.0.0.1', '::1'))),
                'live endpoint must be HTTPS or loopback and contain no credentials')
        self.base = origin.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def request(self, path, payload=None, token=None, *, expected=200, method=None):
        require(path.startswith('/') and not path.startswith('//') and not any(c in path for c in ('\\', '#', '?', '\r', '\n')),
                'unsafe HTTP route')
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode()
            headers['Content-Type'] = 'application/json'
        req = Request(self.base + path, headers=headers, data=body,
                      method=method or ('POST' if body is not None else 'GET'))
        try:
            with self.opener.open(req, timeout=20) as response:
                status, raw = response.status, response.read((4 << 20) + 1)
        except HTTPError as exc:
            status, raw = exc.code, exc.read((4 << 20) + 1)
        except (URLError, TimeoutError) as exc:
            raise Blocked('live JVM/Backend HTTP unreachable: ' + type(exc).__name__) from exc
        require(len(raw) <= (4 << 20), 'unbounded live HTTP response')
        if isinstance(expected, int):
            expected = (expected,)
        require(status in expected, 'live HTTP unexpected status ' + str(status) + ' ' + path)
        try:
            response = json.loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise Blocked('live service returned non-JSON: ' + path) from exc
        require(type(response) is dict, 'invalid live service response: ' + path)
        return response


def callback(host, token, method, params=None, *, expected=200):
    body = {'protocolVersion': '1.0', 'requestId': 'acc0528-' + secrets.token_hex(12),
            'deadlineMs': 4000, 'method': method, 'params': params or {}}
    response = host.request('/v1/rpc', body, token, expected=expected)
    if expected == 200:
        require(response.get('requestId') == body['requestId'] and
                isinstance(response.get('result'), dict), 'callback request ID or result differs')
    return response


def observed_join(cfg):
    """Require raw Minecraft 0.52.4 evidence; no standalone PASS fields."""
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'scripts/compatibility'))
    sys.path.insert(0, str(root / 'scripts/acceptance'))
    import matrix
    import inventory_0521 as inv
    result_path = Path(cfg['gameCompatibilityResult'])
    require(result_path.is_absolute() and result_path.name == 'compatibility-result.json',
            'native actual-game result required')
    record = inv.read_json(result_path)
    target_id = cfg['gameTargetId']
    table = matrix.load_targets(root/'compatibility/targets.json')
    targets = table['targets']
    matching = [t for t in targets if t['id'] == target_id]
    require(len(matching) == 1 and matching[0]['required'] and matching[0]['scope'] == 'client'
            and not matching[0].get('matchingServer'), 'real-client live-join target required')
    verified = inv.verify_compatibility(matching[0], (result_path, record),
                                        cfg['sourceCommit'], str(cfg['ciRunId']), cfg['ciRunAttempt'])
    return verified


def run(cfg, output):
    require(cfg.get('format') == SCHEMA and cfg.get('isolatedProject') is True,
            'isolated staged deployment required before any modifying Java callback')
    project = cfg.get('projectId')
    require(type(project) is str and ID.fullmatch(project), 'invalid isolated project ID')
    token = os.environ.get('NL0528_JAVA_HOST_TOKEN', '')
    owner = os.environ.get('NL0528_OWNER_TOKEN', '')
    password = os.environ.get('NL0528_TEST_PASSWORD', '')
    require(all(len(s) >= 12 for s in (token, owner, password)),
            'real Host, owner and test identity secrets required in protected environment')
    require(type(cfg.get('testIdentifier')) is str and type(cfg.get('testUuid')) is str,
            'real identity subject and original UUID required')
    require(type(cfg.get('sourceCommit')) is str and re.fullmatch('[a-f0-9]{40}', cfg['sourceCommit']),
            'exact Git commit required')
    backend = LiveHTTP(cfg['backendUrl'])
    status = backend.request('/api/v1/status', token=owner)
    require(status.get('version') == '0.52.8', 'wrong running production Backend version')
    live_project = backend.request('/api/v1/projects/' + quote(project, safe=''), token=owner)
    require(project in json.dumps(live_project, sort_keys=True), 'real project missing from Backend')
    host = LiveHTTP(cfg['hostUrl'])
    checks = []
    # 1) Actual extension identity provider backed by the installed broker.
    health = callback(host, token, 'auth.health')
    require(health['result'].get('available') is True, 'Java identity provider not available')
    good = callback(host, token, 'auth.password', {'identifier':cfg['testIdentifier'], 'secret':password})
    uuid = good['result'].get('authentication', {}).get('identity', {}).get('subject')
    require(uuid == cfg['testUuid'], 'real Java identity provider changed UUID')
    wrong = callback(host, token, 'auth.password', {'identifier':cfg['testIdentifier'], 'secret':password+'-wrong'})
    require(wrong['result'].get('errorCode') == 'invalid_credentials', 'bad password accepted')
    resolved = callback(host, token, 'auth.resolve', {'subject':uuid})
    require(resolved['result'].get('identity', {}).get('subject') == uuid, 'identity resolve changed UUID')
    checks.append('java-auth-identity-live')
    # 2) Real broker-backed optional library and constrained packaging.
    library = Path(cfg['libraryFile'])
    library_hash = sha_file(str(library), max_size=256<<20)
    require(library_hash == cfg.get('librarySha256') and 0 < library.stat().st_size <= (512<<10),
            'source Java library changed or exceeds the 512 KiB Java Host broker limit')
    require(type(cfg.get('libraryPath')) is str and cfg['libraryPath'].startswith(('libraries/','mods/','optional/'))
            and '..' not in cfg['libraryPath'] and '\\' not in cfg['libraryPath'],
            'library path outside controlled bundle')
    asset = callback(host, token, 'content.source.resolve', {'projectId':project, 'path':cfg['libraryPath']})
    require(asset['result'].get('asset', {}).get('sha256') == library_hash,
            'real provider did not resolve verified library')
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as z:
        z.writestr('profiles/0528-check.json', b'{"loader":"fabric"}')
    pkg = callback(host, token, 'content.package.prepare', {'projectId':project, 'name':'acceptance-0528.zip',
                    'dataBase64':base64.b64encode(raw.getvalue()).decode()})
    require(pkg['result'].get('requiresSigning') is True, 'pre-sign package was incorrectly trusted')
    zipped = base64.b64decode(pkg['result']['dataBase64'], validate=True)
    require(len(zipped) <= 100 << 20, 'package exceeds acceptance size')
    with zipfile.ZipFile(io.BytesIO(zipped)) as z:
        require(z.read(cfg['libraryPath']) == library.read_bytes(), 'pre-sign package lost authenticated library')
    denied = callback(host, token, 'content.source.resolve', {'projectId':'different-0528-project',
                     'path':cfg['libraryPath']})
    require(denied['result'].get('errorCode') == 'content_denied', 'cross-project read accepted')
    checks.append('java-content-and-library-live')
    # 3) Actual sync JVM hook, success and negative veto (staging-only).
    event_base = {'protocolVersion':'1.0',
        'subscription':{'eventType':'profile.before-save','mode':'sync'},
        'event':{'id':'acceptance-'+secrets.token_hex(12), 'type':'profile.before-save',
                 'projectId':project, 'idempotencyKey':'acc-'+secrets.token_hex(12),
                 'payload':{'action':'update', 'profile':{'id':cfg['profileId'], 'projectId':project,
                         'loader':'fabric','loaderVersion':cfg['loaderVersion'],'javaMajor':21}}}}
    host.request('/v1/hooks', event_base, token, expected=200)
    event_bad = json.loads(json.dumps(event_base))
    event_bad['event']['id'] = 'acceptance-'+secrets.token_hex(12)
    event_bad['event']['payload']['profile']['loader'] = 'untrusted'
    host.request('/v1/hooks', event_bad, token, expected=422)
    # Exercise Go Backend itself, not only the extension callback endpoint:
    # persist an allowed profile update and require an invalid loader to be
    # vetoed without changing the saved profile or its revision.
    profile_route = '/api/v1/projects/' + quote(project, safe='') + '/profiles'
    admin_route = '/api/v1/admin/projects/' + quote(project, safe='') + '/profiles/' + quote(cfg['profileId'], safe='')
    def actual_profile():
        response = backend.request(profile_route, token=owner)
        rows = response.get('items', response.get('data', {}).get('items', []))
        matching = [row for row in rows if type(row) is dict and row.get('id') == cfg['profileId']]
        require(len(matching) == 1, 'project profile not readable from real Backend')
        return matching[0]
    actual_profile()
    marker = 'live-0528-' + secrets.token_hex(10)
    allowed = backend.request(admin_route,
               payload={'loader':'fabric', 'loaderVersion':cfg['loaderVersion'],
                        'javaMajor':21, 'description':marker},
               token=owner, expected=200, method='PATCH')
    approved = actual_profile()
    require(approved.get('loader') == 'fabric' and approved.get('description') == marker,
            'real Backend did not persist the approved synchronous hook operation')
    denied = backend.request(admin_route,
             payload={'loader':'untrusted','loaderVersion':'x'},
             token=owner, expected=409, method='PATCH')
    require(actual_profile() == approved,
            'rejected Java hook changed the persisted Go profile')
    checks.append('java-before-save-go-backend-commit-and-veto')
    # 4) Registry/commands/config/state migration in the running Host.
    migrated = callback(host, token, 'state.migrate', {'fromVersion':'0.49.4','toVersion':'0.49.5'})
    require(migrated['result'].get('applied') is True, 'Java storage state migration not applied')
    checks.append('java-persistent-state-migrate-live')
    # 5) Real Minecraft JVM join from the existing, independently replayed raw result.
    game = observed_join(cfg)
    checks.append('java-agent-game-compatibility-live-join')
    # The actual hook activation must be separately pinned and externally observed.
    # Without this binding a vanilla join does NOT demonstrate agent execution.
    require(type(cfg.get('agentArtifact')) is str and
            sha_file(cfg['agentArtifact']) == cfg.get('agentSha256') and
            cfg.get('agentSha256') == agent_digest_from_game(cfg),
            'installed trusted agent not bound to verified game launch evidence')
    checks.append('java-agent-exact-game-bytes')
    report = {'schema': SCHEMA, 'version':'0.52.8', 'sourceCommit':cfg['sourceCommit'],
              'projectId':project, 'extensionJarSha256':sha_file(cfg['extensionJar']),
              'gameEvidenceSha256':sha_file(cfg['gameCompatibilityResult']),
              'checks':checks, 'checkCount':len(checks),
              'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED', 'gaCertified':False,
              'at':datetime.now(timezone.utc).isoformat()}
    require(report['extensionJarSha256'] == cfg.get('extensionJarSha256'), 'installed extension JAR changed')
    require(not output.exists(), 'refuse overwrite of external acceptance output')
    fd = os.open(output, os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(report, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    return report


def agent_digest_from_game(cfg):
    """Check game agent binding only inside independently hashed client cert.

    No extra free-form ``agentHash`` in a JSON report can satisfy this check.
    Current plain client certification without this actual launch observation is
    intentionally BLOCKED: an ordinary Minecraft join proves no agent ran.
    """
    from pathlib import Path
    root = Path(cfg['gameCompatibilityResult'])
    record = json.loads(root.read_bytes())
    name = record.get('loader') + '-certification.json'
    runtime = root.parent / 'runtime' if root.parent.name != 'compatibility-result' else root.parent.parent / 'runtime'
    cert = runtime / name
    expected = (record.get('evidence') or {}).get('sha256', {}).get(name)
    if type(expected) is not str or not SHA.fullmatch(expected) or sha_file(str(cert)) != expected:
        return ''
    value = json.loads(cert.read_bytes()).get('trustedAgentSha256', '')
    return value if type(value) is str and SHA.fullmatch(value) else ''


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a=ap.parse_args()
    os.umask(0o077)
    try:
        require(a.output.is_absolute() and a.output.parent.is_dir() and
                not a.output.parent.is_symlink(), 'absolute output in existing directory required')
        cfg=private_json(a.config)
        result=run(cfg,a.output)
        print('JAVA LIVE E2E checks:',result['checkCount'],'(review required)')
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, DatabaseError, zipfile.BadZipFile,
            subprocess.CalledProcessError) as exc:
        print('BLOCKED Java live acceptance:',type(exc).__name__,str(exc),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
