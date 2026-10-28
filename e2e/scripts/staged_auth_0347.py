#!/usr/bin/env python3
"""Live V07 authentication probes. NEVER evidence from mocks/offline gameplay.

Runs inside a pre-approved isolated worker using dedicated, short-lived test
identities. Credentials are injected as read-only files by the host attestor.
Only redacted outcomes and provider identity digests may leave the worker.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request

OFFICIAL_PROFILE = 'https://api.minecraftservices.com/minecraft/profile'
OFFICIAL_SESSION = 'https://sessionserver.mojang.com'
HEXUUID = re.compile(r'^[0-9a-fA-F]{32}$')
USERNAME = re.compile(r'^[A-Za-z0-9_]{3,16}$')

class ProviderUnavailable(RuntimeError): pass
class ProviderRejected(RuntimeError): pass
class ProviderMisconfigured(RuntimeError): pass

def provider_request(base, path, *, method='GET', data=None, token=None):
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProviderMisconfigured('real provider must use a fixed HTTPS origin')
    headers={'Accept':'application/json'}
    if token: headers['Authorization']='Bearer '+token
    body=None
    if data is not None:
        body=json.dumps(data, separators=(',',':')).encode()
        headers['Content-Type']='application/json'
    req=urllib.request.Request(base.rstrip('/')+path,data=body,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=15,context=ssl.create_default_context()) as response:
            if response.status==204:return response.status,None
            raw=response.read(65537)
            if len(raw)>65536: raise ProviderRejected('oversized provider response')
            return response.status,json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code in (408,425,429) or exc.code>=500:
            raise ProviderUnavailable('external provider temporarily unavailable') from None
        body=exc.read(2048).decode('utf-8','replace').lower()
        if 'trust policy denied' in body: raise ProviderRejected(('guard ' if 'guard' in body else '')+'trust policy denied') from None
        if 'integrity policy denied' in body: raise ProviderRejected(('guard ' if 'guard' in body else '')+'integrity policy denied') from None
        raise ProviderRejected('provider rejected the authentication request') from None
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        raise ProviderUnavailable('external provider transport unavailable') from None
    except (ValueError,UnicodeError) as exc:
        raise ProviderRejected('malformed live provider response') from None

def validate_identity(profile, credentials):
    name=profile.get('name','') if isinstance(profile,dict) else ''
    uuid=profile.get('id','') if isinstance(profile,dict) else ''
    if not USERNAME.fullmatch(name) or not HEXUUID.fullmatch(uuid):
        raise ProviderRejected('provider profile is missing a valid Minecraft identity')
    if (name.lower()!=credentials['username'].lower() or
        uuid.lower()!=credentials['uuid'].replace('-','').lower()):
        raise ProviderRejected('provider profile identity does not match staged client')
    return hashlib.sha256((uuid.lower()+':'+name.lower()).encode()).hexdigest()

def official_probe(credentials, package_mode):
    if package_mode != 'official' or credentials.get('userType')!='msa' or credentials.get('authServerBaseUrl'):
        raise ProviderMisconfigured('official login must use a real MSA token and Mojang sessionserver')
    token=credentials['accessToken']
    if not token or token in ('offline','0'):
        raise ProviderRejected('offline/mock token cannot certify official login')
    _,profile=provider_request('https://api.minecraftservices.com','/minecraft/profile',token=token)
    profile_sha=validate_identity(profile,credentials)
    challenge=secrets.token_hex(20)
    code,_=provider_request(OFFICIAL_SESSION,'/session/minecraft/join',method='POST',data={
        'accessToken':token,'selectedProfile':credentials['uuid'].replace('-',''), 'serverId':challenge})
    if code!=204:raise ProviderRejected('official join not accepted')
    q=urllib.parse.urlencode({'username':credentials['username'],'serverId':challenge})
    _,joined=provider_request(OFFICIAL_SESSION,'/session/minecraft/hasJoined?'+q)
    if validate_identity(joined,credentials)!=profile_sha:
        raise ProviderRejected('official hasJoined identity differs from profile')
    return {'mode':'official','source':'live-minecraft-services-and-mojang-sessionserver',
            'profileSha256':profile_sha,'providerJoin':'passed','providerHasJoined':'passed',
            'serverOnlineModeRequired':True}

def custom_probe(credentials, negative_credentials):
    if credentials.get('userType')!='mojang':
        raise ProviderMisconfigured('custom auth requires a real Yggdrasil session')
    base=credentials.get('authServerBaseUrl','').rstrip('/')
    if not base or base in ('https://example.com','https://example.org'):
        raise ProviderMisconfigured('custom Yggdrasil provider must be explicitly configured')
    # Do NOT accept arbitrary loopback/mock servers as a real external provider.
    parsed=urllib.parse.urlsplit(base)
    if parsed.hostname in ('localhost','127.0.0.1','::1'):
        raise ProviderMisconfigured('loopback mock is not live custom-provider certification')
    if negative_credentials.get('accessToken') == credentials.get('accessToken'):
        raise ProviderMisconfigured('negative/revocation account must be separate')
    for c in (credentials,negative_credentials):
        if c.get('authServerBaseUrl','').rstrip('/')!=base or c.get('userType')!='mojang':
            raise ProviderMisconfigured('mixed Yggdrasil providers are forbidden')
        code,_=provider_request(base,'/authserver/validate',method='POST',data={'accessToken':c['accessToken']})
        if code!=204:raise ProviderRejected('custom session validate not accepted')
    def join(c, challenge):
        status,_=provider_request(base,'/sessionserver/session/minecraft/join',method='POST',data={
            'accessToken':c['accessToken'],'selectedProfile':c['uuid'].replace('-',''),'serverId':challenge})
        if status!=204:raise ProviderRejected('custom join not accepted')
    def has_joined(c, challenge):
        q=urllib.parse.urlencode({'username':c['username'],'serverId':challenge})
        status,profile=provider_request(base,'/sessionserver/session/minecraft/hasJoined?'+q)
        if status==204:return False
        validate_identity(profile,c)
        return True
    live_challenge=secrets.token_hex(32)
    join(credentials,live_challenge)
    if not has_joined(credentials,live_challenge):
        raise ProviderRejected('custom hasJoined did not redeem a live session')
    # Existing backend uses atomic consume-once Yggdrasil joins.
    if has_joined(credentials,live_challenge):
        raise ProviderRejected('custom join ticket replay was accepted')
    revoked_challenge=secrets.token_hex(32)
    join(negative_credentials,revoked_challenge)
    status,_=provider_request(base,'/authserver/invalidate',method='POST',data={
        'accessToken':negative_credentials['accessToken']})
    if status!=204:raise ProviderRejected('custom session revocation failed')
    if has_joined(negative_credentials,revoked_challenge):
        raise ProviderRejected('revoked custom Minecraft session retained join authorization')
    return {'mode':'custom','source':'live-yggdrasil-session-and-authserver',
            'profileSha256':hashlib.sha256((credentials['uuid'].replace('-','').lower()+':'+credentials['username'].lower()).encode()).hexdigest(),
            'providerJoin':'passed','providerHasJoined':'passed','replayDenied':True,
            'revokedSessionDenied':True,'serverOnlineModeRequired':False}

def run_probe(mode,credentials_path,negative_path=None,expected_backend=None):
    if mode not in ('official','custom'):
        raise ProviderMisconfigured('offline/mock executions are not provider certification')
    def read_credential(path):
        p=Path(path)
        if not p.is_file() or p.is_symlink() or p.stat().st_size>16384:
            raise ProviderMisconfigured('missing or unsafe test-account credential file')
        c=json.loads(p.read_text())
        if not isinstance(c,dict) or not all(k in c for k in ('username','uuid','accessToken','userType','authServerBaseUrl')):
            raise ProviderMisconfigured('invalid test-account credential object')
        if not USERNAME.fullmatch(c['username']) or not HEXUUID.fullmatch(c['uuid'].replace('-','')) or not (8<=len(c['accessToken'])<=8192):
            raise ProviderMisconfigured('invalid test-account identity or token')
        return c
    c=read_credential(credentials_path)
    if mode=='custom':
        # Only the exact staged Backend may issue a trusted custom session.
        # A third-party mock with a valid public TLS certificate is NOT proof.
        if not expected_backend or c.get('authServerBaseUrl','').rstrip('/')!=expected_backend.rstrip('/'):
            raise ProviderMisconfigured('custom auth provider differs from the staged Backend')
    negative=read_credential(negative_path) if mode=='custom' and negative_path else None
    if mode=='custom' and negative is None:
        raise ProviderMisconfigured('separate revocable test session is required')
    return (official_probe(c,mode) if mode=='official' else custom_probe(c,negative)),c

def guard_denial_probe(active, denied_path):
    """A real device/trust/Guard denied identity, provisioned by test operator.

    A missing negative test identity can NEVER be replaced by a mocked 403.
    This identity must have a token which remains valid but is denied by the
    backend's live gameplay-trust policy on join.
    """
    p=Path(denied_path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size>16384:
        raise ProviderMisconfigured('missing or unsafe trust-denied identity')
    denied=json.loads(p.read_text())
    if (denied.get('userType')!='mojang' or
        denied.get('authServerBaseUrl')!=active.get('authServerBaseUrl') or
        denied.get('accessToken')==active.get('accessToken')):
        raise ProviderMisconfigured('trust-denied identity not isolated from live account')
    base=active['authServerBaseUrl'].rstrip('/')
    code,_=provider_request(base,'/authserver/validate',method='POST',data={'accessToken':denied['accessToken']})
    if code!=204:raise ProviderRejected('negative trust session must be valid before join denial')
    payload={'accessToken':denied['accessToken'],
             'selectedProfile':denied['uuid'].replace('-',''),'serverId':secrets.token_hex(32)}
    try:
        provider_request(base,'/sessionserver/session/minecraft/join',method='POST',data=payload)
    except ProviderRejected as exc:
        # Stronger than status-only: a backend generated policy denial is needed.
        if 'trust policy denied' not in str(exc) and 'integrity policy denied' not in str(exc):
            raise ProviderRejected('negative join denied without verifiable trust/Guard policy reason') from None
        return {'negativeGuardJoinDenied':'guard' in str(exc), 'negativeDeviceTrustJoinDenied':True}
    raise ProviderRejected('trust-denied test identity was able to join')
