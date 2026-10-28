#!/usr/bin/env python3
"""Host-only Microsoft -> XBL -> XSTS -> Minecraft Java token exchange.

Operator must authorize a dedicated test Minecraft Java account once via
public-client PKCE/device flow. The refresh token remains on the host and
is NEVER mounted into the untrusted runtime container. Only a short-lived
Minecraft access token is passed to the isolated worker.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MS = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token'
XBL = 'https://user.auth.xboxlive.com/user/authenticate'
XSTS = 'https://xsts.auth.xboxlive.com/xsts/authorize'
MINECRAFT = 'https://api.minecraftservices.com'

class ExternalOutage(RuntimeError): pass
class AccountRejected(RuntimeError): pass

def request_live(url, payload=None, bearer='', form=False):
    if url not in (MS,XBL,XSTS,MINECRAFT+'/authentication/login_with_xbox',MINECRAFT+'/minecraft/profile'):
        raise AccountRejected('untrusted provider endpoint')
    body=None;headers={'Accept':'application/json'}
    if bearer:headers['Authorization']='Bearer '+bearer
    if payload is not None:
        if form:
            body=urllib.parse.urlencode(payload).encode()
            headers['Content-Type']='application/x-www-form-urlencoded'
        else:
            body=json.dumps(payload,separators=(',',':')).encode()
            headers['Content-Type']='application/json'
    request=urllib.request.Request(url,data=body,headers=headers,method='POST' if body is not None else 'GET')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
    try:
        with client.open(request,timeout=18) as resp:
            if resp.status!=200:raise AccountRejected('real authentication returned non-success')
            raw=resp.read(1024*1024+1)
            if len(raw)>1024*1024:raise AccountRejected('oversized provider response')
            out=json.loads(raw)
            if not isinstance(out,dict):raise AccountRejected('invalid provider response')
            return out
    except urllib.error.HTTPError as exc:
        if exc.code in (408,425,429) or exc.code>=500:
            raise ExternalOutage('real official provider temporarily unavailable') from None
        raise AccountRejected('official provider denied dedicated test account') from None
    except (urllib.error.URLError,TimeoutError,OSError):
        raise ExternalOutage('official provider transport unavailable') from None
    except (UnicodeError,ValueError):
        raise AccountRejected('malformed official provider response') from None

def require_token(response,name):
    token=response.get(name)
    if not isinstance(token,str) or not (8 <= len(token) <= 8192) or '\n' in token:
        raise AccountRejected('real provider did not issue a valid token')
    return token

def refresh_file_atomic(path,new_token):
    path=Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise AccountRejected('host refresh token file must be private regular file')
    fd,tmp=tempfile.mkstemp(prefix='.nl-refresh-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write(new_token+'\n');stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        dirfd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def issue_minecraft_credentials(client_id,refresh_token_file,output):
    if not re.fullmatch(r'[0-9a-fA-F-]{36}',client_id):
        raise AccountRejected('dedicated Microsoft public-client ID is missing')
    token_file=Path(refresh_token_file)
    if not token_file.is_file() or token_file.is_symlink() or token_file.stat().st_mode & 0o077:
        raise AccountRejected('refresh token file must be private host file')
    refresh=token_file.read_text().strip()
    require_token({'t':refresh},'t')
    oauth=request_live(MS,{'client_id':client_id,'refresh_token':refresh,'grant_type':'refresh_token',
                           'scope':'XboxLive.signin offline_access'},form=True)
    ms_access=require_token(oauth,'access_token')
    replacement=oauth.get('refresh_token')
    if replacement:
        require_token(oauth,'refresh_token')
        if replacement!=refresh:refresh_file_atomic(token_file,replacement)
    xbl=request_live(XBL,{'Properties':{'AuthMethod':'RPS','SiteName':'user.auth.xboxlive.com',
                                      'RpsTicket':'d='+ms_access},
                         'RelyingParty':'http://auth.xboxlive.com','TokenType':'JWT'})
    xbl_token=require_token(xbl,'Token')
    xui=xbl.get('DisplayClaims',{}).get('xui',[])
    if len(xui)!=1 or not isinstance(xui[0].get('uhs'),str) or not xui[0]['uhs']:
        raise AccountRejected('XBL user identity not established')
    uhs=xui[0]['uhs']
    xsts=request_live(XSTS,{'Properties':{'SandboxId':'RETAIL','UserTokens':[xbl_token]},
                            'RelyingParty':'rp://api.minecraftservices.com/','TokenType':'JWT'})
    xsts_token=require_token(xsts,'Token')
    xsts_users=xsts.get('DisplayClaims',{}).get('xui',[])
    if len(xsts_users)!=1 or xsts_users[0].get('uhs')!=uhs:
        raise AccountRejected('XSTS identity not bound to Xbox Live user')
    game=request_live(MINECRAFT+'/authentication/login_with_xbox',
                      {'identityToken':f'XBL3.0 x={uhs};{xsts_token}'})
    minecraft_token=require_token(game,'access_token')
    if game.get('token_type')!='Bearer' or not isinstance(game.get('expires_in'),int) or game['expires_in']<300:
        raise AccountRejected('short-lived/invalid Minecraft services access token')
    profile=request_live(MINECRAFT+'/minecraft/profile',bearer=minecraft_token)
    username=profile.get('name'); uuid=profile.get('id')
    if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_]{3,16}',username) or not isinstance(uuid,str) or not re.fullmatch(r'[a-fA-F0-9]{32}',uuid):
        raise AccountRejected('test account does not own a valid Minecraft Java profile')
    record={'username':username,'uuid':uuid.lower(),'accessToken':minecraft_token,
            'userType':'msa','authServerBaseUrl':''}
    output=Path(output)
    with output.open('x',encoding='utf-8') as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(record,stream,separators=(',',':'))
        stream.flush();os.fsync(stream.fileno())
    return {'provider':'real-microsoft-xbox-xsts-minecraft','usernameBound':True,
            'expiresInSeconds':game['expires_in']}
