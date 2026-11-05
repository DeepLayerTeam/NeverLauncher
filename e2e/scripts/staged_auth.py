#!/usr/bin/env python3
"""Живые проверки аутентификации V07. НИКОГДА не использовать свидетельства из имитаций или автономной игры.

Работает в заранее одобренном изолированном исполнителе с выделенными краткоживущими тестовыми
идентификаторами. Учётные данные внедряются как файлы только для чтения хостовым аттестатором.
Покидать исполнитель могут только результаты без секретов и дайджесты идентичности провайдера.
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
        raise ProviderMisconfigured('Действующий провайдер должен использовать постоянный HTTPS-адрес')
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
            if len(raw)>65536: raise ProviderRejected('Слишком большой ответ провайдера')
            return response.status,json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code in (408,425,429) or exc.code>=500:
            raise ProviderUnavailable('Внешний провайдер временно недоступен') from None
        body=exc.read(2048).decode('utf-8','replace').lower()
        if 'trust policy denied' in body: raise ProviderRejected(('guard ' if 'guard' in body else '')+'trust policy denied') from None
        if 'integrity policy denied' in body: raise ProviderRejected(('guard ' if 'guard' in body else '')+'integrity policy denied') from None
        raise ProviderRejected('Провайдер отклонил запрос аутентификации') from None
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        raise ProviderUnavailable('Нет сетевого соединения с внешним провайдером') from None
    except (ValueError,UnicodeError) as exc:
        raise ProviderRejected('Некорректный ответ действующего провайдера') from None

def validate_identity(profile, credentials):
    name=profile.get('name','') if isinstance(profile,dict) else ''
    uuid=profile.get('id','') if isinstance(profile,dict) else ''
    if not USERNAME.fullmatch(name) or not HEXUUID.fullmatch(uuid):
        raise ProviderRejected('В профиле провайдера нет действительного идентификатора Minecraft')
    if (name.lower()!=credentials['username'].lower() or
        uuid.lower()!=credentials['uuid'].replace('-','').lower()):
        raise ProviderRejected('Учётная запись в профиле провайдера не совпадает с подготовленным клиентом')
    return hashlib.sha256((uuid.lower()+':'+name.lower()).encode()).hexdigest()

def official_probe(credentials, package_mode):
    if package_mode != 'official' or credentials.get('userType')!='msa' or credentials.get('authServerBaseUrl'):
        raise ProviderMisconfigured('Для официального входа необходим действительный токен MSA и сервер сеансов Mojang')
    token=credentials['accessToken']
    if not token or token in ('offline','0'):
        raise ProviderRejected('Автономный или тестовый токен не подтверждает официальный вход')
    _,profile=provider_request('https://api.minecraftservices.com','/minecraft/profile',token=token)
    profile_sha=validate_identity(profile,credentials)
    challenge=secrets.token_hex(20)
    code,_=provider_request(OFFICIAL_SESSION,'/session/minecraft/join',method='POST',data={
        'accessToken':token,'selectedProfile':credentials['uuid'].replace('-',''), 'serverId':challenge})
    if code!=204:raise ProviderRejected('Сервер отклонил официальный запрос на присоединение')
    q=urllib.parse.urlencode({'username':credentials['username'],'serverId':challenge})
    _,joined=provider_request(OFFICIAL_SESSION,'/session/minecraft/hasJoined?'+q)
    if validate_identity(joined,credentials)!=profile_sha:
        raise ProviderRejected('Данные hasJoined не совпадают с учётной записью в профиле')
    return {'mode':'official','source':'live-minecraft-services-and-mojang-sessionserver',
            'profileSha256':profile_sha,'providerJoin':'passed','providerHasJoined':'passed',
            'serverOnlineModeRequired':True}

def custom_probe(credentials, negative_credentials):
    if credentials.get('userType')!='mojang':
        raise ProviderMisconfigured('Для пользовательской аутентификации требуется действительный сеанс Yggdrasil')
    base=credentials.get('authServerBaseUrl','').rstrip('/')
    if not base or base in ('https://example.com','https://example.org'):
        raise ProviderMisconfigured('Пользовательский провайдер Yggdrasil должен быть настроен явно')
    # НЕ принимайте произвольные локальные или имитирующие серверы за настоящего внешнего провайдера.
    parsed=urllib.parse.urlsplit(base)
    if parsed.hostname in ('localhost','127.0.0.1','::1'):
        raise ProviderMisconfigured('Локальная имитация не является приёмкой действующего пользовательского провайдера')
    if negative_credentials.get('accessToken') == credentials.get('accessToken'):
        raise ProviderMisconfigured('Для отрицательной проверки и отзыва нужна отдельная учётная запись')
    for c in (credentials,negative_credentials):
        if c.get('authServerBaseUrl','').rstrip('/')!=base or c.get('userType')!='mojang':
            raise ProviderMisconfigured('Использование разных провайдеров Yggdrasil запрещено')
        code,_=provider_request(base,'/authserver/validate',method='POST',data={'accessToken':c['accessToken']})
        if code!=204:raise ProviderRejected('Проверка пользовательского сеанса отклонена')
    def join(c, challenge):
        status,_=provider_request(base,'/sessionserver/session/minecraft/join',method='POST',data={
            'accessToken':c['accessToken'],'selectedProfile':c['uuid'].replace('-',''),'serverId':challenge})
        if status!=204:raise ProviderRejected('Пользовательский запрос на присоединение отклонён')
    def has_joined(c, challenge):
        q=urllib.parse.urlencode({'username':c['username'],'serverId':challenge})
        status,profile=provider_request(base,'/sessionserver/session/minecraft/hasJoined?'+q)
        if status==204:return False
        validate_identity(profile,c)
        return True
    live_challenge=secrets.token_hex(32)
    join(credentials,live_challenge)
    if not has_joined(credentials,live_challenge):
        raise ProviderRejected('Запрос hasJoined не подтвердил действующий сеанс')
    # Существующий Backend использует атомарное одноразовое погашение входов Yggdrasil.
    if has_joined(credentials,live_challenge):
        raise ProviderRejected('Система ошибочно приняла повторно использованный билет входа')
    revoked_challenge=secrets.token_hex(32)
    join(negative_credentials,revoked_challenge)
    status,_=provider_request(base,'/authserver/invalidate',method='POST',data={
        'accessToken':negative_credentials['accessToken']})
    if status!=204:raise ProviderRejected('Не удалось отозвать пользовательский сеанс')
    if has_joined(negative_credentials,revoked_challenge):
        raise ProviderRejected('Отозванный сеанс Minecraft сохранил право на присоединение')
    return {'mode':'custom','source':'live-yggdrasil-session-and-authserver',
            'profileSha256':hashlib.sha256((credentials['uuid'].replace('-','').lower()+':'+credentials['username'].lower()).encode()).hexdigest(),
            'providerJoin':'passed','providerHasJoined':'passed','replayDenied':True,
            'revokedSessionDenied':True,'serverOnlineModeRequired':False}

def run_probe(mode,credentials_path,negative_path=None,expected_backend=None):
    if mode not in ('official','custom'):
        raise ProviderMisconfigured('Автономные и имитированные запуски не подтверждают провайдера')
    def read_credential(path):
        p=Path(path)
        if not p.is_file() or p.is_symlink() or p.stat().st_size>16384:
            raise ProviderMisconfigured('Файл учётных данных тестовой записи отсутствует или небезопасен')
        c=json.loads(p.read_text())
        if not isinstance(c,dict) or not all(k in c for k in ('username','uuid','accessToken','userType','authServerBaseUrl')):
            raise ProviderMisconfigured('Некорректный объект учётных данных тестовой записи')
        if not USERNAME.fullmatch(c['username']) or not HEXUUID.fullmatch(c['uuid'].replace('-','')) or not (8<=len(c['accessToken'])<=8192):
            raise ProviderMisconfigured('Недействительная учётная запись или токен тестового пользователя')
        return c
    c=read_credential(credentials_path)
    if mode=='custom':
        # Только точный тестовый Backend может выдавать доверенный пользовательский сеанс. Сторонняя
        # имитация с действительным публичным TLS-сертификатом НЕ является доказательством.
        if not expected_backend or c.get('authServerBaseUrl','').rstrip('/')!=expected_backend.rstrip('/'):
            raise ProviderMisconfigured('Провайдер аутентификации отличается от подготовленного Backend')
    negative=read_credential(negative_path) if mode=='custom' and negative_path else None
    if mode=='custom' and negative is None:
        raise ProviderMisconfigured('Требуется отдельный тестовый сеанс с возможностью отзыва')
    return (official_probe(c,mode) if mode=='official' else custom_probe(c,negative)),c

def guard_denial_probe(active, denied_path):
    """Реальная идентичность с отказом по политике устройства/доверия/Guard, подготовленная тестовым оператором.

    Отсутствующую идентичность для отрицательного теста НИКОГДА нельзя заменить имитированным HTTP
    403. Её токен должен оставаться действительным, но вход должен отклоняться живой политикой
    доверия к игровому процессу Backend.
    """
    p=Path(denied_path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size>16384:
        raise ProviderMisconfigured('Учётная запись с отказом по политике доверия отсутствует или небезопасна')
    denied=json.loads(p.read_text())
    if (denied.get('userType')!='mojang' or
        denied.get('authServerBaseUrl')!=active.get('authServerBaseUrl') or
        denied.get('accessToken')==active.get('accessToken')):
        raise ProviderMisconfigured('Учётная запись с отказом по политике доверия не изолирована от действующей записи')
    base=active['authServerBaseUrl'].rstrip('/')
    code,_=provider_request(base,'/authserver/validate',method='POST',data={'accessToken':denied['accessToken']})
    if code!=204:raise ProviderRejected('Перед проверкой отказа на вход отрицательный тестовый сеанс должен оставаться действительным')
    payload={'accessToken':denied['accessToken'],
             'selectedProfile':denied['uuid'].replace('-',''),'serverId':secrets.token_hex(32)}
    try:
        provider_request(base,'/sessionserver/session/minecraft/join',method='POST',data=payload)
    except ProviderRejected as exc:
        # Недостаточно только кода состояния: требуется отказ по политике, сформированный Backend.
        if 'trust policy denied' not in str(exc) and 'integrity policy denied' not in str(exc):
            raise ProviderRejected('Вход отклонён без проверяемой причины из политики доверия или Guard') from None
        return {'negativeGuardJoinDenied':'guard' in str(exc), 'negativeDeviceTrustJoinDenied':True}
    raise ProviderRejected('Учётная запись, которой запрещён вход, смогла присоединиться')
