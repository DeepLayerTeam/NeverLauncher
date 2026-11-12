#!/usr/bin/env python3
"""Скачать ранее подписанные байты выпуска через staging/public HTTPS и принять их.

Нужны существующий подписанный локальный пакет, закреплённые ключи проверки и производственный
CLI-валидатор. Для незагруженных файлов приёмка не выдаётся.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from delivery_verify_0462 import verify_bundle

MAX_ASSET_BYTES=2*1024*1024*1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Перенаправления на этапе подготовки выпуска запрещены')


def file_hash(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''): h.update(part)
    return h.hexdigest()


def require_remote(base_url: str, version: str) -> str:
    p=urllib.parse.urlsplit(base_url)
    if (p.scheme!='https' or not p.hostname or p.username or p.password
            or p.query or p.fragment or '%' in p.path or any(s in ('.','..') for s in p.path.split('/'))):
        raise ValueError('Источник подготовки выпуска должен иметь неизменяемый HTTPS-путь без учётных данных, запроса и фрагмента')
    if ('v'+version not in p.path.split('/') and version not in p.path.split('/')):
        raise ValueError('Источник подготовки выпуска должен содержать точную версию в сегменте пути')
    return base_url.rstrip('/')+'/'


def compare_downloaded(local: Path, base_url: str, dst: Path, version: str):
    url=require_remote(base_url,version)
    opener=urllib.request.build_opener(NoRedirect())
    files=[]
    for path in sorted(local.iterdir()):
        if path.is_symlink() or (not path.is_file()):
            raise ValueError('Выпуск содержит символическую ссылку или нестандартный файл: '+path.name)
        if '/' in path.name or '\\' in path.name or path.name in ('.','..'):
            raise ValueError('Небезопасный путь к ресурсу выпуска')
        size=path.stat().st_size
        if size<=0 or size>MAX_ASSET_BYTES:raise ValueError('Некорректный размер локального ресурса: '+path.name)
        target=dst/path.name
        req=urllib.request.Request(url+urllib.parse.quote(path.name,safe=''),headers={'Accept-Encoding':'identity'},method='GET')
        with opener.open(req,timeout=40) as res:
            if res.status!=200 or res.headers.get('Content-Encoding','identity')!='identity':
                raise ValueError('Некорректный HTTP-ответ при подготовке выпуска: '+path.name)
            total=0
            with target.open('xb') as out:
                while True:
                    chunk=res.read(1024*1024)
                    if not chunk:break
                    total+=len(chunk)
                    if total>size:raise ValueError('Удалённый файл слишком велик: '+path.name)
                    out.write(chunk)
        if total!=size or file_hash(target)!=file_hash(path):
            raise ValueError('Удалённый файл отличается от защищённого локального выпуска: '+path.name)
        files.append({'name':path.name,'sha256':file_hash(target),'size':size})
    return files


def run_verify(cli: Path, bundle: Path, public: Path, policy: Path, operator: Path):
    if not cli.is_file() or not public.is_file() or not policy.is_file() or not operator.is_file():
        raise ValueError('Обязательны промышленный CLI и внешние ключи проверки выпуска и оператора')
    for secret in (public,policy,operator):
        if secret.is_symlink():raise ValueError('Внешний файл доверия должен быть обычным файлом')
    if operator.resolve().is_relative_to(bundle.resolve()):
        raise ValueError('Корневой доверенный ключ оператора не должен находиться внутри пакета выпуска')
    with tempfile.TemporaryDirectory(prefix='nl462-trust-') as td:
        env={**os.environ,'LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE':str(operator.resolve())}
        for argv in (
            [str(cli.resolve()),'release','verify',str(bundle),'--public-key',str(public),
             '--trust-policy',str(policy),'--trust-state',str(Path(td)/'trust-state.json')],
            [str(cli.resolve()),'release','distribution-verify',str(bundle)],
        ):
            subprocess.run(argv,check=True,timeout=300,env=env)


def accept(local: Path,base_url: str,cli: Path,public: Path,policy: Path,operator: Path,report: Path) -> dict:
    source=verify_bundle(local,True)
    version=source['version']
    # Проверяйте источник ДО скачивания: локальный пакет уже должен быть запечатан
    # закреплённым корневым ключом доверия оператора.
    run_verify(cli,local,public,policy,operator)
    with tempfile.TemporaryDirectory(prefix='nl462-stage-') as td:
        remote=Path(td)
        files=compare_downloaded(local,base_url,remote,version)
        verify_bundle(remote,True)
        # Независимо проверьте скачанную подпись и промышленный дистрибутив.
        run_verify(cli,remote,public,policy,operator)
    result={'schema':'launcher.remote-acceptance.v1','version':version,
            'status':'verified-staged-final-bytes','origin':base_url,
            'downloadedFiles':len(files),'downloadedBytes':sum(x['size'] for x in files),
            'assets':files}
    report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf8')
    return result


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--base-url',required=True)
    p.add_argument('--cli',type=Path,required=True)
    p.add_argument('--public-key',type=Path,required=True)
    p.add_argument('--trust-policy',type=Path,required=True)
    p.add_argument('--operator-key',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    args=p.parse_args()
    try:
        print(json.dumps(accept(args.bundle,args.base_url,args.cli,args.public_key,args.trust_policy,args.operator_key,args.report),sort_keys=True))
        return 0
    except (OSError,ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired,urllib.error.URLError,KeyError,TypeError) as exc:
        print('Приёмка подготовленного выпуска заблокирована: '+str(exc),file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
