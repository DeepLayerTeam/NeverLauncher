#!/usr/bin/env python3
"""Реальный E2E SDK Go, TypeScript и Java на едином проверенном HTTPS API.

Эндпоинт должен возвращать JSON, обычный текст и настоящие бинарные ресурсы. SHA-256 бинарного
ресурса закрепляется независимо от вывода SDK. Тестовый HTTP-сервер или транспорт-заглушка не могут
удовлетворить сценарию производственной приёмки.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[2]
VERSION=(ROOT/'VERSION').read_text().strip()
class Blocked(ValueError):pass

def need(ok,why):
    if not ok:raise Blocked(why)

def run(cmd,cwd,env,timeout=240):
    result=subprocess.run(cmd,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    need(result.returncode==0 and b'PASS sdk=' in result.stdout and
         len(result.stdout)<8192 and len(result.stderr)<8192,
         'real SDK subprocess did not complete: '+Path(cmd[0]).name)
    return result.stdout.decode('ascii','strict').strip()

def probe(args):
    url=urlsplit(args.origin)
    need(url.scheme=='https' and url.hostname and not (url.username or url.password or url.path not in ('','/') or
         url.query or url.fragment), 'production SDK requires a real HTTPS origin')
    for path in (args.json_path,args.text_path,args.binary_path):
        need(path in ('/metrics',) or path.startswith('/api/v1/'), 'only actual application API routes are accepted')
        need(not any(x in path for x in ('..','?','#','//','\\')),'unsafe API path')
    need(re.fullmatch('[a-f0-9]{64}',args.binary_sha256 or ''),'out-of-band pinned binary checksum required')
    token_path=args.bearer_file
    need(token_path.is_absolute() and token_path.is_file() and not token_path.is_symlink() and
         token_path.stat().st_uid==os.geteuid() and token_path.stat().st_mode & 0o077 == 0 and
         20<=token_path.stat().st_size<=16384,'private 0600 real API token required')
    token=token_path.read_text().strip()
    need(not any(ch.isspace() for ch in token),'invalid credential')
    env={**os.environ,'NL_GA_ORIGIN':args.origin,'NL_GA_BEARER':token,
         'NL_GA_JSON_PATH':args.json_path,'NL_GA_TEXT_PATH':args.text_path,
         'NL_GA_BINARY_PATH':args.binary_path,'NL_GA_BINARY_SHA256':args.binary_sha256}
    # Отдельные скомпилированные клиенты, без подмены реализацией HTTP на Python.
    go=Path(args.go).resolve();node=Path(args.node).resolve();java=Path(args.java).resolve()
    need(all(p.is_file() and os.access(p,os.X_OK) for p in (go,node,java)),
         'Go, Node and Java must be installed real executables')
    javac=shutil.which('javac');tsc=shutil.which('tsc')
    need(javac and tsc,'Java compiler and TypeScript compiler are required')
    go_result=run([str(go),'run','./cmd/live-acceptance'],ROOT/'sdk/api/go',env,240)
    run([tsc,'-p','tsconfig.json'],ROOT/'sdk/api/typescript',env,120)
    ts_result=run([str(node),'test/live_acceptance.mjs'],ROOT/'sdk/api/typescript',env,120)
    # build.sh компилирует производственный Java SDK и ядро без их замены.
    run_build=subprocess.run(['sh','build.sh'],cwd=ROOT/'sdk/java/http-client',env=env,
                             stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    need(run_build.returncode==0,'actual Java HTTP SDK build failed')
    cp=os.pathsep.join((str(ROOT/'sdk/java/http-client/build/classes'),
                        str(ROOT/'sdk/java/core/build/classes')))
    build=ROOT/'sdk/java/http-client/build/tests'
    build.mkdir(parents=True,exist_ok=True)
    java_source=ROOT/'sdk/java/http-client/src/test/java/ru/neverlauncher/api/LiveAcceptance.java'
    compiled=subprocess.run([javac,'--release','17','-cp',cp,'-d',str(build),str(java_source)],
                            cwd=ROOT,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=80)
    need(compiled.returncode==0,'live Java SDK verifier did not compile')
    java_result=run([str(java),'-cp',os.pathsep.join((cp,str(build))),
                     'ru.neverlauncher.api.LiveAcceptance'],ROOT,env,180)
    outputs=(go_result,ts_result,java_result)
    need(all(args.binary_sha256 in r and 'checks=3' in r for r in outputs),
         'not all published clients verified the same binary asset')
    return {'schema':'neverlauncher.sdk-live/0.53.0','version':VERSION,
            'status':'LIVE_SDK_OPERATIONS_PASSED_NOT_GA',
            'checks':['go-json','go-text','go-binary','typescript-json','typescript-text',
                      'typescript-binary','java-json','java-text','java-binary'],
            'binarySha256':args.binary_sha256,
            'outputsSha256':{kind:hashlib.sha256(msg.encode()).hexdigest()
              for kind,msg in zip(('go','typescript','java'),outputs)}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('origin','json-path','text-path','binary-path','binary-sha256','go','node','java'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--bearer-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        need(VERSION=='0.53.0','requires exact 0.53.0 published SDK')
        need(a.output.is_absolute() and not a.output.exists() and a.output.parent.is_dir(),
             'new absolute SDK evidence destination required')
        result=probe(a)
        import inventory_0521 as inventory
        inventory.write_exclusive(a.output,(json.dumps(result,sort_keys=True)+'\n').encode())
        print('PASS: реальные операции HTTP SDK Go, TS и Java прошли на одном HTTPS Backend')
        return 0
    except (Blocked,OSError,ValueError,TypeError,subprocess.TimeoutExpired) as exc:
        print('Реальный сквозной тест SDK заблокирован: '+type(exc).__name__,file=sys.stderr)
        return 3
if __name__=='__main__':raise SystemExit(main())
