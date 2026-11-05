#!/usr/bin/env python3
"""Настоящая закрытая настройка Alertmanager и сбор санитизированных инцидентов на хосте.

Не собираются окружение Compose, секреты, токены доступа или URL запросов. Команды доступны только
для чтения; вывод создаётся с правами 0600 и атомарным переименованием.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
import zipfile

SERVICES = ("api", "api-b", "worker-a", "worker-b", "postgres", "redis", "admin", "nginx")
SAFE_LOG_FIELDS = frozenset(("time", "timestamp", "level", "msg", "event", "correlation_id", "method", "route_group", "status", "duration_ms", "request_id", "backend_correlation_id", "upstream_status", "request_time"))
SAFE_METRIC = re.compile(r'^launcher_(?:http_[a-z0-9_]+|process_[a-z0-9_]+|serverbridge_[a-z0-9_]+|worker_poll_fresh)\s+[-+0-9.eE]+$')

class OperatorError(Exception):
    pass

def ensure_https(url: str) -> str:
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise OperatorError('alert receiver must be a trusted HTTPS endpoint without credentials or fragment')
    hostname=parsed.hostname
    if hostname.lower() in ('localhost', 'localhost.localdomain') or hostname.endswith('.local'):
        raise OperatorError('webhook endpoint cannot be local')
    try:
        addr=ipaddress.ip_address(hostname)
        if not addr.is_global:
            raise OperatorError('webhook IP must be globally routable')
    except ValueError:
        if '.' not in hostname:
            raise OperatorError('webhook must use a fully qualified domain')
    return url

def configure(args):
    raw_url = args.webhook_url
    filename = getattr(args, 'webhook_url_file', None)
    if filename:
        source=Path(filename)
        if not source.is_file() or source.is_symlink() or source.stat().st_mode & 0o077:
            raise OperatorError('webhook URL file must be a private regular file (0600)')
        raw_url=source.read_text(encoding='utf-8').strip()
    url=ensure_https(raw_url)
    target=Path(args.output).expanduser().absolute()
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise OperatorError('refusing symlink/non-file destination')
    target.parent.mkdir(parents=True,exist_ok=True)
    data={"global":{"resolve_timeout":"5m"},
          "route":{"receiver":"operator-webhook","group_by":["alertname"],"group_wait":"30s","group_interval":"5m","repeat_interval":"4h"},
          "receivers":[{"name":"operator-webhook","webhook_configs":[{"url":url,"send_resolved":True}]}]}
    fd,tmp=tempfile.mkstemp(prefix='.alertmanager-',dir=target.parent)
    try:
        os.fchmod(fd,0o640)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(data,stream,indent=2)
            stream.write('\n')
            stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,target)
        directory_fd=os.open(target.parent,os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    # Не выводите URL вебхука: в его пути могут быть секретные данные.
    print('Alertmanager configuration written. Ensure container group can read it:',target)
    print('LAUNCHER_MONITOR_GID=',os.getgid(),sep='')

def run_compose(prefix, extra, *, timeout=30, max_bytes=2_000_000):
    cmd=["docker","compose",*prefix,*extra]
    try:
        p=subprocess.run(cmd, capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise OperatorError('Docker Compose command failed or timed out') from None
    if p.returncode:
        raise OperatorError('Docker Compose command returned a nonzero exit code')
    if len(p.stdout)>max_bytes:
        raise OperatorError('Compose output exceeded its safe limit')
    return p.stdout.decode('utf-8','replace')

def sanitize_status(raw):
    parsed=[]
    raw=raw.strip()
    if not raw:return parsed
    try:
        value=json.loads(raw)
        parsed=value if isinstance(value,list) else [value]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            try:parsed.append(json.loads(line))
            except json.JSONDecodeError:raise OperatorError('unsupported Compose ps JSON output') from None
    answer=[]
    for item in parsed:
        if not isinstance(item,dict): continue
        service=str(item.get('Service',''))
        if service not in SERVICES:continue
        answer.append({k:item[k] for k in ('Service','Name','State','Health','ExitCode') if k in item and isinstance(item[k],(str,int))})
    return answer

def sanitize_logs(raw):
    clean=[]
    safe_methods={'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'}
    safe_route_groups={'api','health','ready','metrics','admin','storage','other'}
    for line in raw.splitlines():
        if len(clean)>=1500:break
        # Compose может добавлять префикс службы. Принимайте ТОЛЬКО проверенные
        # форматы журналов.
        pos=line.find('{')
        if pos<0:continue
        try: entry=json.loads(line[pos:])
        except json.JSONDecodeError:continue
        if not isinstance(entry,dict):continue
        if entry.get('msg') not in ('http_request','http_panic') and entry.get('event') != 'reverse_proxy_request':continue
        accepted={}
        for key, val in entry.items():
            if key not in SAFE_LOG_FIELDS:continue
            if key == 'method' and isinstance(val,str) and val in safe_methods:
                accepted[key]=val
            elif key == 'route_group' and isinstance(val,str) and val in safe_route_groups:
                accepted[key]=val
            elif key == 'status' and type(val)==int and 100<=val<=599:
                accepted[key]=val
            elif key in ('correlation_id','request_id','backend_correlation_id') and isinstance(val,str) and (not val or re.fullmatch(r'[0-9a-f]{32}',val)):
                accepted[key]=val
            elif key in ('time','timestamp') and isinstance(val,str) and re.fullmatch(r'[0-9TZ:+.-]{10,40}',val):
                accepted[key]=val
            elif key == 'level' and isinstance(val,str) and val in ('INFO','WARN','ERROR','DEBUG'):
                accepted[key]=val
            elif key == 'msg' and isinstance(val,str) and val in ('http_request','http_panic'):
                accepted[key]=val
            elif key == 'event' and val == 'reverse_proxy_request':
                accepted[key]=val
            elif key in ('duration_ms','request_time') and type(val) in (float,int) and 0<=val<1e9:
                accepted[key]=val
            elif key == 'request_time' and isinstance(val,str) and re.fullmatch(r'[0-9]{1,9}(?:\.[0-9]{1,6})?',val):
                accepted[key]=val
            elif key == 'upstream_status' and isinstance(val,str) and re.fullmatch(r'[0-9]{3}(?:, [0-9]{3})*|-',val):
                accepted[key]=val
        if accepted:clean.append(accepted)
    return clean

def sanitize_metrics(raw):
    return [line for line in raw.splitlines() if SAFE_METRIC.fullmatch(line)][:200]

def build_bundle(status, logs, metrics, version):
    now=dt.datetime.now(dt.timezone.utc).isoformat()
    data={"schema":"neverlauncher-incident-0459", "incident_id":uuid.uuid4().hex,"created_at":now,
          "system":{"version":version, "status":status},"logs":logs,"metrics":metrics,
          "omissions":["secrets","environment","HTTP URL/query","request/response body","IP","authentication","legacy unstructured logs"]}
    return json.dumps(data,ensure_ascii=False,indent=2).encode('utf-8')+b'\n'

def incident(args):
    output=Path(args.output).expanduser().absolute()
    if output.exists() or output.is_symlink():raise OperatorError('incident output must not already exist')
    if not output.parent.is_dir():raise OperatorError('output parent does not exist')
    prefix=['-f',str(Path(args.compose).absolute()),'-p',args.project]
    if args.overlay:prefix.extend(['-f',str(Path(args.overlay).absolute())])
    status=sanitize_status(run_compose(prefix,['ps','--format','json']))
    if not status:raise OperatorError('no known running Compose services were found')
    services=[s['Service'] for s in status if s.get('Service') in ('api','api-b','worker-a','worker-b','nginx') and s.get('State')=='running']
    logs={}
    for svc in services:
        logs[svc]=sanitize_logs(run_compose(prefix,['logs','--no-color','--since',args.since,svc],max_bytes=4_000_000))
    metrics={}
    for svc in ('api','api-b','worker-a','worker-b'):
        if svc not in services:continue
        try:
            raw=run_compose(prefix,['exec','-T',svc,'wget','-qO-','http://127.0.0.1:8080/metrics'],timeout=15,max_bytes=200_000)
            metrics[svc]=sanitize_metrics(raw)
        except OperatorError:
            metrics[svc]=[]
    payload=build_bundle(status,logs,metrics,args.version)
    digest=hashlib.sha256(payload).hexdigest()
    fd,tmp=tempfile.mkstemp(prefix='.nl-incident-',dir=output.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('incident.json',payload)
                archive.writestr('sha256.txt',digest+'  incident.json\n')
            stream.flush();os.fsync(stream.fileno())
        os.rename(tmp,output)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    print('Incident collected:',output,'sha256:',digest)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    conf=sub.add_parser('configure',help="Создать закрытую производственную конфигурацию Alertmanager")
    conf.add_argument('--webhook-url',default=os.environ.get('LAUNCHER_ALERT_WEBHOOK_URL',''))
    conf.add_argument('--output',required=True)
    conf.add_argument('--webhook-url-file',help="Закрытый файл 0600; не раскрывает секретный путь получателя через argv")
    take=sub.add_parser('incident',help="Собрать архив ZIP инцидента Compose только для чтения с удалёнными секретами")
    take.add_argument('--compose',default='deploy/production/docker-compose.yml')
    take.add_argument('--overlay')
    take.add_argument('--project',required=True)
    take.add_argument('--since',default='15m')
    take.add_argument('--version',default='unknown')
    take.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        if args.operation=='configure':configure(args)
        else:
            if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}',args.project):raise OperatorError('invalid Compose project')
            if not re.fullmatch(r'[1-9][0-9]?[mhd]',args.since):raise OperatorError('since must be short relative duration (15m)')
            incident(args)
    except OperatorError as err:
        # Детали ошибки намеренно не содержат stdout команды и секретов.
        print('ERROR:',err,file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':sys.exit(main())
