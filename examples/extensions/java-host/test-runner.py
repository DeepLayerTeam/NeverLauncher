#!/usr/bin/env python3
"""Executes the actual signed-package-compatible Java JAR, not an in-process mock SDK."""
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
STAGE = ROOT / 'build' / 'package'
TOKEN = 'java-host-real-transport-test-token'
CALLBACK = 'java-host-real-callback-test-token'

class Handler(http.server.BaseHTTPRequestHandler):
    hellos = 0
    readies = 0
    manifests = 0
    heartbeat = 0
    callback = None
    lock = threading.Lock()
    def log_message(self, *_):pass
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer '+TOKEN:
            self.send_error(401);return
        if self.path!='/v1/manifest':self.send_error(404);return
        with Handler.lock:Handler.manifests+=1
        content=(ROOT/'neverlauncher-extension.json').read_bytes()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
    def do_POST(self):
        if self.headers.get('Authorization') != 'Bearer '+TOKEN:
            self.send_error(401);return
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
        code=200
        if self.path=='/v1/hello':
            assert data['protocolVersion']=='1.0'
            assert data['extensionId']=='org.example.java-host'
            assert data['instanceId']=='java-host-123'
            assert data['pid']>0
            with Handler.lock:
                Handler.hellos+=1
                Handler.callback=data['callbackUrl']
            result={'protocolVersion':'1.0','extensionApiVersion':'1.0','instanceId':'java-host-123','heartbeatTimeoutSeconds':6,'capabilities':[]}
        elif self.path=='/v1/ready':
            assert data=={'protocolVersion':'1.0','instanceId':'java-host-123'}
            with Handler.lock:Handler.readies+=1
            result={'ready':True}
        elif self.path=='/v1/heartbeat':
            with Handler.lock:Handler.heartbeat+=1
            result={'ok':True}
        else:code=404;result={'error':'unknown'}
        body=json.dumps(result).encode();self.send_response(code)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)

def rpc(method,params=None,token=CALLBACK,version='1.0',deadline=1200):
    assert Handler.callback
    query={'protocolVersion':version,'requestId':'r-'+str(time.monotonic_ns()),'method':method,'params':params or {},'deadlineMs':deadline}
    req=urllib.request.Request(Handler.callback+'/v1/rpc',data=json.dumps(query).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=4) as reply:return reply.status,json.loads(reply.read()),query
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read()),query

def env(server,target):
    settings=os.environ.copy()
    settings.update({
        'NEVERLAUNCHER_EXTENSION_HOST_URL':f'http://127.0.0.1:{server.server_port}',
        'NEVERLAUNCHER_EXTENSION_HOST_TOKEN':TOKEN,
        'NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN':CALLBACK,
        'NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL':'1.0',
        'NEVERLAUNCHER_EXTENSION_API_VERSION':'1.0',
        'NEVERLAUNCHER_EXTENSION_INSTANCE_ID':'java-host-123',
        'NEVERLAUNCHER_EXTENSION_ID':'org.example.java-host',
        'NEVERLAUNCHER_EXTENSION_VERSION':'0.1.0',
        'NEVERLAUNCHER_EXTENSION_SCOPE':'global',
        'NEVERLAUNCHER_EXTENSION_SCOPE_ID':'',
        'NEVERLAUNCHER_EXTENSION_TARGET':target,
    })
    return settings

if __name__=='__main__':
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    jar=STAGE/'backend'/'java-host.jar'
    assert jar.is_file(), 'run build.sh first'
    backend=subprocess.Popen(['java','-jar',str(jar.resolve())],cwd=STAGE,env=env(server,'backend'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        until=time.monotonic()+10
        while time.monotonic()<until and Handler.readies<1 and backend.poll() is None:time.sleep(.05)
        assert backend.poll() is None and Handler.readies==1 and Handler.callback, (backend.poll(),Handler.readies)
        status,body,query=rpc('health')
        assert status==200 and body['requestId']==query['requestId'] and body['protocolVersion']=='1.0' and body['result']=={'state':'RUNNING','responsive':True},body
        status,body,_=rpc('command.invoke',{'command':'echo','payload':{'id':42}})
        assert status==200 and body['result']=={'value':{'echo':{'id':42}}},body
        status,_,_=rpc('health',token='invalid')
        assert status==401
        status,_,_=rpc('health',version='2.0')
        assert status==409
        status,_,_=rpc('command.invoke',{'command':'not-declared'})
        assert status==422
        now=time.monotonic()
        status,_,_=rpc('command.invoke',{'command':'hang'},deadline=200)
        assert status==504 and time.monotonic()-now<2
        status,body,_=rpc('health')
        assert status==200 and body['result']['responsive']
        cli=subprocess.run(['java','-jar',str(jar.resolve()),'status'],cwd=STAGE,env=env(server,'cli'),capture_output=True,text=True,timeout=12)
        assert cli.returncode==0,(cli.returncode,cli.stderr)
        assert json.loads(cli.stdout.strip())=={'extensionId':'org.example.java-host','running':True},cli.stdout
        assert Handler.hellos==2 and Handler.readies==1 and Handler.manifests==2
        print('PASS: executable JVM-host JAR -> authenticated hello -> ready after start -> RPC health/command -> authorization/version/deadline -> CLI')
    finally:
        if backend.poll() is None:backend.send_signal(signal.SIGTERM)
        try:backend.communicate(timeout=6)
        except subprocess.TimeoutExpired:backend.kill();backend.communicate()
        server.shutdown();server.server_close()
