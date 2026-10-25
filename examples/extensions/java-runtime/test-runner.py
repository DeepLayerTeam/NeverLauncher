#!/usr/bin/env python3
"""Run TWO actual Java OS processes against an authenticated host, share durable broker state and deliver an event."""
import base64
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.request

ROOT=Path(__file__).resolve().parent
STAGE=ROOT/'build'/'package'
class Handler(http.server.BaseHTTPRequestHandler):
    state={}; callback=None; subscribed=False; hello=0
    lock=threading.Lock()
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer real-host-token':
            self.send_error(401);return
        payload=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
        status=200
        if self.path=='/v1/hello':
            assert payload['protocolVersion']=='1.0' and payload['extensionId']=='org.example.java-runtime'
            assert payload['pid']>0 and payload['instanceId']=='real-instance'
            Handler.hello+=1
            if payload.get('callbackUrl'):Handler.callback=payload['callbackUrl']
            result={'protocolVersion':'1.0','extensionApiVersion':'1.0','instanceId':'real-instance','heartbeatTimeoutSeconds':3,'capabilities':['runtime.config.get','runtime.config.put','runtime.storage.get','runtime.storage.put']}
        elif self.path=='/v1/heartbeat': result={'ok':True}
        elif self.path.startswith('/v1/capabilities/runtime.'):
            kind,verb=self.path.rsplit('/',1)[-1].removeprefix('runtime.').split('.')
            key=(kind,payload['key'])
            with Handler.lock:
                if verb=='get' and key not in Handler.state:status,result=404,{'error':'missing'}
                elif verb=='get':result={'value':Handler.state[key]}
                elif verb=='put':Handler.state[key]=payload['value'];result={'saved':True}
                elif verb=='delete':Handler.state.pop(key,None);result={'deleted':True}
                else:status,result=404,{'error':'unknown'}
        elif self.path=='/v1/events/subscriptions':
            assert payload=={'eventType':'release.published','mode':'async'}
            Handler.subscribed=True;status,result=201,{'id':22}
        else:status,result=404,{'error':'unknown'}
        data=json.dumps(result).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_DELETE(self):
        assert self.headers['Authorization']=='Bearer real-host-token'
        self.send_response(204);self.end_headers()
    def log_message(self,*args):pass

def env(host,target):
    result=dict(os.environ)
    result.update(NEVERLAUNCHER_EXTENSION_HOST_URL=f'http://127.0.0.1:{host.server_port}',NEVERLAUNCHER_EXTENSION_HOST_TOKEN='real-host-token',NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN='real-callback-token',NEVERLAUNCHER_EXTENSION_ID='org.example.java-runtime',NEVERLAUNCHER_EXTENSION_VERSION='0.1.0',NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL='1.0',NEVERLAUNCHER_EXTENSION_API_VERSION='1.0',NEVERLAUNCHER_EXTENSION_INSTANCE_ID='real-instance',NEVERLAUNCHER_EXTENSION_TARGET=target)
    return result

if __name__=='__main__':
    assert (STAGE/'backend/bin/java-runtime').exists(), 'build.sh first'
    host=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=host.serve_forever,daemon=True).start()
    p=subprocess.Popen(['backend/bin/java-runtime'],cwd=STAGE,env=env(host,'backend'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+10
        while time.monotonic()<deadline and not Handler.subscribed and p.poll() is None:time.sleep(.05)
        assert p.poll() is None and Handler.subscribed and Handler.callback, f'backend did not subscribe: {p.poll()}'
        msg={'protocolVersion':'1.0','subscription':{'eventType':'release.published','mode':'async'},'event':{'id':'e1','type':'release.published','payload':{'version':'42.1.0'},'idempotencyKey':'e1'}}
        req=urllib.request.Request(Handler.callback+'/v1/events',data=json.dumps(msg).encode(),headers={'Authorization':'Bearer real-callback-token','Content-Type':'application/json'})
        assert urllib.request.urlopen(req,timeout=3).status==200
        with Handler.lock:assert Handler.state.get(('storage','last-release'))=={'version':'42.1.0'}
        cli=subprocess.run(['cli/bin/java-runtime','status'],cwd=STAGE,env=env(host,'cli'),capture_output=True,text=True,timeout=12)
        assert cli.returncode==0, f'CLI error {cli.stderr} stdout {cli.stdout}'
        data=json.loads(cli.stdout.strip())
        assert data['settings']=={'enabled':True} and data['lastRelease']=={'version':'42.1.0'},data
        assert Handler.hello==2, 'both JVM processes must authenticate with Go-compatible host protocol'
        print('PASS: real Java backend event callback -> broker storage -> separate CLI Java process -> typed command')
    finally:
        if p.poll() is None:p.send_signal(signal.SIGTERM)
        try:p.communicate(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.communicate()
        host.shutdown();host.server_close()
