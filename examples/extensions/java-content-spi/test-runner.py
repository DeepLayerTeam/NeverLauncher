#!/usr/bin/env python3
"""Реальный цикл java -jar, чтение данных хранилища Host, RPC-контент, CLI и завершение."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
TOKEN = 'content-go-host-0486'
CALLBACK = 'content-callback-0486'

class Handler(http.server.BaseHTTPRequestHandler):
    callback = ''
    ready = 0
    beats = 0
    hellos = 0
    storage = 0
    def log_message(self, *_): pass
    def respond(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN: return self.respond(401,{})
        if self.path != '/v1/manifest': return self.respond(404,{})
        data=(ROOT/'launcher-extension.json').read_bytes()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers();self.wfile.write(data)
    def do_POST(self):
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN: return self.respond(401,{})
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        if self.path=='/v1/hello':
            assert data['extensionId']=='org.example.content-spi'
            Handler.hellos+=1
            Handler.callback=data['callbackUrl']
            return self.respond(200,{'protocolVersion':'1.0','extensionApiVersion':'1.0','instanceId':'content-host-0486','heartbeatTimeoutSeconds':3,'capabilities':['storage.read']})
        if self.path=='/v1/ready':
            Handler.ready+=1
            return self.respond(200,{'ready':True})
        if self.path=='/v1/heartbeat':
            Handler.beats+=1
            return self.respond(200,{'ok':True})
        if self.path=='/v1/capabilities/storage.read':
            assert data=={'projectId':'demo-project','version':'release-1','path':'demo.json'},data
            Handler.storage+=1
            return self.respond(200,{'size':4,'contentBase64':base64.b64encode(b'data').decode()})
        return self.respond(404,{})

def env(port,target='backend'):
    return dict(os.environ, LAUNCHER_EXTENSION_HOST_URL=f'http://127.0.0.1:{port}',
       LAUNCHER_EXTENSION_HOST_TOKEN=TOKEN,LAUNCHER_EXTENSION_CALLBACK_TOKEN=CALLBACK,
       LAUNCHER_EXTENSION_HOST_PROTOCOL='1.0',LAUNCHER_EXTENSION_API_VERSION='1.0',
       LAUNCHER_EXTENSION_INSTANCE_ID='content-host-0486', LAUNCHER_EXTENSION_ID='org.example.content-spi',
       LAUNCHER_EXTENSION_VERSION='0.48.6',LAUNCHER_EXTENSION_TARGET=target,
       LAUNCHER_EXTENSION_SCOPE='project',LAUNCHER_EXTENSION_SCOPE_ID='demo-project')

def rpc(callback, method, params={},token=CALLBACK):
    msg={'protocolVersion':'1.0','requestId':'content-'+str(time.monotonic_ns()),
         'method':method,'deadlineMs':1600,'params':params}
    req=urllib.request.Request(callback+'/v1/rpc',data=json.dumps(msg).encode(),
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=3) as res: return res.status,json.loads(res.read())
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read())

def main():
    jar=ROOT/'build/package/backend/content-spi.jar'
    assert jar.exists(),'run build.sh first'
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    child=subprocess.Popen(['java','-jar',str(jar.resolve())],cwd=ROOT/'build/package',env=env(server.server_port),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+12
        while Handler.ready==0 and child.poll() is None and time.monotonic()<deadline: time.sleep(.05)
        assert child.poll() is None and Handler.ready==1,(child.returncode,child.communicate() if child.poll() is not None else 'not-ready')
        callback=Handler.callback
        status,res=rpc(callback,'content.health')
        assert status==200 and res['result']['available'],(status,res)
        status,res=rpc(callback,'content.source.resolve',{'projectId':'demo-project','path':'demo.json'})
        assert status==200 and res['result']['asset']['sha256']==hashlib.sha256(b'data').hexdigest(),(status,res)
        status,res=rpc(callback,'content.texture.resolve',{'projectId':'demo-project','profileId':'steve','kind':'skin'})
        assert status==200 and res['result']['asset']['path']=='textures/steve/skin.png',(status,res)
        status,res=rpc(callback,'content.metadata.enrich',{'projectId':'demo-project','releaseId':'release-1','metadata':{'projectId':'demo-project','signature':{'algorithm':'Ed25519'}}})
        assert status==200 and res['result']['metadata']['x-content-label']=='sample',(status,res)
        status,res=rpc(callback,'content.package.prepare',{'projectId':'demo-project','name':'small.json','dataBase64':base64.b64encode(b'raw').decode()})
        assert status==200 and res['result']['requiresSigning'] is True and base64.b64decode(res['result']['dataBase64'])==b'raw-processed',(status,res)
        status,res=rpc(callback,'content.delivery.resolve',{'projectId':'demo-project','path':'demo.json'})
        assert status==200 and res['result']['asset']['location']=='storage',(status,res)
        status,_=rpc(callback,'content.source.resolve',{'projectId':'demo-project','path':'demo.json'},token='revoked')
        assert status==401,status
        cli=subprocess.run(['java','-jar',str((ROOT/'build/package/cli/content-spi.jar').resolve()),'content-check'],cwd=ROOT/'build/package',env=env(server.server_port,'cli'),capture_output=True,text=True,timeout=12)
        assert cli.returncode==0,(cli.stderr,cli.stdout)
        payload=json.loads(cli.stdout)
        assert payload['prepared']=='hello-processed' and payload['requiresSigning'] and payload['sourceVerified'],payload
        assert Handler.storage>=1
        deadline=time.monotonic()+6
        while Handler.beats==0 and time.monotonic()<deadline: time.sleep(.05)
        assert Handler.beats>0,'отсутствует аутентифицированное сообщение о работоспособности'
        child.terminate()
        out,err=child.communicate(timeout=8)
        assert child.returncode in (0,143,-15),(out,err,child.returncode)
        print('PASS: запуск java -jar, готовность хоста, выбранный ContentProvider, RPC содержимого и доставки, чтение хранилища с SHA, сигнал активности и штатное завершение')
    finally:
        if child.poll() is None:
            child.kill();child.communicate(timeout=4)
        server.shutdown()

if __name__=='__main__': main()
