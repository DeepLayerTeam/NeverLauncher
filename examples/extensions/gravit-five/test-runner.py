#!/usr/bin/env python3
"""Пять сценариев переноса нативных Java-модулей; настоящий JVM-хост/RPC и управляемый имитатор Go-брокера.
Здесь не сертифицируются подписанные .nlext, настоящий PostgreSQL, учётная запись Minecraft или
публичный выпуск.
"""
import base64, copy, hashlib, hmac, http.server, io, json, os, pathlib, subprocess, tempfile, threading, time, urllib.error, urllib.request, zipfile
ROOT=pathlib.Path(__file__).resolve().parent
MANIFEST=json.loads((ROOT/'launcher-extension.json').read_text())
HOST_TOKEN='five-test-go-broker-secret'
CB_TOKEN='five-test-jvm-secret'
INSTANCE='five-0495-run'
UUID='4201292f-160e-4718-af9f-d91f300e16e6'
SALT=bytes.fromhex('1a'*16)
PW_HASH=hashlib.pbkdf2_hmac('sha256',b'secret-password',SALT,210000).hex()
LIBRARY=b'validated-library-jar'
FILEHASH=hashlib.sha256(LIBRARY).hexdigest()

def once_zip():
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z: z.writestr('profiles/default.json',b'{"loader":"fabric"}')
    return buf.getvalue()

class Broker(http.server.BaseHTTPRequestHandler):
    callback=''; ready=0; beats=0; subs=0
    docs={('config','legacy-identities'):{'bob':{'uuid':UUID,'name':'Bob','scheme':'pbkdf2-sha256','saltHex':SALT.hex(),'hashHex':PW_HASH,'iterations':210000}},
          ('config','legacy-assets'):{'libraries/game.jar':{'projectId':'demo-project','version':'bundle-1','sha256':FILEHASH,'size':len(LIBRARY)},'bundle:demo-project':['libraries/game.jar']},
          ('storage','ported-settings'):{'updates':1}}
    def log_message(self,*args): pass
    def reply(self,status,body):
        payload=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(payload)));self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(payload)
    def do_GET(self):
        if self.headers.get('Authorization')!='Bearer '+HOST_TOKEN:return self.reply(401,{})
        if self.path=='/v1/manifest':return self.reply(200,MANIFEST)
        return self.reply(404,{})
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer '+HOST_TOKEN:return self.reply(401,{})
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        if self.path=='/v1/hello':
            assert data['extensionId']==MANIFEST['id']
            Broker.callback=data['callbackUrl'];return self.reply(200,{'protocolVersion':'1.0','extensionApiVersion':'1.0','instanceId':INSTANCE,'heartbeatTimeoutSeconds':3,'eventProtocolVersion':'1.0',
                'events':['profile.before-save'],'capabilities':['runtime.config.get','runtime.storage.get','runtime.storage.put','storage.read']})
        if self.path=='/v1/heartbeat':
            Broker.beats+=1;return self.reply(200,{'ok':True})
        if self.path=='/v1/ready':
            Broker.ready+=1;return self.reply(200,{'ready':True})
        if self.path=='/v1/events/subscriptions':
            assert data=={'eventType':'profile.before-save','mode':'sync'},data
            Broker.subs+=1;return self.reply(201,{'id':Broker.subs})
        if self.path.startswith('/v1/capabilities/runtime.'):
            _,kind,action=self.path.split('/')[-1].split('.')
            key=(kind,data['key'])
            if action=='get':
                if key not in Broker.docs:return self.reply(404,{'code':'NOT_FOUND'})
                return self.reply(200,{'value':Broker.docs[key]})
            if action=='put' and kind=='storage':
                Broker.docs[key]=data['value'];return self.reply(200,{'ok':True})
        if self.path=='/v1/capabilities/storage.read':
            assert data=={'projectId':'demo-project','version':'bundle-1','path':'libraries/game.jar'},data
            return self.reply(200,{'contentBase64':base64.b64encode(LIBRARY).decode()})
        return self.reply(404,{'code':'NOT_FOUND'})

def rpc(method,params=None,token=CB_TOKEN):
    body={'protocolVersion':'1.0','requestId':'port'+str(time.monotonic_ns()),'deadlineMs':1600,'method':method,'params':params or {}}
    return request('/v1/rpc',body,token)

def request(path,body,token=CB_TOKEN):
    req=urllib.request.Request(Broker.callback+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
    try:
        with urllib.request.urlopen(req,timeout=6) as res:return res.status,json.load(res)
    except urllib.error.HTTPError as e:return e.code,json.load(e)

def hook(loader,version):
    event={'protocolVersion':'1.0','subscription':{'eventType':'profile.before-save','mode':'sync'},'event':{
        'id':'event'+str(time.monotonic_ns()),'type':'profile.before-save','projectId':'demo-project','idempotencyKey':'idem',
        'payload':{'action':'update','profile':{'id':'profile','projectId':'demo-project','loader':loader,'loaderVersion':version,'javaMajor':21}}}}
    return request('/v1/hooks',event)

def run_env(port,target='backend'):
    return dict(os.environ,LAUNCHER_EXTENSION_HOST_URL='http://127.0.0.1:'+str(port),LAUNCHER_EXTENSION_HOST_TOKEN=HOST_TOKEN,
      LAUNCHER_EXTENSION_CALLBACK_TOKEN=CB_TOKEN,LAUNCHER_EXTENSION_HOST_PROTOCOL='1.0',LAUNCHER_EXTENSION_API_VERSION='1.0',
      LAUNCHER_EXTENSION_INSTANCE_ID=INSTANCE,LAUNCHER_EXTENSION_ID=MANIFEST['id'],LAUNCHER_EXTENSION_VERSION='0.49.5',
      LAUNCHER_EXTENSION_TARGET=target,LAUNCHER_EXTENSION_SCOPE='project',LAUNCHER_EXTENSION_SCOPE_ID='demo-project')

def test_game_hook():
    agent=ROOT.parents[2]/'sdk/java/trusted-agent/build/agent.jar'
    jar=ROOT/'build/game-hook.jar'
    game=ROOT/'build/game-fixture.jar'
    with tempfile.TemporaryDirectory() as td:
        conf=pathlib.Path(td)/'agent.properties'
        conf.write_text('main='+base64.b64encode(b'net.minecraft.client.main.Main').decode()+'\ncount=1\nplugin.0='+base64.b64encode(str(jar.resolve()).encode()).decode()+'\nplugin.0.sha256='+hashlib.sha256(jar.read_bytes()).hexdigest()+'\n')
        cmd=['java','-javaagent:'+str(agent.resolve())+'='+str(conf),'-cp',str(agent.resolve())+os.pathsep+str(game.resolve()),'ru.launcher.trusted.MinecraftMain']
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
        assert p.returncode==0 and 'GAME_HOOK_TRANSFORMED' in p.stdout,(p.returncode,p.stdout,p.stderr)
        conf.write_text(conf.read_text().replace(hashlib.sha256(jar.read_bytes()).hexdigest(),'0'*64))
        bad=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
        assert bad.returncode!=0 and 'Контрольная сумма не совпадает' in bad.stderr,(bad.returncode,bad.stderr)

def main():
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Broker)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    jar=ROOT/'build/package/backend/gravit-five.jar'
    child=subprocess.Popen(['java','-jar',str(jar.resolve())],env=run_env(server.server_port),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+14
        while Broker.ready<1 and child.poll() is None and time.monotonic()<deadline:time.sleep(.04)
        assert Broker.ready and child.poll() is None,child.communicate() if child.poll() is not None else 'хост так и не перешёл в состояние готовности'
        status,health=rpc('auth.health');assert status==200 and health['result']['available'],(status,health)
        status,good=rpc('auth.password',{'identifier':'bob','secret':'secret-password'});assert status==200 and good['result']['authentication']['identity']['subject']==UUID,(status,good)
        status,wrong=rpc('auth.password',{'identifier':'bob','secret':'wrong'});assert status==200 and wrong['result']['errorCode']=='invalid_credentials',(status,wrong)
        status, resolved=rpc('auth.resolve',{'subject':UUID});assert status==200 and resolved['result']['identity']['subject']==UUID,(status,resolved)
        Broker.docs['config','legacy-identities']['bob']['scheme']='legacy-unknown'
        try:
            status,bad=rpc('auth.password',{'identifier':'bob','secret':'secret-password'})
            assert status==200 and bad['result']['errorCode']=='unsupported',(status,bad)
        finally:
            Broker.docs['config','legacy-identities']['bob']['scheme']='pbkdf2-sha256'
        print('PASS 1: live Java identity provider verifies PBKDF2, immutable UUID and unsupported-hash denial')
        status,asset=rpc('content.source.resolve',{'projectId':'demo-project','path':'libraries/game.jar'});assert status==200 and asset['result']['asset']['sha256']==FILEHASH,(status,asset)
        status,package=rpc('content.package.prepare',{'projectId':'demo-project','name':'modpack.zip','dataBase64':base64.b64encode(once_zip()).decode()})
        assert status==200 and package['result']['requiresSigning'],(status,package)
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(package['result']['dataBase64']))) as z:
            assert z.read('libraries/game.jar')==LIBRARY and z.read('profiles/default.json')==b'{"loader":"fabric"}'
        status, denied=rpc('content.source.resolve',{'projectId':'other-project','path':'libraries/game.jar'})
        assert status==200 and denied['result']['errorCode']=='content_denied',(status,denied)
        status,invalid=rpc('content.package.prepare',{'projectId':'demo-project','name':'modpack.zip',
            'dataBase64':base64.b64encode(b'not-a-zip').decode()})
        assert status==200 and invalid['result']['errorCode']=='content_unavailable',(status,invalid)
        original=Broker.docs['config','legacy-assets']['libraries/game.jar']['sha256']
        Broker.docs['config','legacy-assets']['libraries/game.jar']['sha256']='0'*64
        try:
            status,denied=rpc('content.package.prepare',{'projectId':'demo-project','name':'modpack.zip',
                'dataBase64':base64.b64encode(once_zip()).decode()})
            assert status==200 and denied['result']['errorCode'] in ('content_unavailable','content_denied'),(status,denied)
        finally:
            Broker.docs['config','legacy-assets']['libraries/game.jar']['sha256']=original
        print('PASS 2: live pre-sign ZIP packaging, integrity enforcement and cross-project denial')
        assert hook('fabric','0.16.0')[0]==200
        assert hook('fabric','')[0]==422
        assert hook('untrusted','x')[0]==422
        print('PASS 3: actual authenticated JVM sync callback permits and vetoes profile before mutation')
        status,denied=rpc('auth.health',token='revoked-token');assert status==401,(status,denied)
        status,migrated=rpc('state.migrate',{'fromVersion':'0.49.4','toVersion':'0.49.5'});assert status==200 and migrated['result']['applied'],(status,migrated)
        assert Broker.docs['storage','ported-settings']['schema']==2
        cli=ROOT/'build/package/cli/gravit-five.jar'
        result=subprocess.run(['java','-jar',str(cli.resolve()),'ported-save'],env=run_env(server.server_port,'cli'),capture_output=True,text=True,timeout=14)
        assert result.returncode==0,(result.stdout,result.stderr)
        assert Broker.docs['storage','ported-settings']['updates']==2
        print('PASS 5: CLI command/registry/config/state migration backed by host storage')
        # Имитируйте документированный откат контрольной точки Go, затем проверьте статус через свежий CLI.
        saved=copy.deepcopy(Broker.docs);Broker.docs['storage','ported-settings']={'updates':1}
        status=subprocess.run(['java','-jar',str(cli.resolve()),'ported-status'],env=run_env(server.server_port,'cli'),capture_output=True,text=True,timeout=14)
        assert status.returncode==0 and json.loads(status.stdout)['config']=={'updates':1},(status.stdout,status.stderr)
        Broker.docs=saved
        test_game_hook()
        print('PASS 4: real premain transforms net.minecraft class in actual JVM; wrong digest fails launch')
        print('LOCAL E2E PASS: five Java source-port behaviors; simulated host, not full production certification')
    finally:
        if child.poll() is None:
            child.terminate()
            try:child.communicate(timeout=8)
            except subprocess.TimeoutExpired:child.kill();child.communicate(timeout=4)
        server.shutdown()
if __name__=='__main__':main()
