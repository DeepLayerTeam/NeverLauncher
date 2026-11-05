#!/usr/bin/env python3
"""Запускает настоящие JAR Backend и CLI Java-расширения на аутентифицированном тестовом хосте."""
import http.server
import json
import os
import sys
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parent
TOKEN="java-ui-host-test"
CALLBACK_TOKEN="java-ui-callback-test"
MANIFEST=Path(sys.argv[2]).resolve() if len(sys.argv)>=3 else ROOT/"launcher-extension.json"
EXPECTED=json.loads(MANIFEST.read_text())
class Host(http.server.BaseHTTPRequestHandler):
    callback=None
    ready=0
    settings={}
    def log_message(self,*a):pass
    def send(self,code,payload):
        data=json.dumps(payload).encode();self.send_response(code)
        self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(data)))
        self.end_headers();self.wfile.write(data)
    def do_GET(self):
        if self.headers.get("Authorization")!="Bearer "+TOKEN:return self.send(401,{"error":"forbidden"})
        if self.path!="/v1/manifest":return self.send(404,{"error":"not found"})
        return self.send(200,EXPECTED)
    def do_POST(self):
        if self.headers.get("Authorization")!="Bearer "+TOKEN:return self.send(401,{"error":"forbidden"})
        data=json.loads(self.rfile.read(int(self.headers.get("Content-Length",0))))
        if self.path=="/v1/hello":
            assert data["extensionId"]==EXPECTED["id"]
            Host.callback=data.get("callbackUrl")
            return self.send(200,{"protocolVersion":"1.0","extensionApiVersion":"1.0","instanceId":"java-ui-1","heartbeatTimeoutSeconds":9,
                "capabilities":["runtime.config.get","runtime.config.put"],"events":[]})
        if self.path=="/v1/ready":
            Host.ready+=1;return self.send(200,{"ready":True})
        if self.path=="/v1/heartbeat":return self.send(200,{"ok":True})
        if self.path.startswith("/v1/capabilities/runtime.config."):
            key=data["key"]
            if self.path.endswith(".get"):
                if key not in Host.settings:return self.send(404,{"error":"not found"})
                return self.send(200,{"value":Host.settings[key]})
            if self.path.endswith(".put"):
                Host.settings[key]=data["value"]
                return self.send(200,{"saved":True})
        return self.send(404,{"error":"not found"})

def rpc(method,params,token=CALLBACK_TOKEN):
    query={"protocolVersion":"1.0","requestId":"req-"+str(time.monotonic_ns()),"method":method,"params":params,"deadlineMs":1400}
    request=urllib.request.Request(Host.callback+"/v1/rpc",data=json.dumps(query).encode(),headers={"Authorization":"Bearer "+token})
    try:
        with urllib.request.urlopen(request,timeout=3) as result:return result.status,json.load(result)
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read())

def env(server,target):
    data=os.environ.copy();data.update({"LAUNCHER_EXTENSION_HOST_URL":"http://127.0.0.1:"+str(server.server_port),
        "LAUNCHER_EXTENSION_HOST_TOKEN":TOKEN,"LAUNCHER_EXTENSION_CALLBACK_TOKEN":CALLBACK_TOKEN,
        "LAUNCHER_EXTENSION_HOST_PROTOCOL":"1.0","LAUNCHER_EXTENSION_API_VERSION":"1.0",
        "LAUNCHER_EXTENSION_INSTANCE_ID":"java-ui-1","LAUNCHER_EXTENSION_ID":EXPECTED["id"],
        "LAUNCHER_EXTENSION_VERSION":EXPECTED["version"],"LAUNCHER_EXTENSION_TARGET":target})
    return data

if __name__=="__main__":
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Host)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    jar=Path(sys.argv[1]).resolve() if len(sys.argv)>=2 else ROOT/"build/package/backend/workspace.jar"
    assert jar.is_file(),"run build.sh first"
    proc=subprocess.Popen(["java","-jar",str(jar)],env=env(server,"backend"),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+12
        while time.monotonic()<deadline and Host.ready==0 and proc.poll() is None:time.sleep(.05)
        assert Host.ready==1 and proc.poll() is None,(Host.ready,proc.poll())
        action={"surface":"admin","actionId":"refresh","payload":{},"actor":{"id":"admin-user"}}
        code,answer=rpc("ui.action.invoke",action)
        assert code==200 and answer["result"]["actor"]=="admin-user",(code,answer)
        code,answer=rpc("ui.action.invoke",{"surface":"desktop","actionId":"refresh","payload":{},"actor":{"id":"desktop-user"}})
        assert code==200 and answer["result"]["surface"]=="desktop",(code,answer)
        code,_=rpc("ui.action.invoke",{"surface":"desktop","actionId":"unsigned","payload":{},"actor":{"id":"admin-user"}})
        assert code==422
        code,_=rpc("ui.action.invoke",action,token="invalid")
        assert code==401
        code,answer=rpc("ui.settings.get",{"surface":"admin","key":"appearance"})
        assert code==200 and answer["result"]["value"]=={"theme":"dark"},(code,answer)
        code,answer=rpc("ui.settings.put",{"surface":"admin","key":"appearance","value":{"theme":"light"}})
        assert code==200 and answer["result"]["saved"] and Host.settings["ui.admin.appearance"]=={"theme":"light"}
        code,_=rpc("ui.settings.put",{"surface":"admin","key":"appearance","value":{"theme":"invalid"}})
        assert code==422
        status,body=rpc("health",{})
        assert status==200 and body["result"]["state"]=="RUNNING"
        cli=subprocess.run(["java","-jar",str(jar),"status"],env=env(server,"cli"),capture_output=True,text=True,timeout=15)
        assert cli.returncode==0,(cli.stderr,cli.stdout)
        assert json.loads(cli.stdout)["extension"]==EXPECTED["id"],cli.stdout
        print("PASS: реальный JAR Java, обратные вызовы Admin и Desktop, настройки через брокер хоста, CLI, запрет действий и авторизация")
    finally:
        if proc.poll() is None:proc.send_signal(signal.SIGTERM)
        try:proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:proc.kill();proc.communicate()
        server.shutdown();server.server_close()
