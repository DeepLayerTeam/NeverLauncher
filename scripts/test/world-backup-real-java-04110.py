#!/usr/bin/env python3
"""Executable JVM process + supervised stop + real file bytes + isolated recovery.
This is a Java host integration test, NOT a Minecraft Paper JAR certification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--cli', required=True, type=Path)
args = parser.parse_args()
cli = str(args.cli.resolve())

def run(*cmd, ok=True, timeout=90):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if ok and result.returncode:
        raise AssertionError(f'{cmd}: exit={result.returncode}, stdout={result.stdout}, stderr={result.stderr}')
    return result

with tempfile.TemporaryDirectory(prefix='nl-real-jvm-backup-04110-') as tmp:
    root = Path(tmp)/'server'
    root.mkdir()
    (root/'server.properties').write_text('level-name=world\n')
    (root/'world').mkdir()
    (root/'WorldLifecycle.java').write_text('''
import java.nio.file.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
public class WorldLifecycle {
 public static void main(String[] args) throws Exception {
  Path count=Path.of("jvm-launch-count.txt");
  String old=Files.exists(count)?Files.readString(count):"";
  Files.writeString(count,old+"JVM_STARTED\\n");
  Files.createDirectories(Path.of("world/playerdata"));
  Files.createDirectories(Path.of("world/region"));
  Files.createDirectories(Path.of("plugins/Essentials/userdata"));
  BufferedReader in=new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
  for(String cmd;(cmd=in.readLine())!=null;){
   if(cmd.equals("stop")){
    Files.write(Path.of("world/level.dat"),new byte[]{0x1f,(byte)0x8b,0x08,0,1,2,3});
    Files.write(Path.of("world/region/r.0.0.mca"),new byte[]{0,0,0,2,4,7,9,12});
    Files.write(Path.of("world/playerdata/12345678-1234-1234-1234-123456789abc.dat"),new byte[]{1,2,3,4,5,6,0,(byte)255});
    Files.writeString(Path.of("plugins/Essentials/userdata/12345678-1234-1234-1234-123456789abc.yml"),"balance: 1000\\n");
    break;
   }
  }
 }
}
''')
    run('javac', str(root/'WorldLifecycle.java'))
    run(cli, 'server-bridge', 'host', 'configure', '--server-root', str(root), '--platform', 'paper', '--launch-mode', 'java-main-class', '--main-class', 'WorldLifecycle', '--classpath', str(root), '--restart-policy', 'never')
    store=Path(tmp)/'backup'
    dest=Path(tmp)/'restored'
    # A crashed maintenance process must fail closed, including on first JVM spawn.
    gate=root/'.neverlauncher/server-bridge/host/world-maintenance.gate'
    gate.mkdir()
    denied=run(cli,'server-bridge','host','run','--server-root',str(root),ok=False,timeout=10)
    assert denied.returncode!=0, 'JVM launched through maintenance gate'
    assert not (root/'jvm-launch-count.txt').exists(), 'JVM launched while gate was occupied'
    gate.rmdir()
    host=subprocess.Popen([cli,'server-bridge','host','run','--server-root',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        runtime=root/'.neverlauncher/server-bridge/host/runtime.json'
        for _ in range(120):
            if host.poll() is not None:
                raise AssertionError('Java Host Supervisor exited before backup')
            if runtime.exists():
                state=json.loads(runtime.read_text())
                if state.get('status')=='running' and state.get('processPid',0)>0:
                    break
            time.sleep(0.1)
        else: raise AssertionError('Java JVM did not reach running')
        result=run(cli,'server-bridge','host','world-backup','create','--server-root',str(root),'--backup-root',str(store),'--consistency','stop')
        m=json.loads(result.stdout)['manifest']
        assert m['consistency']=='confirmed-stopped'
        assert host.wait(timeout=12)==0, 'Supervisor did not exit gracefully'
        assert (root/'jvm-launch-count.txt').read_text()=='JVM_STARTED\n', 'unexpected JVM restart'
        bid=m['id']
        run(cli,'server-bridge','host','world-backup','verify','--server-root',str(root),'--backup-root',str(store),'--id',bid)
        run(cli,'server-bridge','host','world-backup','restore','--server-root',str(root),'--backup-root',str(store),'--id',bid,'--destination',str(dest),'--confirm',bid)
        names=['world/level.dat','world/playerdata/12345678-1234-1234-1234-123456789abc.dat','world/region/r.0.0.mca','plugins/Essentials/userdata/12345678-1234-1234-1234-123456789abc.yml']
        for rel in names:
            a=(root/rel).read_bytes()
            b=(dest/rel).read_bytes()
            assert a==b and hashlib.sha256(a).digest()==hashlib.sha256(b).digest(),f'restore mismatch: {rel}'
        assert run(cli,'server-bridge','host','world-backup','restore','--server-root',str(root),'--backup-root',str(store),'--id',bid,'--destination',str(dest),'--confirm',bid,ok=False).returncode!=0
        assert (root/'jvm-launch-count.txt').read_text()=='JVM_STARTED\n', 'restore restarted JVM'
        assert not gate.exists(), 'backup gate not released'
        print('PASS OpenJDK 21 process supervised stop, binary world/player/plugin data, SHA-256 verify and isolated restore; no JVM relaunch')
    finally:
        if host.poll() is None:
            host.terminate()
        try:
            host.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            host.kill();host.communicate()
