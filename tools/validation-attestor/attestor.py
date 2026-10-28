#!/usr/bin/env python3
"""Independent host-side V04/V06 attestor. NEVER execute inside the worker.

An operator-controlled, non-root host invokes ONLY the pre-approved OCI image
by digest. The Ed25519 private key stays in this host process, never in OCI,
CI, Docker environment, network or mounted volumes. Only verified on-disk
observations from this execution are signed, not uploaded JSON from callers.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import urllib.request
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SCHEMA = 'neverlauncher.validation-evidence.v2'
DOMAIN = b'NeverLauncher/validation-evidence/v2\x00'
REQUIRED = ('manifest-files','materialization','startup','loader-readiness',
            'server-readiness','matching-server','gameplay-smoke')
FILES = ('staged-execution.json','verified.json','startup-readiness.json',
         'server-readiness.json','gameplay-smoke.json','runtime-launch.json',
         'runtime-gameplay-launch.json','execution-identity.json')
STAGE_ARTIFACT = {'materialization':'verified.json','startup':'startup-readiness.json',
                  'loader-readiness':'startup-readiness.json','server-readiness':'server-readiness.json',
                  'matching-server':'gameplay-smoke.json','gameplay-smoke':'gameplay-smoke.json'}
HEX64 = re.compile(r'^[a-f0-9]{64}$')
TOKEN = re.compile(r'^[a-zA-Z0-9_.:/@+\-]{1,160}$')

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''): h.update(part)
    return h.hexdigest()

def read_json(p,limit=4*1024*1024):
    if not p.is_file() or p.is_symlink() or p.stat().st_size>limit: raise ValueError('missing/oversized evidence: '+p.name)
    return json.loads(p.read_text(encoding='utf-8'))

def check(expr, message):
    if not expr: raise ValueError(message)

def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',',':')).encode('utf-8')

def verify_local_artifacts(work, issued, image_sha, source_sha, build_sha, bridge_sha):
    """Only run after a trusted, pinned OCI container has exited successfully."""
    report=read_json(work/'staged-execution.json')
    check(report['schemaVersion']=='neverlauncher.staged-runtime-run.v1','wrong execution report schema')
    for k in ('runId','packageId','manifestSha256','artifactSha256'):
        check(report[k]==issued[k], 'staged grant/report mismatch: '+k)
    stages=report['stages']
    check(set(stages)==set(REQUIRED), 'staged execution is incomplete or contains unrecognized stages')
    for name in REQUIRED:
        check(stages[name]['status']=='passed','unverified runtime stage: '+name)
    hashes={name:sha(work/name) for name in FILES}
    for stage,name in STAGE_ARTIFACT.items():
        check(stages[stage].get('evidenceSha256')==hashes[name], 'stage evidence does not match raw artifact: '+stage)
    identity=read_json(work/'execution-identity.json')
    check(HEX64.fullmatch(identity['javaSha256']) and HEX64.fullmatch(identity['neverRuntimeSha256']) and
          HEX64.fullmatch(identity['cliSha256']), 'unbound Java or binary hashes')
    check(hashlib.sha256((identity['cliSha256']+identity['neverRuntimeSha256']).encode()).hexdigest()==
          identity['installAdapterSha256'], 'install adapter binary identity inconsistent')
    check(HEX64.fullmatch(identity['resolvedPlanSha256']) and HEX64.fullmatch(identity['guardPolicySha256']),
          'unbound runtime plan or guard policy')
    # Independently verify the exact staged downloads AND the actual installed
    # bytes. A report saying "valid" cannot compensate for a modified game jar.
    snapshot=read_json(work/'payload'/'staged-package-description.json')
    signed_manifest=read_json(work/'payload'/'signed-release-manifest.json')
    check(snapshot['packageId']==issued['packageId'] and
          signed_manifest['projectId']==snapshot['projectId'] and
          signed_manifest['version']==snapshot['version'], 'materialized release identity mismatch')
    signed_files={f['path']:f for f in signed_manifest['files']}
    check(len(signed_files)==len(snapshot['files']) and bool(signed_files), 'missing or duplicated signed staged files')
    for entry in snapshot['files']:
        name=entry['path']
        check(isinstance(name,str) and name and not name.startswith('/') and
              not any(bit in ('.','..','') for bit in name.split('/')) and '\\' not in name,
              'unsafe staged file path')
        check(name in signed_files and entry['sha256']==signed_files[name]['sha256'] and
              entry['size']==signed_files[name]['size'], 'staged file diverges from signed manifest')
        for folder in (work/'payload',work/'client'):
            full=folder/name
            check(full.is_file() and not full.is_symlink() and
                  full.resolve().is_relative_to(folder.resolve()) and
                  full.stat().st_size==entry['size'] and sha(full)==entry['sha256'],
                  'downloaded or installed client bytes are not signed staged bytes: '+name)
    recomputed=hashlib.sha256(json.dumps({'minecraft':signed_manifest.get('minecraft'),
        'runtime':signed_manifest.get('runtime'),
        'fileHashes':sorted((f['path'],f['sha256']) for f in snapshot['files'])},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    check(identity['resolvedPlanSha256']==recomputed, 'runtime plan digest not bound to signed staged contents')
    guard=signed_manifest.get('runtime',{}).get('guard',{})
    actual_guard=hashlib.sha256(json.dumps(guard,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    check(identity['guardPolicySha256']==actual_guard and
          identity['guardMode']==str(guard.get('mode') or 'disabled'), 'Guard policy mismatch')
    check(identity['loader']==signed_manifest.get('minecraft',{}).get('loader','vanilla').lower(),
          'loader mismatch against signed manifest')
    check(identity['preset']==str(signed_manifest.get('optionalPreset') or 'default'),
          'preset mismatch against signed manifest')
    install=read_json(work/'verified.json')
    check(install['status']=='valid','client verify did not pass')
    startup=read_json(work/'startup-readiness.json')
    check(startup['schemaVersion']=='neverlauncher.startup-readiness.v1' and
          startup['windowPid'] is not None and not startup.get('failure') and not startup.get('blocked'),
          'GUI readiness not positively established')
    samples=startup.get('samples',[])
    check(len(samples)==2 and samples[0]['sha256']!=samples[1]['sha256'],'two distinct rendered menu frames missing')
    for i,sample in enumerate(samples,1):
        f=work/'startup-diagnostics'/f'menu-frame-{i}.png'
        check(f.is_file() and not f.is_symlink() and sha(f)==sample['sha256'] and
              len(sample['menuControls'])>=2 and sample['pid']==startup['windowPid'] and
              sample['width']>=640 and sample['height']>=400, 'menu frame not bound to Java window')
        hashes['menu-frame-'+str(i)+'.png']=sha(f)
    server=read_json(work/'server-readiness.json')
    game=read_json(work/'gameplay-smoke.json')
    check(server['runId']==issued['runId'] and game['runId']==issued['runId'], 'gameplay/server run ID mismatch')
    check(server['startup']=='passed' and server['minecraftVersion']==game['minecraftVersion'] and
          server['loader']==game['loader'] and server['loaderVersion']==game['loaderVersion'],
          'server/plugin/runtime version mismatch')
    check(game['status']=='passed' and game['serverJoinAndOnline'] is True and
          game['clientConnectionLogObserved'] is True and game['clientInputSent'] is True and
          game['windowJavaProcessId'] is not None and not game['failure'], 'gameplay not positively confirmed')
    before,after=game['positionBefore'],game['positionAfter']
    check(len(before)==3 and len(after)==3 and any(abs(float(a)-float(b))>0.001 for a,b in zip(before,after)) and
          int(game['ticksAfter'])>int(game['ticksBefore']), 'no server-confirmed movement or game ticks')
    check(game['frameBeforeSha256']!=game['frameAfterSha256'] and
          all(HEX64.fullmatch(game[k]) for k in ('frameBeforeSha256','frameAfterSha256')),
          'rendered gameplay frames did not change')
    for filename,key in (('world-before.png','frameBeforeSha256'),('world-after.png','frameAfterSha256')):
        frame=work/'gameplay-diagnostics'/filename
        check(frame.is_file() and not frame.is_symlink() and sha(frame)==game[key],
              'gameplay screenshot not present or wrong digest')
        hashes[filename]=sha(frame)
    check(identity['loader']==server['loader'] and TOKEN.fullmatch(identity['preset']) and
          TOKEN.fullmatch(identity['guardMode']), 'signed loader/preset/guard mismatch')
    check(HEX64.fullmatch(bridge_sha), 'bridge digest must be pinned (zero digest for Vanilla)')
    if server['bridgeRequired']:
        check(bridge_sha!='0'*64 and server['bridgeRequired'] and game['serverBridgeVersion'],
              'ServerBridge required but unverified')
    else:
        check(bridge_sha=='0'*64,'Vanilla without bridge cannot claim a bridge binary')
    java_version=identity['javaVersionRaw'].splitlines()[0].strip()
    match=re.search(r'(?:version\s+)?["\']?([0-9]+(?:\.[0-9]+){0,3})',java_version)
    check(bool(match),'Java version not verified')
    java_version=match.group(1)
    image_sha=image_sha.lower()
    check(HEX64.fullmatch(image_sha) and HEX64.fullmatch(build_sha) and
          bool(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}',source_sha)),'untrusted host build provenance')
    started=datetime.fromisoformat(report['startedAt'].replace('Z','+00:00'))
    finished=datetime.fromisoformat(report['finishedAt'].replace('Z','+00:00'))
    check(started<=finished and (finished-started).total_seconds()<4*3600 and
          finished<=datetime.now(timezone.utc), 'invalid execution time bounds')
    # IMPORTANT: order must match Go validationPayload0345 field order.
    evidence={
        'schemaVersion':SCHEMA,'runId':report['runId'],'packageId':report['packageId'],
        'manifestSha256':report['manifestSha256'],'artifactSha256':report['artifactSha256'],
        'resolvedPlanSha256':identity['resolvedPlanSha256'],'sourceSha':source_sha,
        'buildSha':build_sha,'runnerImageSha256':image_sha,
        'javaSha256':identity['javaSha256'],'javaVersion':java_version,
        'os':'linux','arch':'amd64','loader':identity['loader'],
        'installAdapterSha256':identity['installAdapterSha256'],
        'guardMode':identity['guardMode'],'guardPolicySha256':identity['guardPolicySha256'],
        'serverBridgeSha256':bridge_sha,'serverPluginVersion':game['serverBridgeVersion'] or 'none',
        'preset':identity['preset'],'stages':{k:stages[k]['status'] for k in sorted(stages)},
        'artifactHashes':{k:hashes[k] for k in sorted(hashes)},
        'startedAt':report['startedAt'],'finishedAt':report['finishedAt']}
    for val in ('runId','packageId','javaVersion','os','arch','loader','guardMode','serverPluginVersion','preset'):
        check(TOKEN.fullmatch(evidence[val]),'unsafe/noncanonical signed value: '+val)
    return evidence

def request_json(base,path,token,body):
    u=base.rstrip('/')+path
    req=urllib.request.Request(u,data=json.dumps(body).encode(),headers={
        'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=60) as res:
        check(res.status==201,'backend refused validation operation')
        return json.load(res)['data']

def sign_evidence(payload,key_path):
    p=Path(key_path)
    check(p.stat().st_mode & 0o077 == 0,'attestation private key must be owner-only')
    private=load_pem_private_key(p.read_bytes(),password=None)
    check(isinstance(private,Ed25519PrivateKey),'Ed25519 attestation key required')
    return {'evidence':payload,'signature':base64.urlsafe_b64encode(private.sign(DOMAIN+canonical(payload))).decode().rstrip('=')}

def execute_run(cfg,package_id):
    check(re.fullmatch(r'[A-Za-z0-9_\-]{1,128}',package_id),'invalid package identifier')
    check(platform.system()=='Linux' and platform.machine() in ('x86_64','AMD64'),
          'this pinned runner is limited to Linux amd64; other targets require their own build')
    check(cfg.backend.startswith('https://'),'attestor requires HTTPS backend')
    check('@sha256:' in cfg.image and HEX64.fullmatch(cfg.image.rsplit('@sha256:',1)[1]),
          'runner image must be pinned with an OCI digest')
    image_sha=cfg.image.rsplit('@sha256:',1)[1]
    check(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}',cfg.source_sha),'source commit must be pinned')
    check(HEX64.fullmatch(cfg.build_sha),'trusted build SHA-256 must be pinned')
    check(HEX64.fullmatch(cfg.manifest_key),'signed staged manifest key must be pinned')
    # Pull/inspect the digest-identified image on the trusted host. Image labels
    # are immutable under the pinned digest, so arbitrary host-provided source
    # and build identifiers cannot be silently presented as observed provenance.
    subprocess.run([cfg.engine,'pull','--quiet',cfg.image],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=600)
    inspected=subprocess.run([cfg.engine,'image','inspect','--format','{{json .Labels}}',cfg.image],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
    labels=json.loads(inspected.stdout)
    check(labels.get('org.opencontainers.image.revision')==cfg.source_sha and
          labels.get('io.neverlauncher.validation.build-sha256')==cfg.build_sha,
          'pinned image build provenance labels do not match operator-approved release')
    # Do not accept a user-chosen executable, runtime, image, Docker flags or signing key.
    grant=request_json(cfg.backend,'/api/v1/packages/'+package_id+'/staged-runs',cfg.operator_token,{})
    check(grant['packageId']==package_id and grant['attested'] is False,'backend issued wrong staged snapshot')
    with tempfile.TemporaryDirectory(prefix='neverlauncher-attestor-') as tmp:
        root=Path(tmp)
        inp=root/'input';out=root/'output';inp.mkdir(mode=0o700);out.mkdir(mode=0o700)
        grant_path=inp/'grant.json';grant_path.write_text(json.dumps(grant),encoding='utf-8');grant_path.chmod(0o600)
        if cfg.server_bundle_file:
            check(cfg.server_sha and HEX64.fullmatch(cfg.server_sha) and sha(cfg.server_bundle_file)==cfg.server_sha,
                  'server bundle digest does not match operator pin')
        job_network='nlval-'+grant['runId'][:24]
        check(os.getuid()!=0,'attestation service MUST run as unprivileged account')
        subprocess.run([cfg.engine,'network','create',job_network],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
        # Never mount production data, Docker socket, runner source checkout,
        # admin token or signing key. Each job gets a fresh network namespace,
        # root filesystem readonly, all Linux capabilities dropped and bounded resources.
        name='nl-validation-'+grant['runId'][:24]
        args=[cfg.engine,'run','--rm','--name',name,'--init','--read-only',
              '--userns=keep-id','--platform','linux/amd64',
              '--security-opt','no-new-privileges','--cap-drop=ALL',
              '--pids-limit=256','--memory=6g','--cpus=4',
              '--network',job_network,'--user',f'{os.getuid()}:{os.getgid()}',
              '--tmpfs','/tmp:rw,nosuid,nodev,size=2g',
              '--mount',f'type=bind,src={inp},dst=/run/staged,readonly',
              '--mount',f'type=bind,src={out},dst=/work',
              cfg.image,
              '--backend',cfg.backend,'--grant-file','/run/staged/grant.json',
              '--package-id',package_id,'--output','/work',
              '--cli','/opt/neverlauncher','--runtime','/opt/neverruntime',
              '--java','auto','--pinned-public-key',cfg.manifest_key,
              '--runtime-seconds',str(cfg.runtime_seconds)]
        if cfg.server_bundle_file:
            args[args.index(cfg.image):args.index(cfg.image)]=['--mount',
                f'type=bind,src={Path(cfg.server_bundle_file).resolve()},dst=/run/server/bundle.zip,readonly']
            args += ['--server-bundle','/run/server/bundle.zip','--server-sha256',cfg.server_sha,
                     '--server-entry',cfg.server_entry,'--bridge-path',cfg.bridge_path,
                     '--bridge-sha256',cfg.bridge_sha,'--bridge-version',cfg.bridge_version]
        worker_log=root/'worker-redacted-pending.log'
        try:
            with open(worker_log,'wb') as log:
                proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=log,
                                    stderr=subprocess.STDOUT,timeout=7200,check=False)
        except subprocess.TimeoutExpired:
            subprocess.run([cfg.engine,'rm','-f',name],stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,timeout=20,check=False)
            raise
        finally:
            subprocess.run([cfg.engine,'network','rm',job_network],stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,timeout=30,check=False)
        # Do not surface raw JVM logs in API responses; they can contain
        # credentials or personal information. Retention/redaction is V12.
        check(proc.returncode==0,'pinned worker failed; no trusted evidence emitted')
        payload=verify_local_artifacts(out,grant,image_sha,cfg.source_sha,cfg.build_sha,cfg.bridge_sha)
        signed=sign_evidence(payload,cfg.signing_key)
        # No signature is ever exposed to an OCI container or a user-supplied
        # report. Only the backend receives signed evidence via scoped API.
        result=request_json(cfg.backend,'/api/v1/packages/'+package_id+'/validation-attestations',
                            cfg.operator_token,signed)
        return {'runId':grant['runId'],'attestationVerified':result['attestationVerified'],
                'stablePublishEligible':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',required=True)
    p.add_argument('--operator-token-file',required=True,help='0600 host-only credential file; never enters worker')
    p.add_argument('--signing-key',required=True,help='Host-only Ed25519 PKCS8 PEM, permission 0600')
    p.add_argument('--image',required=True,help='Trusted fully pinned image name@sha256:...')
    p.add_argument('--server-bundle-file',default='',help='Host-pinned complete matching server ZIP')
    p.add_argument('--server-sha',default='')
    p.add_argument('--server-entry',default='')
    p.add_argument('--bridge-path',default='')
    p.add_argument('--bridge-version',default='')
    p.add_argument('--source-sha',required=True)
    p.add_argument('--build-sha',required=True)
    p.add_argument('--manifest-key',required=True)
    p.add_argument('--bridge-sha',default='0'*64)
    p.add_argument('--runtime-seconds',type=int,default=180)
    p.add_argument('--engine',choices=('podman',),default='podman')
    p.add_argument('--package-id',help='One-shot attestation; omit for the mTLS service')
    p.add_argument('--listen',default='127.0.0.1:8845')
    p.add_argument('--tls-cert',default='')
    p.add_argument('--tls-key',default='')
    p.add_argument('--client-ca',default='')
    cfg=p.parse_args()
    token_path=Path(cfg.operator_token_file)
    check(token_path.stat().st_mode & 0o077==0,'host operator credential must be owner-only')
    cfg.operator_token=token_path.read_text(encoding='utf-8').strip()
    check(bool(cfg.operator_token),'missing host operator credential')
    check(15<=cfg.runtime_seconds<=3600,'invalid runtime deadline')
    # A rootful Docker daemon makes its client effectively root on the host,
    # including access to the signing key. Refuse it unconditionally.
    info=subprocess.run(['podman','info','--format','{{.Host.Security.Rootless}}'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
    check(info.returncode==0 and info.stdout.strip()==b'true',
          'host-side attestor requires configured rootless Podman')
    if cfg.package_id:
        print(json.dumps(execute_run(cfg,cfg.package_id)));return
    check(cfg.tls_cert and cfg.tls_key and cfg.client_ca,'service requires mTLS server+client certificates')
    lock=threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path!='/v1/attest' or int(self.headers.get('Content-Length','0'))>512:
                self.send_error(404);return
            try:
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                check(set(body)=={'packageId'},'only packageId is accepted')
                if not lock.acquire(blocking=False): self.send_error(429,'attestor busy');return
                try: result=execute_run(cfg,body['packageId'])
                finally:lock.release()
                raw=json.dumps(result).encode();self.send_response(201)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            except Exception as exc:
                self.send_error(409,str(exc)[:160])
        def log_message(self,*args):pass
    ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,cafile=cfg.client_ca)
    ctx.load_cert_chain(cfg.tls_cert,cfg.tls_key)
    ctx.verify_mode=ssl.CERT_REQUIRED
    host,port=cfg.listen.rsplit(':',1)
    server=ThreadingHTTPServer((host,int(port)),Handler)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    server.serve_forever()

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('attestor error:',str(e),file=sys.stderr);sys.exit(1)
