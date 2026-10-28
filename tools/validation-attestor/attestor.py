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
from official_chain_0347 import issue_minecraft_credentials, ExternalOutage, AccountRejected
from component_matrix_0348 import selected_components

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

SCHEMA = 'neverlauncher.validation-evidence.v4'
EVIDENCE_FIELDS = ('schemaVersion', 'runNonce', 'audience', 'purpose', 'targetId', 'targetMatrixSha256', 'signerKeyId', 'packageVersion', 'runId', 'packageId', 'manifestSha256', 'artifactSha256', 'resolvedPlanSha256', 'sourceSha', 'buildSha', 'runnerImageSha256', 'javaSha256', 'javaVersion', 'os', 'arch', 'loader', 'installAdapterSha256', 'guardMode', 'guardPolicySha256', 'serverBridgeSha256', 'serverPluginVersion', 'preset', 'authenticationMode', 'stages', 'artifactHashes', 'startedAt', 'finishedAt', 'issuedAt', 'expiresAt')
DOMAIN = b'NeverLauncher/validation-evidence/v4\x00'
REQUIRED = ('manifest-files','materialization','startup','loader-readiness',
            'authentication','server-readiness','matching-server','gameplay-smoke')
FILES = ('staged-execution.json','verified.json','startup-readiness.json',
         'server-readiness.json','gameplay-smoke.json','authentication.json','runtime-launch.json',
         'runtime-gameplay-launch.json','execution-identity.json','native-adoption.json')
STAGE_ARTIFACT = {'materialization':'verified.json','startup':'startup-readiness.json',
                  'loader-readiness':'startup-readiness.json','authentication':'authentication.json','server-readiness':'server-readiness.json',
                  'matching-server':'gameplay-smoke.json','gameplay-smoke':'gameplay-smoke.json'}
HEX64 = re.compile(r'^[a-f0-9]{64}$')
TOKEN = re.compile(r'^[a-zA-Z0-9_.:/@+,\-]{1,160}$')

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
    native_adoption=read_json(work/'native-adoption.json')
    check(native_adoption.get('status')=='ready' and native_adoption.get('networkDownloads')==0 and
          isinstance(native_adoption.get('importedFiles'),int) and native_adoption['importedFiles']>0 and
          HEX64.fullmatch(native_adoption.get('planSha256','')),
          'native transaction must adopt exact staged bytes without network downloads')
    catalog=signed_manifest.get('componentCatalog')
    if catalog:
        selection=read_json(work/'component-selection.json')
        check(selection['schemaVersion']=='neverlauncher.component-execution.v1' and
              selection['preset']==identity['preset'] and
              selection['catalogDigest']==catalog['digest'], 'selected catalog/preset not bound to run')
        selected_ids,selected_paths=selected_components(signed_manifest,selection['preset'])
        native=read_json(work/'component-verification.json')
        sync=read_json(work/'component-sync.json')
        check(native.get('status')=='ready' and sync==native_adoption and sync.get('status')=='ready',
              'native selected install was not committed and verified')
        check(selection['syncSha256']==sha(work/'component-sync.json') and
              selection['nativeVerifySha256']==sha(work/'component-verification.json'),
              'native component verifier artifacts were tampered')
        observed={f['path'] for f in native.get('files',[]) if f.get('status')=='ok'}
        check(observed<=selected_paths and bool(observed), 'native verifier checked files outside selected preset')
        # For every optional JAR, presence must equal signed membership. A
        # default install leaving unselected mods in mods/ would be a FAIL.
        all_optional={f for c in catalog['components'] for f in c['files']}
        for name in all_optional:
            if name not in selected_paths:
                check(not (work/'client'/name).exists() and not (work/'client'/name).is_symlink(),
                      'unselected optional component remains physically installed: '+name)
        listed=sorted((f['path'],signed_files[f['path']]['sha256']) for f in native['files'] if f['status']=='ok')
        calculated_component_digest=hashlib.sha256(json.dumps({'catalogDigest':catalog['digest'],
            'preset':selection['preset'],'selectedFiles':listed},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        check(selection['resolvedComponentPlanSha256']==calculated_component_digest,
              'signed component resolved plan does not match native verified paths')
        hashes['component-selection.json']=sha(work/'component-selection.json')
        hashes['component-verification.json']=sha(work/'component-verification.json')
        hashes['component-sync.json']=sha(work/'component-sync.json')
        extra={'componentSelection':selection['preset'],
               'componentPlanSha256':selection['resolvedComponentPlanSha256'],
               'componentCatalogDigest':catalog['digest']}
    else:
        check(identity['preset']=='default','unsigned component selection claimed')
        selected_paths={f['path'] for f in signed_manifest['files']}
        extra={}
    for entry in snapshot['files']:
        name=entry['path']
        check(isinstance(name,str) and name and not name.startswith('/') and
              not any(bit in ('.','..','') for bit in name.split('/')) and '\\' not in name,
              'unsafe staged file path')
        check(name in signed_files and entry['sha256']==signed_files[name]['sha256'] and
              entry['size']==signed_files[name]['size'], 'staged file diverges from signed manifest')
        folders=(work/'payload',work/'client') if name in selected_paths else (work/'payload',)
        for folder in folders:
            full=folder/name
            check(full.is_file() and not full.is_symlink() and
                  full.resolve().is_relative_to(folder.resolve()) and
                  full.stat().st_size==entry['size'] and sha(full)==entry['sha256'],
                  'downloaded or installed client bytes are not signed staged bytes: '+name)
    recomputed=hashlib.sha256(json.dumps(dict({'minecraft':signed_manifest.get('minecraft'),
        'runtime':signed_manifest.get('runtime'),
        'fileHashes':sorted((f['path'],f['sha256']) for f in snapshot['files'])},**extra),
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    check(identity['resolvedPlanSha256']==recomputed, 'runtime plan digest not bound to signed staged contents')
    guard=signed_manifest.get('runtime',{}).get('guard',{})
    actual_guard=hashlib.sha256(json.dumps(guard,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    check(identity['guardPolicySha256']==actual_guard and
          identity['guardMode']==str(guard.get('mode') or 'disabled'), 'Guard policy mismatch')
    check(identity['loader']==signed_manifest.get('minecraft',{}).get('loader','vanilla').lower(),
          'loader mismatch against signed manifest')
    check(identity['preset']==(selection['preset'] if catalog else 'default'),
          'actual preset mismatch against signed component selection')
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
    authentication=read_json(work/'authentication.json')
    mode=authentication.get('mode')
    check(mode in ('official','custom') and authentication.get('provider')=='live' and
          authentication.get('status')=='passed' and
          authentication.get('runId')==issued['runId'] and
          authentication.get('manifestSha256')==issued['manifestSha256'] and
          authentication.get('artifactSha256')==issued['artifactSha256'] and
          authentication.get('providerJoin')=='passed' and
          authentication.get('providerHasJoined')=='passed' and
          HEX64.fullmatch(authentication.get('profileSha256','')),
          'real provider authentication missing or mock not accepted')
    if mode=='custom':
        check(authentication.get('replayDenied') is True and
              authentication.get('revokedSessionDenied') is True and
              authentication.get('deviceTrust')=='positive-join-and-live-trust-denial' and
              authentication.get('guardPolicySha256')==identity['guardPolicySha256'],
              'custom Yggdrasil revocation/replay/device policy not verified')
        check(authentication.get('negativeDeviceTrustJoinDenied') is True,
              'device trust policy must reject a real negatively provisioned test session')
        if identity['guardMode']!='disabled':
            check(authentication.get('negativeGuardJoinDenied') is True,
                  'Guard-enabled runtime requires real Guard-specific denial')
    else:
        check(authentication.get('serverOnlineModeRequired') is True and identity['guardMode']=='disabled',
              'official Minecraft requires online-mode and disabled Guard until a live Guard policy proof exists')
    server=read_json(work/'server-readiness.json')
    game=read_json(work/'gameplay-smoke.json')
    props=work/'matching-server'/'server.properties'
    check(props.is_file() and not props.is_symlink(), 'matching server properties missing')
    server_properties=dict(line.split('=',1) for line in props.read_text().splitlines() if '=' in line and not line.startswith('#'))
    expected_online=(mode=='official')
    check(server.get('onlineMode') is expected_online and
          server_properties.get('online-mode')==str(expected_online).lower() and
          server_properties.get('server-ip')=='127.0.0.1',
          'Minecraft server online-mode policy does not match real provider')
    hashes['server.properties']=sha(props)
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
    if mode=='custom':
        check(server['bridgeRequired'], 'custom Yggdrasil matching server must run verified ServerBridge')
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
        'schemaVersion':SCHEMA,'runNonce':issued['nonce'],
        'audience':'neverlauncher-api/validation-evidence/0.34.7',
        'purpose':'staged-package-runtime-verification',
        'targetId':'', 'targetMatrixSha256':issued['targetMatrixSha256'],
        'signerKeyId':'0'*64,'packageVersion':signed_manifest['version'],
        'runId':report['runId'],'packageId':report['packageId'],
        'manifestSha256':report['manifestSha256'],'artifactSha256':report['artifactSha256'],
        'resolvedPlanSha256':identity['resolvedPlanSha256'],'sourceSha':source_sha,
        'buildSha':build_sha,'runnerImageSha256':image_sha,
        'javaSha256':identity['javaSha256'],'javaVersion':java_version,
        'os':'linux','arch':'amd64','loader':identity['loader'],
        'installAdapterSha256':identity['installAdapterSha256'],
        'guardMode':identity['guardMode'],'guardPolicySha256':identity['guardPolicySha256'],
        'serverBridgeSha256':bridge_sha,'serverPluginVersion':game['serverBridgeVersion'] or 'none',
        'preset':identity['preset'],'authenticationMode':mode,'stages':{k:stages[k]['status'] for k in sorted(stages)},
        'artifactHashes':{k:hashes[k] for k in sorted(hashes)},
        'startedAt':report['startedAt'],'finishedAt':report['finishedAt'],
        'issuedAt':issued['issuedAt'], 'expiresAt':(datetime.fromisoformat(issued['issuedAt'].replace('Z','+00:00')) + __import__('datetime').timedelta(hours=24)).isoformat().replace('+00:00','Z')}
    # The target matrix is issued by the Backend, not selected by CI or the
    # worker. Require an EXACT identity match; no wildcard or fallback target.
    fields=('packageVersion','manifestSha256','artifactSha256','resolvedPlanSha256',
            'sourceSha','buildSha','javaSha256','javaVersion','os','arch','loader',
            'installAdapterSha256','guardMode','guardPolicySha256',
            'serverBridgeSha256','serverPluginVersion','preset','authenticationMode')
    applicable=[t for t in issued['requiredTargets'] if all(t.get('version' if k=='packageVersion' else k)==evidence.get(k) for k in fields)]
    check(len(applicable)==1,'no unique configured target matches exact Java/preset/server/build/runtime identity')
    evidence['targetId']=applicable[0]['id']
    check(HEX64.fullmatch(evidence['runNonce']) and HEX64.fullmatch(evidence['targetMatrixSha256']),
          'missing backend issued run nonce or target matrix')
    for val in ('runId','packageId','targetId','packageVersion','javaVersion','os','arch','loader','guardMode','serverPluginVersion','preset','authenticationMode','audience','purpose'):
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
    payload=dict(payload)
    payload['signerKeyId']=hashlib.sha256(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).hexdigest()
    payload={key:payload[key] for key in EVIDENCE_FIELDS}
    # The byte order of the following dictionary is the Go struct field order.
    return {'evidence':payload,'signature':base64.urlsafe_b64encode(private.sign(DOMAIN+canonical(payload))).decode().rstrip('=')}

def execute_run(cfg,package_id,selection=None,issued_grant=None):
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
    grant=issued_grant if issued_grant is not None else request_json(cfg.backend,'/api/v1/packages/'+package_id+'/staged-runs',cfg.operator_token,{})
    check(grant['packageId']==package_id and grant['attested'] is False,'backend issued wrong staged snapshot')
    with tempfile.TemporaryDirectory(prefix='neverlauncher-attestor-') as tmp:
        root=Path(tmp)
        inp=root/'input';out=root/'output';inp.mkdir(mode=0o700);out.mkdir(mode=0o700)
        grant_path=inp/'grant.json';grant_path.write_text(json.dumps(grant),encoding='utf-8');grant_path.chmod(0o600)
        official_credentials = inp/'official-credentials.json'
        if cfg.auth_mode=='official':
            check(cfg.official_client_id and cfg.official_refresh_token_file,
                  'official provider requires authorized test account and host-only refresh token')
            issue_minecraft_credentials(cfg.official_client_id,cfg.official_refresh_token_file,official_credentials)
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
        check(cfg.auth_mode in ('official','custom'), 'live V07 provider mode must be explicit')
        def mount_identity(hostfile,inside,argument,required):
            if not hostfile:
                check(not required,'required live test identity unavailable')
                return
            supplied=Path(hostfile)
            check(not supplied.is_symlink(), 'symlink credential file not allowed')
            path=supplied.resolve(strict=True)
            stat=path.stat()
            check(path.is_file() and not path.is_symlink() and
                  stat.st_mode & 0o077 == 0 and stat.st_size <= 16384,
                  'test-account credential file must be a regular owner-only file')
            # Mounted directly, never copied into generic work/output artifacts.
            args[args.index(cfg.image):args.index(cfg.image)] = [
                '--mount',f'type=bind,src={path},dst={inside},readonly']
            args.extend([argument,inside])
        if selection is not None:
            check(selection['authenticationMode']==cfg.auth_mode and
                  selection['preset'] in {target['preset'] for target in grant['requiredTargets']},
                  'target not permitted by backend-issued runtime matrix')
            args.extend(['--preset',selection['preset']])
        args.extend(['--auth-mode',cfg.auth_mode])
        mount_identity(str(official_credentials) if cfg.auth_mode=='official' else cfg.credentials_file,
                       '/run/auth/credentials.json','--credentials-file',True)
        mount_identity(cfg.negative_credentials_file,'/run/auth/negative.json','--negative-credentials-file',cfg.auth_mode=='custom')
        mount_identity(cfg.guard_denied_credentials_file,'/run/auth/guard-denied.json',
                       '--guard-denied-credentials-file',cfg.auth_mode=='custom')
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
        check(payload['authenticationMode']==cfg.auth_mode,
              'worker returned a different real authentication provider than the host selected')
        if selection is not None:
            check(payload['targetId']==selection['id'] and payload['preset']==selection['preset'],
                  'worker executed a different runtime matrix target')
        signed=sign_evidence(payload,cfg.signing_key)
        # No signature is ever exposed to an OCI container or a user-supplied
        # report. Only the backend receives signed evidence via scoped API.
        result=request_json(cfg.backend,'/api/v1/packages/'+package_id+'/validation-attestations',
                            cfg.operator_token,signed)
        return {'runId':grant['runId'],'attestationVerified':result['attestationVerified'],
                'stablePublishEligible':False}

def execute_matrix(cfg, package_id):
    """Execute every required target on its OWN fresh staged grant and OCI job.

    A failed case remains failed. A passing default cannot be substituted for a
    missing preset. Unsupported OS/arch targets remain incomplete until a
    real matching worker executes them; no synthetic pass is emitted.
    """
    initial=request_json(cfg.backend,'/api/v1/packages/'+package_id+'/staged-runs',cfg.operator_token,{})
    targets=initial.get('requiredTargets',[])
    check(bool(targets) and len(targets)<=128,'backend did not provide required runtime targets')
    outcomes=[]
    seen=set()
    for index,target in enumerate(targets):
        ident=target['id']
        check(ident not in seen,'duplicate required target ID')
        seen.add(ident)
        if target['os']!='linux' or target['arch'] not in ('amd64','x86_64'):
            outcomes.append({'targetId':ident,'preset':target['preset'],'status':'blocked',
                             'detail':'target needs an independent matching OS/arch trusted runner'})
            continue
        if target['authenticationMode']!=cfg.auth_mode:
            outcomes.append({'targetId':ident,'preset':target['preset'],'status':'blocked',
                             'detail':'target needs its own live authentication provider runner'})
            continue
        try:
            # A separate grant/challenge/workdir prevents one successful run
            # from being replayed for two target IDs or two different presets.
            grant=initial if index==0 else request_json(
                cfg.backend,'/api/v1/packages/'+package_id+'/staged-runs',cfg.operator_token,{})
            check(grant['targetMatrixSha256']==initial['targetMatrixSha256'],
                  'required matrix changed while running; restart entire matrix')
            result=execute_run(cfg,package_id,target,grant)
            outcomes.append({'targetId':ident,'preset':target['preset'],'status':'passed',
                             'runId':result['runId']})
        except Exception as exc:
            outcomes.append({'targetId':ident,'preset':target['preset'],'status':'failed',
                             'detail':str(exc)[:512]})
    return {'packageId':package_id,'targetMatrixSha256':initial['targetMatrixSha256'],
            'allRequiredTargetsVerified':all(x['status']=='passed' for x in outcomes),
            'targets':outcomes,'stablePublishEligible':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',required=True)
    p.add_argument('--operator-token-file',required=True,help='0600 host-only credential file; never enters worker')
    p.add_argument('--signing-key',required=True,help='Host-only Ed25519 PKCS8 PEM, permission 0600')
    p.add_argument('--image',required=True,help='Trusted fully pinned image name@sha256:...')
    p.add_argument('--auth-mode',choices=('official','custom'),required=True)
    p.add_argument('--credentials-file',default='',help='Custom-Yggdrasil test-session JSON only')
    p.add_argument('--official-client-id',default='',help='Dedicated Microsoft public-client app ID')
    p.add_argument('--official-refresh-token-file',default='',help='Host-only authorized test account refresh token, 0600')
    p.add_argument('--negative-credentials-file',default='',help='Separate live session for custom revocation')
    p.add_argument('--guard-denied-credentials-file',default='',help='Real live policy-denied session')
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
        outcome=execute_matrix(cfg,cfg.package_id)
        print(json.dumps(outcome))
        if not outcome['allRequiredTargetsVerified']: raise RuntimeError('runtime matrix incomplete')
        return
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
                try: result=execute_matrix(cfg,body['packageId'])
                finally:lock.release()
                raw=json.dumps(result).encode();self.send_response(201 if result['allRequiredTargetsVerified'] else 409)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            except ExternalOutage:
                self.send_error(503,'inconclusive: external official provider unavailable')
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
