import importlib.util
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

spec=importlib.util.spec_from_file_location('attestor',Path(__file__).with_name('attestor.py'))
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def dump(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data),encoding='utf-8')

def fixture(work):
    package='package-abc'; run='9'*48; b='b'*64; m='a'*64
    data=b'valid staged jar bytes'
    artifact={'path':'mods/example.jar','size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    signed={'projectId':'project','version':'1.0.0','minecraft':{'loader':'vanilla','version':'1.21.1'},
            'runtime':{'guard':{}},'files':[artifact]}
    pkg={'projectId':'project','packageId':package,'version':'1.0.0','files':[artifact]}
    dump(work/'payload'/'signed-release-manifest.json',signed)
    dump(work/'payload'/'staged-package-description.json',pkg)
    for folder in ('payload','client'):
        p=work/folder/artifact['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    dump(work/'verified.json',{'status':'valid'})
    dump(work/'native-adoption.json',{'status':'ready','networkDownloads':0,'importedFiles':1,'planSha256':'0'*64})
    for i in (1,2):
        p=work/'startup-diagnostics'/f'menu-frame-{i}.png'
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(bytes([i])*4096)
    samples=[{'sha256':a.sha(work/'startup-diagnostics'/f'menu-frame-{i}.png'),
              'menuControls':['multiplayer','singleplayer'],'pid':123,'width':1280,'height':720} for i in (1,2)]
    dump(work/'startup-readiness.json',{'schemaVersion':'neverlauncher.startup-readiness.v1',
        'windowPid':123,'failure':None,'blocked':None,'samples':samples})
    for fname,bb in [('world-before.png',b'a'),('world-after.png',b'b')]:
        pp=work/'gameplay-diagnostics'/fname;pp.parent.mkdir(parents=True,exist_ok=True);pp.write_bytes(bb*4096)
    dump(work/'server-readiness.json',{'runId':run,'minecraftVersion':'1.21.1','loader':'vanilla',
         'loaderVersion':'','bridgeRequired':False,'onlineMode':True,'startup':'passed'})
    (work/'matching-server').mkdir(parents=True,exist_ok=True)
    (work/'matching-server'/'server.properties').write_text('server-ip=127.0.0.1\nonline-mode=true\n')
    dump(work/'gameplay-smoke.json',{'runId':run,'minecraftVersion':'1.21.1','loader':'vanilla',
         'loaderVersion':'','serverBridgeVersion':'','status':'passed','failure':'',
         'serverJoinAndOnline':True,'clientConnectionLogObserved':True,'clientInputSent':True,
         'windowJavaProcessId':123,'positionBefore':[0,65,0],'positionAfter':[1,65,0],
         'ticksBefore':100,'ticksAfter':110,
         'frameBeforeSha256':a.sha(work/'gameplay-diagnostics'/'world-before.png'),
         'frameAfterSha256':a.sha(work/'gameplay-diagnostics'/'world-after.png')})
    dump(work/'authentication.json', {'mode':'official','provider':'live','status':'passed',
         'runId':run,'manifestSha256':m,'artifactSha256':b,
         'providerJoin':'passed','providerHasJoined':'passed','profileSha256':'f'*64,
         'serverOnlineModeRequired':True})
    for fname in ('runtime-launch.json','runtime-gameplay-launch.json'):
        dump(work/fname,{'success':True,'timed_out':True})
    resolution=hashlib.sha256(json.dumps({'minecraft':signed['minecraft'],
        'runtime':signed['runtime'],'fileHashes':[(artifact['path'],artifact['sha256'])]},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    cli='1'*64;rt='2'*64
    dump(work/'execution-identity.json',{'javaSha256':'3'*64,'javaVersionRaw':'openjdk version "21.0.7"',
        'neverRuntimeSha256':rt,'cliSha256':cli,
        'installAdapterSha256':hashlib.sha256((cli+rt).encode()).hexdigest(),
        'resolvedPlanSha256':resolution,'guardPolicySha256':hashlib.sha256(b'{}').hexdigest(),
        'guardMode':'disabled','loader':'vanilla','preset':'default'})
    # V09 fixture: independently verifiable previous package and recorded CLI
    # transaction outputs. Real updater coverage is exercised in the CLI tests.
    prev={'packageId':'prev-package','version':'0.9.0','projectId':'project',
          'profileId':'profile','files':[artifact]}
    previous_signed={'version':'0.9.0','signature':{'publicKey':'a'*64},'files':[artifact]}
    signed['signature']={'publicKey':'a'*64}
    pkg.update({'packageId':package,'profileId':'profile'})
    signed['profileId']='profile'
    dump(work/'payload'/'staged-package-description.json',pkg)
    dump(work/'payload'/'signed-release-manifest.json',signed)
    lifecycle=work/'lifecycle-validation'
    dump(lifecycle/'previous-source'/'staged-package-description.json',prev)
    dump(lifecycle/'previous-source'/'signed-release-manifest.json',previous_signed)
    for sub in ('previous-source','installation'):
        f=lifecycle/sub/artifact['path'];f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(data)
    for name,status in (('prior-install','applied-and-verified'),('update','applied-and-verified'),
                        ('repaired','repaired-and-verified'),('rollback','rolled-back')):
        dump(lifecycle/(name+'.json'),{'status':status,'restoredSnapshot':'snapshot-1'})
    for phase in ('staging','committing'):
        for name in ('prior','retry'):
            dump(lifecycle/('interrupted-'+phase)/(name+'.json'),{'status':'applied-and-verified'})
    download_path=lifecycle/'interrupted-download.bin';download_path.write_bytes(data)
    for name,key in (('rollback-launch','3'*64),('java-replacement-launch','4'*64),('managed-java-repair-launch','5'*64)):
        dump(lifecycle/(name+'.json'),{'status':'passed','javaSha256':key,
            'menuSamples':[{'sha256':str(i)*64,'menuControls':['singleplayer','multiplayer']} for i in (1,2)]})
    file_map={artifact['path']:artifact['sha256']}
    checks={name:'passed' for name in ('cleanPreviousInstall','failedUpdateLeavesPrevious',
            'upgrade','corruptCacheRejected','repair','javaReplacementLaunch','managedJavaRepairAndLaunch','rollbackAndLaunch')}
    checks['interruptedDownload']={'interruptedRejected':True,'partialRemoved':True,
         'retryVerified':True,'artifactSha256':a.sha(download_path)}
    for phase in ('staging','committing'):
        checks['interruptedTransaction-'+phase]={'phase':phase,'killedUpdater':True,
             'recovery':'passed','previousRestored':True,'retryVerified':True,'currentPackageId':package}
    dump(work/'update-recovery.json',{'schemaVersion':'neverlauncher.lifecycle-validation.v1',
       'status':'passed','currentPackageId':package,'currentVersion':'1.0.0',
       'previousPackageId':'prev-package','previousVersion':'0.9.0',
       'previousArchiveSha256':'a'*64,'rollbackSnapshot':'snapshot-1',
       'javaOriginalSha256':'3'*64,'javaReplacementSha256':'4'*64,
       'managedJava':{'manifestSha256':'a'*64,'archiveSha256':'b'*64,'javaSha256':'5'*64,'majorVersion':21,'reinstalled':True},
       'checks':checks,'files':file_map,
       'filesSha256':hashlib.sha256(json.dumps(file_map,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
    stages={name:{'status':'passed'} for name in a.REQUIRED}
    for name,file in a.STAGE_ARTIFACT.items():stages[name]['evidenceSha256']=a.sha(work/file)
    now=datetime.now(timezone.utc)
    issued={'runId':run,'packageId':package,'manifestSha256':m,'artifactSha256':b,
            'nonce':'7'*64,'targetMatrixSha256':'6'*64,
            'issuedAt':(now-timedelta(minutes=4)).isoformat().replace('+00:00','Z')}
    issued['requiredTargets']=[{'id':'linux-default','version':'1.0.0',
        'manifestSha256':m,'artifactSha256':b,'resolvedPlanSha256':resolution,
        'sourceSha':'f'*40,'buildSha':'2'*64,'javaSha256':'3'*64,'javaVersion':'21.0.7',
        'os':'linux','arch':'amd64','loader':'vanilla',
        'installAdapterSha256':hashlib.sha256((cli+rt).encode()).hexdigest(),
        'guardMode':'disabled','guardPolicySha256':hashlib.sha256(b'{}').hexdigest(),
        'serverBridgeSha256':'0'*64,'serverPluginVersion':'none','preset':'default','authenticationMode':'official'}]
    dump(work/'staged-execution.json',{'schemaVersion':'neverlauncher.staged-runtime-run.v1',
        **issued,'startedAt':(now-timedelta(minutes=3)).isoformat().replace('+00:00','Z'),
        'finishedAt':now.isoformat().replace('+00:00','Z'),'stages':stages})
    return issued

class TrustBoundaryTests(unittest.TestCase):
    def test_signing_key_stays_host_only_and_signature_domain_separated(self):
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/'key.pem'
            priv=Ed25519PrivateKey.generate()
            key.write_bytes(priv.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
            key.chmod(0o600)
            payload={k:'placeholder' for k in a.EVIDENCE_FIELDS}
            payload['schemaVersion']=a.SCHEMA;payload['runId']='real-run'
            payload['stages']={};payload['artifactHashes']={}
            signed=a.sign_evidence(payload,key)
            import base64
            signature=base64.urlsafe_b64decode(signed['signature']+'==')
            priv.public_key().verify(signature,a.DOMAIN+a.canonical(signed['evidence']))
            with self.assertRaises(Exception):priv.public_key().verify(signature,a.canonical(signed['evidence']))
            payload=dict(signed['evidence']);payload['runId']='modified-run'
            with self.assertRaises(Exception):priv.public_key().verify(signature,a.DOMAIN+a.canonical(payload))
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'owner-only'):a.sign_evidence(payload,key)

    def test_no_report_or_arbitrary_stage_can_certify(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):a.verify_local_artifacts(Path(d),{},'a'*64,'b'*40,'c'*64,'0'*64)

    def test_validate_raw_downloaded_installed_menu_and_gameplay_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            payload=a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)
            self.assertEqual(payload['stages']['gameplay-smoke'],'passed')
            self.assertEqual(payload['serverBridgeSha256'],'0'*64)
            self.assertEqual(payload['javaVersion'],'21.0.7')
            adoption=work/'native-adoption.json'
            adoption.write_text(json.dumps({'status':'ready','networkDownloads':1,
                                           'importedFiles':1,'planSha256':'0'*64}))
            with self.assertRaisesRegex(ValueError,'without network downloads'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)
            dump(adoption,{'status':'ready','networkDownloads':0,'importedFiles':1,'planSha256':'0'*64})
            (work/'client'/'mods'/'example.jar').write_bytes(b'poison')
            with self.assertRaisesRegex(ValueError,'installed client bytes'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_forged_steps_still_fail_independent_artifact_verification(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            doc=a.read_json(work/'gameplay-smoke.json');doc['ticksAfter']=doc['ticksBefore']
            dump(work/'gameplay-smoke.json',doc)
            report=a.read_json(work/'staged-execution.json')
            report['stages']['gameplay-smoke']['evidenceSha256']=a.sha(work/'gameplay-smoke.json')
            report['stages']['matching-server']['evidenceSha256']=a.sha(work/'gameplay-smoke.json')
            dump(work/'staged-execution.json',report)
            with self.assertRaisesRegex(ValueError,'movement or game ticks'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v07_rejects_mock_provider_even_when_report_and_digest_are_rewritten(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            auth=a.read_json(work/'authentication.json');auth['provider']='mock'
            dump(work/'authentication.json',auth)
            report=a.read_json(work/'staged-execution.json')
            report['stages']['authentication']['evidenceSha256']=a.sha(work/'authentication.json')
            dump(work/'staged-execution.json',report)
            with self.assertRaisesRegex(ValueError,'real provider authentication'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v07_rejects_offline_server_claiming_official_auth(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            (work/'matching-server'/'server.properties').write_text('server-ip=127.0.0.1\nonline-mode=false\n')
            with self.assertRaisesRegex(ValueError,'online-mode policy'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v09_rejects_forged_repair_and_incomplete_interruption(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            self.assertEqual(a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)['targetId'],'linux-default')
            proof=a.read_json(work/'update-recovery.json')
            proof['checks']['interruptedTransaction-committing']['killedUpdater']=False
            dump(work/'update-recovery.json',proof)
            report=a.read_json(work/'staged-execution.json')
            report['stages']['update-recovery']['evidenceSha256']=a.sha(work/'update-recovery.json')
            dump(work/'staged-execution.json',report)
            with self.assertRaisesRegex(ValueError,'crashed updater phase'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v09_rejects_tampered_previous_release_file(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            (work/'lifecycle-validation'/'installation'/'mods'/'example.jar').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'rollback did not restore signed previous bytes'):
                a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v05_rejects_wrong_preset_java_server_even_with_valid_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d); issued=fixture(work)
            self.assertEqual(a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)['targetId'],'linux-default')
            for field,wrong in [('preset','another'),('javaSha256','9'*64),('serverPluginVersion','wrong'),('sourceSha','9'*40)]:
                forged=json.loads(json.dumps(issued))
                forged['requiredTargets'][0][field]=wrong
                with self.assertRaisesRegex(ValueError,'no unique configured target'):
                    a.verify_local_artifacts(work,forged,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_v05_attestation_signed_fields_and_key_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);issued=fixture(work)
            key=work/'key.pem';priv=Ed25519PrivateKey.generate()
            key.write_bytes(priv.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));key.chmod(0o600)
            payload=a.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)
            signed=a.sign_evidence(payload,key)
            self.assertEqual(tuple(signed['evidence']),a.EVIDENCE_FIELDS)
            self.assertEqual(len(signed['evidence']['signerKeyId']),64)
            mutated=json.loads(json.dumps(signed['evidence']));mutated['runNonce']='0'*64
            from cryptography.exceptions import InvalidSignature
            with self.assertRaises(InvalidSignature):
                priv.public_key().verify(__import__('base64').urlsafe_b64decode(signed['signature']+'=='),a.DOMAIN+a.canonical(mutated))

    def test_python_canonical_order_agrees_with_go_signed_struct(self):
        source=(Path(__file__).resolve().parents[2]/'services/api/internal/httpapi/validation_attestation_0345.go').read_text()
        import re
        structure=source.split('type validationPayload0345 struct {',1)[1].split('}',1)[0]
        fields=tuple(re.findall(r'`json:"([a-zA-Z0-9]+)"`',structure))
        self.assertEqual(fields,a.EVIDENCE_FIELDS)

    def test_signed_payload_fixed_canonical_order(self):
        self.assertEqual(a.canonical({'a':'A','b':{'x':'X','y':'Y'}}),b'{"a":"A","b":{"x":"X","y":"Y"}}')
        self.assertEqual(len(a.REQUIRED),9)

if __name__=='__main__':unittest.main()
