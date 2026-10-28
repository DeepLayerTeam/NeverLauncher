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
         'loaderVersion':'','bridgeRequired':False,'startup':'passed'})
    dump(work/'gameplay-smoke.json',{'runId':run,'minecraftVersion':'1.21.1','loader':'vanilla',
         'loaderVersion':'','serverBridgeVersion':'','status':'passed','failure':'',
         'serverJoinAndOnline':True,'clientConnectionLogObserved':True,'clientInputSent':True,
         'windowJavaProcessId':123,'positionBefore':[0,65,0],'positionAfter':[1,65,0],
         'ticksBefore':100,'ticksAfter':110,
         'frameBeforeSha256':a.sha(work/'gameplay-diagnostics'/'world-before.png'),
         'frameAfterSha256':a.sha(work/'gameplay-diagnostics'/'world-after.png')})
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
    stages={name:{'status':'passed'} for name in a.REQUIRED}
    for name,file in a.STAGE_ARTIFACT.items():stages[name]['evidenceSha256']=a.sha(work/file)
    now=datetime.now(timezone.utc)
    issued={'runId':run,'packageId':package,'manifestSha256':m,'artifactSha256':b}
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
            payload={'schemaVersion':a.SCHEMA,'runId':'real-run'}
            signed=a.sign_evidence(payload,key)
            import base64
            signature=base64.urlsafe_b64decode(signed['signature']+'==')
            priv.public_key().verify(signature,a.DOMAIN+a.canonical(payload))
            with self.assertRaises(Exception):priv.public_key().verify(signature,a.canonical(payload))
            payload['runId']='modified-run'
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

    def test_signed_payload_fixed_canonical_order(self):
        self.assertEqual(a.canonical({'a':'A','b':{'x':'X','y':'Y'}}),b'{"a":"A","b":{"x":"X","y":"Y"}}')
        self.assertEqual(len(a.REQUIRED),7)

if __name__=='__main__':unittest.main()
