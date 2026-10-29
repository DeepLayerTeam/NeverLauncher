"""Fail-closed RC harness tests. Fixtures only exercise the verifier, never sign GA."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gate_03514 import verify, GateBlocked, REQUIRED_NATIVE
from native_03514 import process, pass_native, reject_native, RCBlocked, check_binary
from operations_03514 import check_args, OperationsBlocked

COMMIT='a'*40
HEX='b'*64


def fixtures(path):
    native=path/'native'; desktop=path/'desktop'
    native.mkdir(); desktop.mkdir()
    for osname in ('linux','windows','darwin'):
        (native/f'{osname}.json').write_text(json.dumps({
            'schemaVersion':'neverlauncher.rc.native.v1', 'status':'passed', 'simulated':False,
            'version':'0.35.14','commit':COMMIT,'platform':osname,
            'runtimeSha256':HEX,'signerSha256':HEX,'signedFixtureSha256':HEX,
            'fixtureBytes':128*1024,'checks':sorted(REQUIRED_NATIVE),
            'certificationScope':'real native commands; not Minecraft/GUI E2E'}))
        (desktop/f'{osname}.json').write_text(json.dumps({
            'schemaVersion':'neverlauncher.rc.desktop-build.v1','status':'passed','simulated':False,
            'version':'0.35.14','commit':COMMIT,'platform':osname,
            'binarySha256':HEX,'binarySizeBytes':3_000_000,'frontendSha256':HEX,'frontendAssets':3}))
    backend=path/'backend.json'
    backend.write_text(json.dumps({'schemaVersion':'neverlauncher.owner-player-http-acceptance.v1',
        'status':'local-loopback-passed', 'version':'0.35.14','realBackend':True,
        'realMinecraftCertification':False,'nativeDesktopVerified':False,'stablePublicationVerified':False,
        'checks':['real-backend-health-0351','unauthenticated-admin-mutation-denied',
                  'real-admin-and-player-sign-in','player-accounts-protected',
                  'owner-create-update-player-read-project','owner-create-player-discover-profile',
                  'owner-create-player-discover-channel','unpublished-or-workspace-content-not-served',
                  'refresh-rotation-and-logout-revocation']}))
    return native,desktop,backend


class NativeRunnerTests(unittest.TestCase):
    def test_real_process_exit_and_rejection(self):
        good=process(Path(sys.executable),'-c','import json; print(json.dumps({"status":"ready"}))')
        self.assertEqual(pass_native(good)['status'],'ready')
        with self.assertRaises(RCBlocked):
            reject_native(good, 'a real ready result cannot be a rejection')
        bad=process(Path(sys.executable),'-c','import json,sys; print(json.dumps({"status":"invalid"}));sys.exit(0)')
        reject_native(bad, 'a native structured rejection must be accepted')
        with self.assertRaises(RCBlocked):
            pass_native(bad)

    def test_executable_absent_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing=Path(tmp)/'missing'
            with self.assertRaises(RCBlocked):check_binary(missing)
            link=Path(tmp)/'link'
            link.symlink_to(sys.executable)
            with self.assertRaises(RCBlocked):check_binary(link)


class OperationsTests(unittest.TestCase):
    def test_requires_distinct_isolated_projects_and_protected_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            env=root/'env';env.write_text('COMPOSE_PROJECT_NAME=some-staging-project')
            with self.assertRaises(OperationsBlocked):
                check_args('production','production','http://127.0.0.1:1/ready',
                           'http://127.0.0.1:2/ready',env,root/'snapshot')
            with self.assertRaises(OperationsBlocked):
                check_args('nl-dr-source','nl-dr-target','http://127.0.0.1:1/ready',
                           'http://127.0.0.1:1/ready',env,root/'snapshot')
            with self.assertRaises(OperationsBlocked):
                check_args('nl-dr-source','nl-dr-target','https://remote.example/ready',
                           'http://127.0.0.1:2/ready',env,root/'snapshot')
            with self.assertRaises(OperationsBlocked):
                check_args('nl-dr-source','nl-dr-target','http://127.0.0.1:1/ready',
                           'http://127.0.0.1:2/ready',env,root/'snapshot')


class VerificationTests(unittest.TestCase):
    def test_three_platform_builds_and_true_backend_e2e(self):
        with tempfile.TemporaryDirectory() as tmp:
            n,d,b=fixtures(Path(tmp))
            report=verify(n,d,b,COMMIT,'0.35.14')
            self.assertEqual(report['status'],'rc-source-checks-passed')
            self.assertFalse(report['realMinecraftCertified'])
            self.assertFalse(report['fullDisasterRecoveryCertified'])

    def test_0360_same_executable_rc_checks_without_fabricated_ga(self):
        with tempfile.TemporaryDirectory() as tmp:
            n,d,b=fixtures(Path(tmp))
            for root in (n,d):
                for file in root.glob('*.json'):
                    obj=json.loads(file.read_text());obj['version']='0.36.0'
                    file.write_text(json.dumps(obj))
            obj=json.loads(b.read_text());obj['version']='0.36.0'
            b.write_text(json.dumps(obj))
            result=verify(n,d,b,COMMIT,'0.36.0')
            self.assertEqual(result['status'],'rc-source-checks-passed')
            self.assertFalse(result['realMinecraftCertified'])

    def test_0361_same_real_source_rc_checks_without_ga_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            n,d,b=fixtures(Path(tmp))
            for root in (n,d):
                for file in root.glob('*.json'):
                    obj=json.loads(file.read_text());obj['version']='0.36.1'
                    file.write_text(json.dumps(obj))
            obj=json.loads(b.read_text());obj['version']='0.36.1'
            b.write_text(json.dumps(obj))
            result=verify(n,d,b,COMMIT,'0.36.1')
            self.assertEqual(result['status'],'rc-source-checks-passed')
            self.assertFalse(result['operatorSigned'])

    def deny(self, change):
        with tempfile.TemporaryDirectory() as tmp:
            n,d,b=fixtures(Path(tmp))
            change(n,d,b)
            with self.assertRaises((GateBlocked,ValueError,TypeError,KeyError,FileNotFoundError)):
                verify(n,d,b,COMMIT,'0.35.14')

    def test_reject_missing_platform(self):
        self.deny(lambda n,d,b: (n/'darwin.json').unlink())

    def test_reject_wrong_commit(self):
        def change(n,d,b):
            f=d/'windows.json'; a=json.loads(f.read_text()); a['commit']='c'*40;f.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_faked_native_success(self):
        def change(n,d,b):
            f=n/'linux.json'; a=json.loads(f.read_text()); a['simulated']=True;f.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_missing_signature_negative_probe(self):
        def change(n,d,b):
            f=n/'linux.json'; a=json.loads(f.read_text()); a['checks'].remove('wrong-trust-root-denied');f.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_swapped_platform(self):
        def change(n,d,b):
            f=n/'darwin.json'; a=json.loads(f.read_text()); a['platform']='linux';f.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_missing_real_backend_security_step(self):
        def change(n,d,b):
            a=json.loads(b.read_text());a['checks'].remove('unpublished-or-workspace-content-not-served');b.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_false_claim_of_game_e2e(self):
        def change(n,d,b):
            a=json.loads(b.read_text());a['realMinecraftCertification']=True;b.write_text(json.dumps(a))
        self.deny(change)

    def test_reject_symlinked_evidence(self):
        def change(n,d,b):
            file=n/'darwin.json';file.unlink();file.symlink_to(n/'linux.json')
        self.deny(change)


if __name__=='__main__':unittest.main()
