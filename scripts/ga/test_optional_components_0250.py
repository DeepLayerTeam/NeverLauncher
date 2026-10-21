"""Synthetic signed fixtures exercise the verifier, not release certification."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from release_gate import (
    COMPONENT_GA_DOMAIN, COMPONENT_GA_CHECKS, COMMON_CHECKS,
    TARGETS, verify_all, strict_json,
)

COMMIT = 'c' * 40
VERSION = '0.25.0'
HEXDIGEST = 'd' * 64


def make_fixture(root: Path):
    secret = Ed25519PrivateKey.generate()
    key = secret.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    for platform, arch in sorted(TARGETS):
        target = f'{platform}-{arch}'
        folder = root / target
        folder.mkdir()
        installer = b'test fixture: not an actual executable'
        installer_sha = hashlib.sha256(installer).hexdigest()
        os_label = {'windows':'Windows','linux':'Linux','darwin':'Darwin'}[platform]
        common = {'commit':COMMIT, 'productVersion':VERSION, 'status':'passed', 'simulated':False}
        proof = {
            'nativeRun': dict(common, target=target, actualExecution=True,
                              signedManifestVersion='3.0', catalogSchema='5.0', httpRequests=4),
            'minecraftRun': dict(common, target=target, actualExecution=True,
                                 actualClient=True, loader='vanilla'),
            'guardRun': dict(common, target=target, actualExecution=True,
                             actualIntegration=True, kind='neverguard-live-attestation'),
            'bridgeRun': dict(common, target=target, actualExecution=True,
                              actualIntegration=True, kind='serverbridge-real-join-replay'),
        }
        run_sha = {name:hashlib.sha256(json.dumps(obj).encode()).hexdigest() for name,obj in proof.items()}
        reports = {**proof,
            'osSignature': dict(common, signatureVerified=True, trustedSigner='fixture-only',
                                artifactSha256=installer_sha, platform=os_label),
            'cleanMachine': dict(common, schemaVersion='neverlauncher.ga.clean-machine.v1',
                                 javaSha256=HEXDIGEST, logSha256=HEXDIGEST,
                                 minecraftVersion='1.21.1', installerSha256=installer_sha,
                                 platform=os_label),
            'certification': dict(common, gitTreeClean=True, unmetGates=[], suites=[{'status':'passed'}]),
            'benchmark': dict(common, runs=[{'implementation': p} for p in ('baseline','candidate')*3],
                              speedup=1.2, baselineExecutableSha256=HEXDIGEST,
                              candidateExecutableSha256=HEXDIGEST),
            'components': dict(common, schemaVersion='neverlauncher.components.certification.v1',
                               target=target, gitTreeClean=True, signedManifestVersion='3.0',
                               catalogSchema='5.0', actualMinecraftClient=True,
                               actualGuardIntegration=True, actualBridgeIntegration=True,
                               nativeEvidenceSha256=run_sha["nativeRun"],
                               minecraftEvidence={'target':target,'sha256':run_sha['minecraftRun']},
                               guardEvidence={'target':target,'sha256':run_sha['guardRun']},
                               bridgeEvidence={'target':target,'sha256':run_sha['bridgeRun']},
                               installerSha256=installer_sha,
                               checks={c:'passed' for c in COMPONENT_GA_CHECKS}),
        }
        objects = {}
        for name, data in [('installer', installer), *[(name, json.dumps(obj).encode()) for name,obj in reports.items()]]:
            filename = name + '.bin'
            (folder / filename).write_bytes(data)
            objects[name] = {'file':filename, 'sha256':hashlib.sha256(data).hexdigest()}
        checks = {name:'passed' for name in (COMMON_CHECKS | {'component-graph','signed-actions',
            'migration','serverbridge-plan-evidence','minecraft-component-launch'})}
        if platform == 'windows':
            checks['windows-executable-lock'] = 'passed'
        doc = {'schemaVersion':'neverlauncher.ga.optional-components.v1',
               'productVersion':VERSION, 'status':'passed', 'commit':COMMIT,
               'gitTreeClean':True, 'platform':platform, 'architecture':arch,
               'objects':objects, 'checks':checks}
        payload = json.dumps(doc, sort_keys=True).encode()
        (folder/'attestation.json').write_bytes(payload)
        (folder/'attestation.sig').write_text(secret.sign(COMPONENT_GA_DOMAIN+payload).hex())
    return key


class OptionalComponentsGATests(unittest.TestCase):
    def test_valid_signed_six_platform_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = make_fixture(root)
            report = verify_all(root,key,COMMIT,version=VERSION)
            self.assertEqual(report['status'],'passed')
            self.assertEqual(len(report['artifacts']),6)
    def test_missing_platform_or_signed_proof_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = make_fixture(root)
            (root/'linux-amd64'/'components.bin').unlink()
            with self.assertRaises(Exception):
                verify_all(root,key,COMMIT,version=VERSION)
    def test_old_domain_signatures_do_not_approve_ga_0250(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=make_fixture(root)
            with self.assertRaises(Exception):
                verify_all(root,key,COMMIT,version='0.24.0')
    def test_modified_evidence_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=make_fixture(root)
            path=root/'darwin-arm64'/'components.bin'
            raw=path.read_bytes().replace(b'"passed"',b'"skipped"',1)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'digest mismatch'):
                verify_all(root,key,COMMIT,version=VERSION)
    def test_cross_commit_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=make_fixture(root)
            with self.assertRaises(ValueError):
                verify_all(root,key,'a'*40,version=VERSION)
    def test_symlinked_attestation_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=make_fixture(root)
            original=root/'windows-amd64'
            original.rename(root/'safe-directory')
            original.symlink_to(root/'safe-directory',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symlinked'):
                verify_all(root,key,COMMIT,version=VERSION)
    def test_duplicate_json_object_fields_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON field'):
            strict_json(b'{"status":"passed","status":"failed"}')
    def test_unknown_public_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);make_fixture(root)
            with self.assertRaises(Exception):
                verify_all(root,'0'*64,COMMIT,version=VERSION)

if __name__=='__main__':
    unittest.main()
