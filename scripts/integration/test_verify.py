"""Атакующие тесты валидатора приёмки 0.48.0 (без выдуманных положительных E2E)."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.integration import verify_0478 as verifier
from scripts.integration import legacy_matrix_0478 as legacy

class EvidenceSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload))
        return path

    def test_legacy_missing_release_is_rejected(self):
        self.put('manifest.json', {'target':'0.48.0','baselines':[{'version':'0.47.7','url':'https://example.test/old.zip','sha256':'a'*64,'binary':'launcher'}]})
        with self.assertRaisesRegex(legacy.MatrixError, 'Для каждой поддерживаемой исходной версии'):
            legacy.load_manifest(self.root / 'manifest.json')

    def test_legacy_duplicate_version_is_rejected(self):
        rows = [{'version':x,'sha256':'a'*64,'url':'https://example.test/old.zip','binary':'launcher'} for x in legacy.VERSIONS]
        rows[-1]['version'] = rows[-2]['version']
        self.put('manifest.json', {'target':'0.48.0','baselines':rows})
        with self.assertRaises(legacy.MatrixError):
            legacy.load_manifest(self.root/'manifest.json')

    def test_legacy_unsafe_url_and_hash_rejected(self):
        rows = [{'version':x,'sha256':'a'*64,'url':'https://example.test/old.zip','binary':'launcher'} for x in legacy.VERSIONS]
        rows[3]['url'] = 'http://example.test/old.zip'
        self.put('manifest.json', {'target':'0.48.0','baselines':rows})
        with self.assertRaisesRegex(legacy.MatrixError, 'закреплённый HTTPS-адрес'):
            legacy.load_manifest(self.root/'manifest.json')
        rows[3]['url'] = 'https://example.test/old.zip'; rows[3]['sha256']='wrong'
        self.put('manifest.json', {'target':'0.48.0','baselines':rows})
        with self.assertRaisesRegex(legacy.MatrixError, 'SHA-256'):
            legacy.load_manifest(self.root/'manifest.json')

    def test_archive_traversal_and_duplicates_rejected(self):
        for name in ('../escape', '/tmp/escape', 'bin/../../escape', 'bin\\escape','bin//file'):
            with self.subTest(name=name), self.assertRaises(legacy.MatrixError):
                legacy.safe_member(name)

    def test_no_silent_skip_of_old_versions(self):
        rows = [{'version':x, 'nativeVerified':True,'userDataVerified':True,'beforeFiles':2,
                 'originalSha256':'a'*64, 'oldExecutableSha256':'b'*64,'newExecutableSha256':'c'*64} for x in sorted(verifier.VERSIONS)]
        self.put('legacy.json', {'type':'native-legacy-upgrade','targetVersion':'0.48.0','status':'passed','results':rows})
        verifier.legacy(self.root/'legacy.json','0.48.0')
        rows.pop()
        self.put('legacy.json', {'type':'native-legacy-upgrade','targetVersion':'0.48.0','status':'passed','results':rows})
        with self.assertRaises(verifier.EvidenceError):
            verifier.legacy(self.root/'legacy.json','0.48.0')

    def test_unsigned_success_flag_without_game_proof_rejected(self):
        self.put('result.json', {'version':'0.48.0','status':'passed','minecraft':{'version':'1.21.1','client':'actual-mojang-client'}, 'checks':{'actualClient':True}})
        with self.assertRaises(verifier.EvidenceError):
            verifier.minecraft(self.root)

    def test_unsafe_artifact_symlink_and_path_rejected(self):
        for name in ('../fake','/tmp/file','foo//bar','foo/../../bar'):
            with self.subTest(name=name), self.assertRaises(verifier.EvidenceError):
                verifier.files(self.root,[name])
        target = self.root/'real.json'; target.write_text('test')
        (self.root/'linked.json').symlink_to(target)
        with self.assertRaises(verifier.EvidenceError):
            verifier.files(self.root,['linked.json'])

    def test_actual_matching_join_fields_mandatory(self):
        checks = {key:True for key in ('materialized','packageVerified','runtimeResolved','javaMatched','actualClient','matchingServer','serverVersionMatched','serverHealthy','clientJoinedServer')}
        ev = ['client-package.json','matching-server.log','matching-server.json']
        self.put('result.json',{'version':'0.48.0','status':'passed','minecraft':{'version':'1.21.1','serverVersion':'1.21.1','client':'actual-mojang-client'},'checks':checks,'evidence':ev})
        for name in ev:
            (self.root/name).write_text('actual-runner-file')
        self.put('matching-server.json',{'status':'passed','clientJoinedServer':True,'actualClient':True})
        verifier.minecraft(self.root, matching=True, mc='1.21.1')
        self.put('matching-server.json',{'status':'passed','clientJoinedServer':False,'actualClient':True})
        with self.assertRaises(verifier.EvidenceError):
            verifier.minecraft(self.root, matching=True, mc='1.21.1')

    def test_real_owner_receipt_rejects_missing_checks(self):
        path=self.put('owner.json',{'schemaVersion':1,'status':'passed','productVersion':'0.48.0','sourceCommit':'a'*40,'scope':'live-admin-browser-owner-cycle-0390','checks':[]})
        with self.assertRaises(RuntimeError):
            verifier.owner(path,'0.47.8','a'*40)

if __name__ == '__main__':
    unittest.main()
