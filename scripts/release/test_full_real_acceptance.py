"""Тесты противодействия обходам исполняемого шлюза GA с 18 группами.

Все фикстуры — входы только валидатора, НЕ свидетельства реальной пользовательской приёмки.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.release import full_real_acceptance_0530 as m

COMMIT='b'*40
PIN='c'*64

def fixture(root):
    result=root/'results';logs=root/'logs';result.mkdir();logs.mkdir()
    records={}
    for name in m.SCENARIOS:
        row=valid_report(name)
        target=result/(name+'.json');target.write_text(json.dumps(row))
        log=logs/(name+'.log');log.write_text('real observed report verified from signed source\n')
        records[name]={'resultSha256':m.digest(target),'logSha256':m.digest(log),
                       'status':row['status'],'exit':0}
    return records

def valid_report(name):
    if name.startswith('ha-'):
        return {'version':m.VERSION,'mode':'dependency' if name in ('ha-postgresql','ha-redis','ha-s3') else name[3:],
                'status':'PASS','markerVerified':True,
                'service':{'ha-postgresql':'patroni','ha-redis':'redis-server','ha-s3':'minio'}.get(name)}
    if name=='minimal':return {'status':'passed','productVersion':m.VERSION,'checks':[{'status':'passed'}]*20}
    if name=='standard':return {'status':'passed','productVersion':m.VERSION,'checks':[{'status':'passed'}]*14}
    if name=='auth':return {'status':'passed-live-operator-observations-not-independent-ga',
                           'productVersion':m.VERSION,'sourceCommit':COMMIT,'checks':[{'status':'passed'}]*13}
    if name=='modpacks':return {'status':'passed','version':m.VERSION,'checks':['x']*9,'textures':['skin','cape']}
    if name=='install':return {'status':'PASS','version':m.VERSION,'checks':['install']*8}
    if name=='java':return {'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED',
                 'productVersion':m.VERSION,'sourceCommit':COMMIT,
                 'gravit':{'migrationChecks':36,'moduleChecks':19},'legacy':{'0.36.0':'a','0.46.0':'b'},
                 'java':{'checks':6}}
    if name=='guard':return {'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED',
                  'version':m.VERSION,'sourceCommit':COMMIT,
                  'serverBridge':{'tenRealRuntime':{str(i):'x' for i in range(10)},
                                  'threeBuildCompatibility':['bukkit','quilt','sponge']},
                  'deviceTrust':{'targets':{'x':'ok'}},'guard':{'x':'ok'}}
    if name=='sdk':return {'status':'LIVE_SDK_OPERATIONS_PASSED_NOT_GA',
                           'version':m.VERSION,'checks':['x']*9}
    raise AssertionError(name)

class FullRealGATests(unittest.TestCase):
 def test_full_18_groups_cannot_drop_any_scenario(self):
    self.assertEqual(len(m.GROUPS),18)
    self.assertEqual(list(m.GROUPS),[f'E2E-{i:02d}' for i in range(1,19)])
    self.assertEqual(set(m.GROUPS['E2E-18'])-{'full-sweep'},set(m.SCENARIOS))
 def test_partial_ci_without_real_live_suites_cannot_be_ga(self):
    with self.assertRaises(m.Blocked):m.group_coverage({'status':'OBSERVED_NOT_INDEPENDENT_GA'}, {})
 def test_full_sweep_with_missing_loader_or_http_soak_blocks(self):
    raw={'status':'OBSERVED_NOT_INDEPENDENT_GA','minecraft':{'targets':280},
         'gameSoaks':[{}]*4,'httpSoak':{'requests':10000},
         'reproducibility':{'targets':{str(i):'x' for i in range(6)}},
         'nativePackages':{'status':'CI_OBSERVED_REVIEW_REQUIRED','nativeTargets':[{}]*6},
         'nativeGame':{'status':'observed-not-independently-certified','targets':[{}]*6}}
    with self.assertRaises(m.Blocked):m.group_coverage(raw,{x:{} for x in m.SCENARIOS})
 def test_good_fixture_only_tests_verifier_not_real_ga(self):
    with tempfile.TemporaryDirectory() as t:
        work=Path(t); records=fixture(work)
        self.assertEqual(len(m.replay(work,records,COMMIT)),len(m.SCENARIOS))
        assert m.group_coverage({'status':'OBSERVED_NOT_INDEPENDENT_GA',
          'minecraft':{'targets':280},'gameSoaks':[{}]*5,'httpSoak':{'requests':10000},
          'reproducibility':{'targets':{str(i):'x' for i in range(6)}},
         'nativePackages':{'status':'CI_OBSERVED_REVIEW_REQUIRED','nativeTargets':[{}]*6},
         'nativeGame':{'status':'observed-not-independently-certified','targets':[{}]*6}}, records)
 def test_missing_six_native_game_observations_blocks(self):
    sweep={'status':'OBSERVED_NOT_INDEPENDENT_GA','minecraft':{'targets':280},
           'gameSoaks':[{}]*5,'httpSoak':{'requests':10000},
           'reproducibility':{'targets':{str(i):'x' for i in range(6)}},
           'nativePackages':{'status':'CI_OBSERVED_REVIEW_REQUIRED','nativeTargets':[{}]*6},
           'nativeGame':{'status':'observed-not-independently-certified','targets':[{}]*5}}
    with self.assertRaises(m.Blocked):m.group_coverage(sweep,{x:{} for x in m.SCENARIOS})
 def test_falsified_pass_with_modified_receipt_blocks(self):
    with tempfile.TemporaryDirectory() as t:
        work=Path(t);records=fixture(work)
        (work/'results/guard.json').write_text(json.dumps({'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED'}))
        with self.assertRaises(m.Blocked):m.replay(work,records,COMMIT)
 def test_changed_log_blocks_even_when_json_unchanged(self):
    with tempfile.TemporaryDirectory() as t:
        work=Path(t);records=fixture(work)
        with (work/'logs/ha-world.log').open('a') as f:f.write('tampered')
        with self.assertRaises(m.Blocked):m.replay(work,records,COMMIT)
 def test_missing_true_p1_closure_blocks_in_rehearsal(self):
    self.assertIn('scripts.release.test_full_real_acceptance_0530',m.rehearsal.REGRESSIONS)
 def test_wrong_java_commit_blocks(self):
    row=valid_report('java');row['sourceCommit']='d'*40
    with self.assertRaises(m.Blocked):m.assert_observed('java',row,COMMIT)
 def test_incomplete_gravit_and_legacy_blocks(self):
    row=valid_report('java');row['legacy'].pop('0.36.0')
    with self.assertRaises(m.Blocked):m.assert_observed('java',row,COMMIT)
 def test_partial_guard_native_missing_rejected(self):
    row=valid_report('guard');row['serverBridge']['tenRealRuntime'].pop('0')
    with self.assertRaises(m.Blocked):m.assert_observed('guard',row,COMMIT)
 def test_missing_live_world_marker_blocks(self):
    row=valid_report('ha-world');row['markerVerified']=False
    with self.assertRaises(m.Blocked):m.assert_observed('ha-world',row,COMMIT)
 def test_same_signer_keys_are_not_independent(self):
    p=SimpleNamespace(release_pin=PIN,issues_pin=PIN,qa_pin='d'*64,verifier_pin='e'*64,
                      commit=COMMIT,project='test',index_sha='f'*64)
    with self.assertRaises(m.Blocked):m.approval(p)
 def test_replayed_qa_signature_tampered_json_rejected(self):
    with tempfile.TemporaryDirectory() as t:
        work=Path(t);secret=Ed25519PrivateKey.generate()
        public=secret.public_key();pem=public.public_bytes(serialization.Encoding.PEM,
                          serialization.PublicFormat.SubjectPublicKeyInfo)
        pin=hashlib.sha256(public.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        pub=work/'public.pem';pub.write_bytes(pem)
        doc={'schema':m.SCHEMA,'status':'REVIEWED_LIVE_18_E2E_PENDING_INDEPENDENT_VERIFIER'}
        path=work/'qa.json';sig=work/'qa.sig'
        m.sign(path,sig,doc,secret,m.DOMAIN)
        self.assertEqual(m.verify_signed(path,sig,pub,pin,m.DOMAIN),doc)
        doc['status']='PASS';path.write_text(json.dumps(doc))
        with self.assertRaises(m.rehearsal.Blocked):m.verify_signed(path,sig,pub,pin,m.DOMAIN)
 def test_scenario_execution_rejects_missing_actual_outputs(self):
    with tempfile.TemporaryDirectory() as t:
        work=Path(t);plan=work/'plan.json';plan.write_text('{}');plan.chmod(0o600)
        with self.assertRaises(m.Blocked):m.execute(plan,work,COMMIT,PIN)
 def test_fake_plan_omits_reality_blocks(self):
    with self.assertRaises(m.Blocked):m.strict_plan({'version':m.VERSION,'sourceCommit':COMMIT,
            'sourceIndexSha256':PIN,'scenarios':{'minimal':[]}},COMMIT,PIN)
 def test_wrong_sdk_version_blocks(self):
    row=valid_report('sdk');row['version']='0.52.12'
    with self.assertRaises(m.Blocked):m.assert_observed('sdk',row,COMMIT)
 def test_signed_receipt_from_old_version_never_promotes(self):
    self.assertIn('0.53.0',m.DOMAIN.decode())
    self.assertNotEqual(m.DOMAIN,m.rehearsal.REHEARSAL_DOMAIN)

if __name__=='__main__':unittest.main()
