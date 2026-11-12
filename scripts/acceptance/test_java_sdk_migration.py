#!/usr/bin/env python3
"""Отрицательные регрессии действующей приёмки. Имитированные входные данные НИКОГДА не засчитываются как GA."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import legacy_upgrade_real as legacy
import java_sdk_migration as suite
import java_host_real as host


class Acceptance0528(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)

    def private(self, value, name='config.json'):
        path=self.root/name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_private_config_duplicate_fields_and_permissions(self):
        path=self.private({'format':'test'})
        self.assertEqual(legacy.private_json(path)['format'],'test')
        path.write_text('{"format":"first","format":"second"}')
        with self.assertRaises(legacy.Blocked):legacy.private_json(path)
        path.chmod(0o644)
        with self.assertRaises(legacy.Blocked):legacy.private_json(path)
        path.chmod(0o600)
        link=self.root/'linked.json';link.symlink_to(path)
        with self.assertRaises(legacy.Blocked):legacy.private_json(link)

    def test_original_migration_files_cannot_be_hardlinks_or_symlinks(self):
        source=self.root/'old.db';source.write_bytes(b'data')
        h=legacy.sha_file(str(source))
        self.assertEqual(h,hashlib.sha256(b'data').hexdigest())
        link=self.root/'linked.db';link.symlink_to(source)
        with self.assertRaises(legacy.Blocked):legacy.sha_file(str(link))
        hard=self.root/'hard.db';os.link(source,hard)
        with self.assertRaises(legacy.Blocked):legacy.sha_file(str(source))
        hard.unlink()
        source.write_bytes(b'updated')
        self.assertNotEqual(legacy.sha_file(str(source)),h)

    def test_real_disk_source_snapshot_detects_mutation(self):
        original=self.root/'original.db';original.write_bytes(b'real-sqlite-source-snapshot')
        storage=self.root/'storage';storage.mkdir()
        (storage/'world.dat').write_bytes(b'real-minecraft-world-bytes')
        cfg={'sourceFiles':{'core_db':str(original)},'storageRoot':str(storage)}
        first=legacy.source_snapshot(cfg)
        self.assertEqual(first['source']['files'] if 'source' in first else first['files']['core_db'],
                         hashlib.sha256(original.read_bytes()).hexdigest())
        (storage/'world.dat').write_bytes(b'corrupted-world')
        second=legacy.source_snapshot(cfg)
        self.assertNotEqual(first['storage'],second['storage'])

    def test_live_historical_upgrade_fail_closed_for_owner_change_and_source_drift(self):
        old_worlds=self.root/'original-worlds';old_worlds.mkdir()
        migrated_worlds=self.root/'migrated-worlds';migrated_worlds.mkdir()
        cfg={'sourceVersion':'0.36.0','baseUrl':'https://real.example',
             'sourceFiles':{'core_db':str(self.root/'original-source.db')},
             'storageRoot':str(old_worlds), 'targetStorageRoot':str(migrated_worlds),
             'sourceCaptureSha256':'a'*64}
        original={'schema':legacy.SCHEMA,'phase':'original','sourceVersion':'0.36.0',
                  'source':{'files':{'core_db':'b'*64},'storage':{'sha256':'c'*64,'count':1,'size':4}},
                  'identity':{'owner':{'id':'owner-1'},'project':'p'}}
        with patch.object(legacy.live,'running_version',return_value=(legacy.ROOT/'VERSION').read_text().strip()), \
             patch.object(legacy,'source_snapshot',return_value=original['source']), \
             patch.object(legacy,'live_snapshot',return_value=original['identity']):
            self.assertEqual(legacy.verify(cfg,original)['status'],'LIVE_CHECKS_PASSED_REVIEW_REQUIRED')
            alias=dict(cfg, targetStorageRoot=str(old_worlds/'..'/'original-worlds'))
            with self.assertRaises(legacy.Blocked):legacy.verify(alias,original)
            nested=old_worlds/'nested';nested.mkdir()
            nested_cfg=dict(cfg, targetStorageRoot=str(nested))
            with self.assertRaises(legacy.Blocked):legacy.verify(nested_cfg,original)
        with patch.object(legacy.live,'running_version',return_value=(legacy.ROOT/'VERSION').read_text().strip()), \
             patch.object(legacy,'source_snapshot',return_value=original['source']), \
             patch.object(legacy,'live_snapshot',return_value={'owner':{'id':'attacker'}}):
            with self.assertRaises(legacy.Blocked):legacy.verify(cfg,original)
        with patch.object(legacy.live,'running_version',return_value=(legacy.ROOT/'VERSION').read_text().strip()), \
             patch.object(legacy,'source_snapshot',return_value={'files':{},'storage':{}}):
            with self.assertRaises(legacy.Blocked):legacy.verify(cfg,original)
        with patch.object(legacy.live,'running_version',return_value='0.46.0'):
            with self.assertRaises(legacy.Blocked):legacy.verify(cfg,original)

    def test_live_manifest_requires_both_old_routes_and_exact_commit(self):
        base={'format':suite.SCHEMA,'sourceCommit':'a'*40,
              'gravit':{},'java':{},
              'legacy':[{'sourceVersion':'0.36.0','capture':'/a'},
                        {'sourceVersion':'0.46.0','capture':'/b'}]}
        self.assertEqual(suite.parse_live(base),base)
        for key, bad in [('sourceCommit','a'*39),('legacy',[{'sourceVersion':'0.36.0','capture':'/a'}]*2)]:
            mutated=dict(base);mutated[key]=bad
            with self.assertRaises(legacy.Blocked):suite.parse_live(mutated)

    def test_live_http_rejects_downgrade_and_embedded_credentials(self):
        for address in ('http://remote.example','https://u:p@host.test',
                        'http://127.0.0.1:123/path','https://host.test/?token=x',
                        'https://host.test:99999'):
            with self.subTest(address=address),self.assertRaises(legacy.Blocked):
                host.LiveHTTP(address)
        host.LiveHTTP('http://127.0.0.1:1234')
        host.LiveHTTP('https://api.example')

    def test_live_game_agent_must_appear_in_hashed_certification(self):
        runtime=self.root/'runtime';runtime.mkdir()
        cert=runtime/'fabric-certification.json'
        cert.write_text(json.dumps({'trustedAgentSha256':'a'*64}))
        digest=hashlib.sha256(cert.read_bytes()).hexdigest()
        receipt=self.private({'loader':'fabric','evidence':{'sha256':{'fabric-certification.json':digest}}},'compatibility-result.json')
        self.assertEqual(host.agent_digest_from_game({'gameCompatibilityResult':str(receipt)}),'a'*64)
        cert.write_text(json.dumps({'trustedAgentSha256':'b'*64}))
        self.assertEqual(host.agent_digest_from_game({'gameCompatibilityResult':str(receipt)}),'')
        receipt.write_text(json.dumps({'loader':'fabric','evidence':{'sha256':{}}}))
        self.assertEqual(host.agent_digest_from_game({'gameCompatibilityResult':str(receipt)}),'')

    def test_report_never_overwrites_existing_file(self):
        path=self.root/'results.json'
        suite.private_save(path, {'gaCertified':False})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(legacy.Blocked):suite.private_save(path, {'gaCertified':True})


if __name__=='__main__':unittest.main()
