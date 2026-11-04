"""Real subprocess + Unix-socket transport tests against fake Backend/systemd.

NOT evidence of running PostgreSQL, actual Gravit worlds or Minecraft join.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import operational_rollback_04912 as rb
import production_cutover_04911 as cut
import test_production_cutover_04911 as prev

UUID = prev.UUID

FAKE_CLI = '''#!/usr/bin/env python3
import hashlib, json, os, sys
args = sys.argv
assert os.environ.get('LAUNCHER_TOKEN') == 'SECRET_SHOULD_NOT_BE_IN_ARGV'
assert 'SECRET_SHOULD_NOT_BE_IN_ARGV' not in ' '.join(args)
cmd = args[3]
out = args[args.index('--output')+1]
statefile = os.environ['CUTOVER_TEST_STATE_FILE']
with open(statefile) as f: state = f.read().strip()
sha = lambda data: hashlib.sha256(data).hexdigest()
revision = 5
if cmd == 'cutover-list':
    doc = {'data':[{'runId':'run_12345678','profileId':'main','channel':'stable',
        'stageId':'stage_12345678','releaseId':'release-abc','targetDigest':'d'*64,
        'baselineRevision':8,'activatedRevision':9,'revision':5 if state=='rolled_back' else 4,
        'state':'rolled_back' if state=='rolled_back' else 'active'}]}
elif cmd == 'rollback-plan':
    snap = args[args.index('--snapshot')+1]
    data = open(snap,'rb').read()
    report = {'format':'never/gravit-rollback/v1','runId':'run_12345678','profileId':'main',
      'channel':'stable','state':'planned','ready':True,'blockers':[], 'routeRevision':4,
      'evidenceSha256':sha(data),'planSha256':'a'*64,
      'mode':'reconciled' if '--reconciled-source-snapshot' in args else 'unchanged'}
    if os.environ.get('FAIL_ROLLBACK_PLAN')=='1': report['ready']=False; report['blockers']=['world changed']
elif cmd == 'rollback-commit':
    assert args[args.index('--plan-sha256')+1]=='a'*64
    with open(statefile,'w') as f: f.write('rolled_back')
    if os.environ.get('FAIL_AFTER_ROLLBACK_COMMIT')=='1': sys.exit(8)
    report = {'state':'completed','planSha256':'a'*64}
elif cmd == 'rollback-status':
    report = {'state':'completed' if state=='rolled_back' else 'planned','ready':True,
       'planSha256':'a'*64,'routeRevision':4}
else: sys.exit(8)
if cmd not in ('cutover-list',): doc={'data':report}
with open(out,'x') as f: json.dump(doc,f)
'''


class RollbackTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.journal = self.root / 'journal'
        self.journal.mkdir(mode=0o700)
        self.haproxy = prev.HAProxySocket(self.root / 'proxy.sock')
        self.addCleanup(self.haproxy.close)
        self.launcher = self.root / 'launcher'
        prev.write_private(self.launcher, FAKE_CLI.encode())
        self.launcher.chmod(0o700)
        self.canary = self.root / 'auth.json'
        prev.write_private(self.canary, b'{"user":"test"}')
        prev.write_private(self.root / 'live-session.json', {'clientArgs':['--server','play.example.org:25565']})
        self.statefile = self.root / 'backend-state'
        self.statefile.write_text('active')
        self.snapshot = {'worldSha256':'a'*64,'loader':'forge','optionalPresetSha256':'b'*64,
          'players':[{'sourceId':'user-1','uuid':UUID,'inventorySha256':'c'*64,
          'permissionsSha256':'d'*64,'economy':'4.00','skinSha256':'e'*64,'admin':False}]}
        self.current = self.root / 'current.json'
        self.source = self.root / 'source.json'
        self.fresh = self.root / 'fresh.json'
        self.cut = {'format':cut.FORMAT,'runId':'run_12345678','profileId':'main','channel':'stable',
             'stageId':'stage_12345678','releaseId':'release-abc','expectedRevision':3,
             'baselineRevision':8,'targetDigest':'d'*64,'inventorySha256':'b'*64,
             'sourceSnapshotSha256':rb.typed_digest(self.snapshot),
             'backend':'https://localhost:9443','launcher':str(self.launcher),
             'launcherSha256':hashlib.sha256(self.launcher.read_bytes()).hexdigest(),
             'proxySocket':self.haproxy.path,
             'routes':{'auth':{'backend':'auth-backend','source':'old-auth','target':'new-auth'},
                        'game':{'backend':'game-backend','source':'old-game','target':'new-game'}},
             'drainSeconds':5,'postSwitchStage':str(self.root),'gamePublicAddress':'play.example.org:25565',
             'authCanary':{'url':'https://localhost:9444/login','frontendUrl':'https://play.example.org/auth/login',
                 'method':'POST','requestBodyFile':str(self.canary),'expectedPlayerUuid':UUID,
                 'uuidJSONField':'uuid','requestSha256':hashlib.sha256(self.canary.read_bytes()).hexdigest()}}
        self.cutfile = self.root/'cutover.json'
        prev.write_private(self.cutfile, self.cut)
        cut_hash = hashlib.sha256(self.cutfile.read_bytes()).hexdigest()
        cut.journal_write(self.journal, dict(cut.new_phase(cut_hash,'complete'), phase='complete',backendRouteActive=True,trafficOpen=True),new=True)
        self.cfg = {'format':rb.FORMAT,'runId':self.cut['runId'],'profileId':'main','channel':'stable',
            'cutoverConfigSha256':cut_hash,'units':{'source':['gravit.service'],'target':['never.service']},
            'currentSnapshot':str(self.current),'sourceSnapshot':str(self.source)}
        self.cfgfile = self.root/'rollback.json'
        prev.write_private(self.cfgfile,self.cfg)
        self.env = patch.dict(os.environ, {'LAUNCHER_TOKEN':'SECRET_SHOULD_NOT_BE_IN_ARGV',
                                            'CUTOVER_TEST_STATE_FILE':str(self.statefile)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.sysmock = patch.object(rb,'systemd_state',return_value={'ActiveState':'inactive','SubState':'dead','UnitFileState':'masked'})
        self.sysmock.start()
        self.addCleanup(self.sysmock.stop)

    def call(self, cmd, **extra):
        args = [cmd,'--cutover-config',str(self.cutfile),'--rollback-config',str(self.cfgfile),
                '--journal-dir',str(self.journal),'--confirm',self.cut['runId']]
        if cmd=='commit': args += ['--fresh-snapshot',str(extra.get('fresh',self.fresh))]
        return rb.main(args)

    def export(self):
        prev.write_private(self.current,self.snapshot)
        prev.write_private(self.source,self.snapshot)

    def prepare(self):
        self.assertEqual(self.call('fence'),0)
        self.export()

    def approved(self):
        self.prepare()
        self.assertEqual(self.call('plan'),0)

    def test_full_sequence_fences_ingress_and_uses_pg_cli(self):
        self.approved()
        prev.write_private(self.fresh,self.snapshot)
        self.assertEqual(self.call('commit'),0)
        self.assertEqual(self.statefile.read_text(),'rolled_back')
        self.assertEqual(self.call('reconcile'),0)  # повторное чтение идемпотентно; фиксация транзакции не повторяется
        state = rb.state_load(self.journal,hashlib.sha256(self.cfgfile.read_bytes()).hexdigest(),
                              hashlib.sha256(self.cutfile.read_bytes()).hexdigest())
        self.assertEqual(state['phase'],'committed_fenced')
        cut.inspect_proxy(cut.Proxy(self.haproxy.path),self.cut,'closed')
        self.assertNotIn('ready', ' '.join(self.haproxy.commands))

    def test_changed_source_requires_explicit_reconciliation(self):
        self.prepare()
        broken = dict(self.snapshot, worldSha256='f'*64)
        prev.write_private(self.source,broken)
        self.assertEqual(self.call('plan'),2)
        self.assertFalse((self.journal/'rollback-plan-result.json').exists())

    def test_backend_blockers_cannot_be_overridden(self):
        self.prepare()
        with patch.dict(os.environ,{'FAIL_ROLLBACK_PLAN':'1'}):
            self.assertEqual(self.call('plan'),2)
        self.assertEqual(self.statefile.read_text(),'active')

    def test_new_world_writes_after_plan_block_commit(self):
        self.approved()
        prev.write_private(self.fresh,dict(self.snapshot,worldSha256='f'*64))
        self.assertEqual(self.call('commit'),2)
        self.assertEqual(self.statefile.read_text(),'active')

    def test_source_writers_unmasked_block_plan(self):
        self.prepare()
        with patch.object(rb,'systemd_state',return_value={'ActiveState':'inactive','SubState':'dead','UnitFileState':'enabled'}):
            self.assertEqual(self.call('plan'),2)
        self.assertFalse((self.journal/'rollback-plan-result.json').exists())

    def test_reconciliation_requires_actual_matching_source_export(self):
        self.prepare()
        self.cfg['reconciliationEvidenceSha256']='f'*64
        prev.write_private(self.cfgfile,self.cfg)
        prev.write_private(self.current,dict(self.snapshot,worldSha256='f'*64))
        self.assertEqual(self.call('plan'),2)
        self.assertFalse((self.journal/'rollback-plan-result.json').exists())

    def test_uncertain_commit_requires_readback_not_retry(self):
        self.approved()
        prev.write_private(self.fresh,self.snapshot)
        with patch.dict(os.environ,{'FAIL_AFTER_ROLLBACK_COMMIT':'1'}):
            self.assertEqual(self.call('commit'),2)
        self.assertEqual(self.statefile.read_text(),'rolled_back')
        self.assertEqual(self.call('commit'),2)
        self.assertEqual(self.call('reconcile'),0)
        cut.inspect_proxy(cut.Proxy(self.haproxy.path),self.cut,'closed')

    def test_stale_plan_and_proxy_restart_block(self):
        self.approved()
        prev.write_private(self.fresh,self.snapshot)
        state=rb.state_load(self.journal,hashlib.sha256(self.cfgfile.read_bytes()).hexdigest(),
                             hashlib.sha256(self.cutfile.read_bytes()).hexdigest())
        rb.change(self.journal,state,'planned',plannedAtUnix=state['plannedAtUnix']-1000)
        self.assertEqual(self.call('commit'),2)
        with patch.object(cut.Proxy,'instance',return_value='9999'):
            self.assertEqual(self.call('commit'),2)
        self.assertEqual(self.statefile.read_text(),'active')

    def test_cutover_config_tamper_blocks(self):
        self.cut['baselineRevision']=99
        prev.write_private(self.cutfile,self.cut)
        self.assertEqual(self.call('fence'),2)

    def test_snapshot_digest_matches_go_layout(self):
        compact = json.dumps(self.snapshot, separators=(',',':')).encode()
        self.assertEqual(rb.typed_digest(self.snapshot),hashlib.sha256(compact).hexdigest())


if __name__ == '__main__':
    unittest.main()
