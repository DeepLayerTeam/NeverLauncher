"""Исполняемые тесты сбоев и восстановления; имитированные вызовы Docker/SSH не считаются сертификацией HA."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import multi_host_chaos as chaos


class ChaosTests(unittest.TestCase):
    def fixture(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        home = Path(d.name)
        return home

    def args(self, home, fault='network-partition'):
        return argparse.Namespace(node=['a=ops@a.example.org', 'b=ops@b.example.org'],
            failed_node='a', fault=fault, state=str(home / 'fault.json'), report=str(home / 'out.json'),
            directory='/opt/launcher/deploy/production', project='launcher',
            edge_url='https://launcher.example.org/ready', timeout=15,
            multi_host_script='/opt/launcher/scripts/operations/multi_host.py',
            chaos_script='/opt/launcher/scripts/operations/multi_host_chaos.py',
            allow_disruption='I-ACCEPT-REAL-OUTAGE',
            approval_file='/opt/launcher/deploy/production/.chaos-approval-05110.json',
            alertmanager_url=None, alert_name='LauncherHostIngressDown', alert_timeout=45)

    def approval(self, home, expires=None):
        path = home / 'approval.json'
        path.write_text(json.dumps({'project': 'launcher', 'nodeId': 'node-a',
                'allow': ['network-partition'], 'expiresUtc': expires or
                        (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}))
        path.chmod(0o600)
        return path

    def test_rejects_unsafe_consent_and_private_file(self):
        home = self.fixture()
        file = self.approval(home)
        with patch.object(chaos.multi, 'resolved_compose', return_value={'nodeId': 'node-a'}):
            chaos.local_consent(home, 'launcher', file)
            file.chmod(0o644)
            with self.assertRaises(chaos.ChaosError):
                chaos.local_consent(home, 'launcher', file)
            file.chmod(0o600)
            file.write_text(file.read_text().replace('node-a', 'node-b'))
            with self.assertRaises(chaos.ChaosError):
                chaos.local_consent(home, 'launcher', file)
            self.approval(home, (datetime.now(timezone.utc)-timedelta(days=1)).isoformat())
            with self.assertRaises(chaos.ChaosError):
                chaos.local_consent(home, 'launcher', file)

    def test_real_disconnect_command_and_idempotent_heal(self):
        home = self.fixture()
        approval = self.approval(home)
        entries = {'api': ('a'*64, 'launcher_launcher'), 'worker': ('b'*64, 'launcher_launcher')}
        attached = {'api': True, 'worker': True}
        commands = []
        def cmd(args, timeout=40):
            commands.append(args)
            if args[:3] == ['docker','network','disconnect']:
                attached['api' if args[-1] == 'a'*64 else 'worker'] = False
            if args[:3] == ['docker','network','connect']:
                attached['api' if args[-1] == 'a'*64 else 'worker'] = True
            return ''
        def has(ident, network):
            return attached['api' if ident == 'a'*64 else 'worker']
        with patch.object(chaos.multi, 'resolved_compose', return_value={'nodeId': 'node-a'}), \
             patch.object(chaos, 'local_compose_id', side_effect=lambda d,p,r,**kwargs: entries[r]), \
             patch.object(chaos, 'local_network_aliases', side_effect=lambda cid,net,role: [role]), \
             patch.object(chaos, 'invoke', side_effect=cmd), \
             patch.object(chaos, 'inspect_network', side_effect=has):
            response = chaos.local_isolate(home, 'launcher', approval)
            self.assertTrue(response['partitionExecuted'])
            self.assertFalse(any(attached.values()))
            self.assertTrue(chaos.local_status(home, 'launcher')['partitionExecuted'])
            with self.assertRaises(chaos.ChaosError):
                chaos.local_isolate(home, 'launcher', approval)
            recovered = chaos.local_heal(home, 'launcher')
            self.assertTrue(recovered['healed'])
            self.assertTrue(all(attached.values()))
            self.assertFalse((home / '.multi-host-partition-05110.json').exists())
            self.assertEqual(len([c for c in commands if c[:3] == ['docker','network','disconnect']]),2)
            self.assertEqual(len([c for c in commands if c[:3] == ['docker','network','connect']]),2)
            self.assertTrue(all('--alias' in c for c in commands if c[:3] == ['docker','network','connect']))

    def test_partial_disconnect_failure_leaves_recoverable_journal(self):
        home = self.fixture()
        approved = self.approval(home)
        entries = {'api': ('a'*64, 'launcher_launcher'), 'worker': ('b'*64, 'launcher_launcher')}
        def fail_second(args, timeout=40):
            if args[-1] == 'b'*64:
                raise chaos.ChaosError('ошибка выполнения команды Docker')
            return ''
        with patch.object(chaos.multi, 'resolved_compose', return_value={'nodeId':'node-a'}), \
             patch.object(chaos, 'local_compose_id', side_effect=lambda d,p,r,**kwargs: entries[r]), \
             patch.object(chaos, 'local_network_aliases', side_effect=lambda cid,net,role: [role]), \
             patch.object(chaos, 'invoke', side_effect=fail_second):
            with self.assertRaises(chaos.ChaosError):
                chaos.local_isolate(home, 'launcher', approved)
        path = home / '.multi-host-partition-05110.json'
        self.assertEqual(chaos.read_state(path)['phase'], 'disconnecting')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_heal_cannot_reconnect_wrong_docker_identity(self):
        home = self.fixture()
        path = home / '.multi-host-partition-05110.json'
        chaos.save_new(path, {'schema':chaos.SCHEMA, 'project':'launcher', 'targets':[
            {'role':'api','container':'a'*64,'network':'launcher_launcher','aliases':['api']}]})
        with patch.object(chaos, 'local_compose_id', return_value=('b'*64,'launcher_launcher')):
            outcome = chaos.local_heal(home, 'launcher')
        self.assertFalse(outcome['healed'])
        self.assertTrue(path.exists())

    def test_detached_container_still_validated_and_reconnectable(self):
        home=self.fixture()
        project='launcher'
        identity='a'*64
        inspect=[{'Config': {'Labels': {'com.docker.compose.project':project,
                    'com.docker.compose.service':'api'}},
                  'NetworkSettings': {'Networks': {}}}]
        def fake(command, timeout=40):
            if command[:2] == ['docker','inspect']:
                return json.dumps(inspect)
            return identity
        with patch.object(chaos,'invoke',side_effect=fake):
            with self.assertRaises(chaos.ChaosError):
                chaos.local_compose_id(home,project,'api')
            cid, network=chaos.local_compose_id(home,project,'api',allow_detached=True)
        self.assertEqual((cid,network),(identity,'launcher_launcher'))
        inspect[0]['Config']['Labels']['com.docker.compose.service']='another'
        with patch.object(chaos,'invoke',side_effect=fake):
            with self.assertRaises(chaos.ChaosError):
                chaos.local_compose_id(home,project,'api',allow_detached=True)

    def test_preserves_compose_dns_aliases_for_recovery(self):
        raw = [{'NetworkSettings':{'Networks':{'launcher_launcher':
            {'Aliases':['api','launcher-api-1','a'*12]}}}}]
        with patch.object(chaos,'invoke',return_value=json.dumps(raw)):
            aliases = chaos.local_network_aliases('a'*64, 'launcher_launcher', 'api')
        self.assertIn('api', aliases)
        self.assertIn('launcher-api-1', aliases)
        raw[0]['NetworkSettings']['Networks']['launcher_launcher']['Aliases']=['api','--privileged']
        with patch.object(chaos,'invoke',return_value=json.dumps(raw)):
            with self.assertRaises(chaos.ChaosError):
                chaos.local_network_aliases('a'*64,'launcher_launcher','api')

    def test_remote_ssh_uses_strict_host_verification(self):
        with patch.object(chaos,'invoke',return_value=json.dumps({'schema':chaos.SCHEMA,'project':'launcher'})) as run:
            chaos.ssh_helper('ops@node-a.example', '/opt/chaos.py', '/opt/deploy', 'launcher', 'local-status')
            args = run.call_args.args[0]
            self.assertIn('StrictHostKeyChecking=yes', args)
            self.assertEqual(args[0], 'ssh')
            with self.assertRaises(chaos.ChaosError):
                chaos.ssh_helper('-ProxyCommand=bad', '/opt/chaos.py', '/opt/deploy', 'launcher', 'local-status')

    def test_host_stop_checks_physical_service_stop_and_restoration(self):
        home = self.fixture()
        args = self.args(home, 'host-stop')
        nodes = {'a':'ops@a.example.org','b':'ops@b.example.org'}
        calls = []
        def stop_start(*params):
            calls.append(params[-1]); return {'executed':True,'action':params[-1]}
        def observe(*a, **kw):
            return {'ready':False}
        with patch.object(chaos,'assert_baseline',return_value={'a':{},'b':{}}), \
             patch.object(chaos.multi,'remote_stop_start',side_effect=stop_start), \
             patch.object(chaos.multi,'remote_call',side_effect=observe), \
             patch.object(chaos,'edge_survivor_probe',return_value=([{'ingressReady':True}],{'b':True})):
            out = chaos.run_fault(args,nodes)
        self.assertEqual(out['status'],'PASS')
        self.assertTrue(out['recoveredAndVerified'])
        self.assertTrue(out['evidence']['faultObserved'])
        self.assertEqual(calls,['stop','start'])
        self.assertFalse(Path(args.state).exists())
        self.assertEqual(stat.S_IMODE(Path(args.report).stat().st_mode),0o600)

    def test_failed_survivor_preserves_fail_report_and_recovers(self):
        home = self.fixture()
        args = self.args(home, 'network-partition')
        nodes = {'a':'ops@a.example.org','b':'ops@b.example.org'}
        modes=[]
        def remote(*params, **kw):
            mode=params[-1]; modes.append(mode)
            if mode=='local-status':
                return {'partitionExecuted':True,'detachedRoles':['api','worker']}
            return {'healed':True}
        with patch.object(chaos,'assert_baseline',return_value={'a':{},'b':{}}), \
             patch.object(chaos,'ssh_helper',side_effect=remote), \
             patch.object(chaos,'edge_survivor_probe',side_effect=chaos.ChaosError('survivor failed')):
            report=chaos.run_fault(args,nodes)
        self.assertEqual(report['status'],'FAIL')
        self.assertTrue(report['recoveredAndVerified'])
        self.assertEqual(modes, ['local-isolate','local-status','local-heal'])
        self.assertNotIn('survivor failed',Path(args.report).read_text())

    def test_failed_recovery_keeps_journal_and_blocks_future_run(self):
        home=self.fixture()
        args=self.args(home,'host-stop')
        nodes={'a':'ops@a.example.org','b':'ops@b.example.org'}
        def stop(*params):
            if params[-1]=='start':
                raise chaos.multi.DeploymentError('failure')
            return {'action':'stop','executed':True}
        with patch.object(chaos,'assert_baseline',return_value={'a':{},'b':{}}), \
             patch.object(chaos.multi,'remote_stop_start',side_effect=stop), \
             patch.object(chaos.multi,'remote_call',return_value={'ready':False}), \
             patch.object(chaos,'edge_survivor_probe',return_value=([],{'b':True})):
            report=chaos.run_fault(args,nodes)
        self.assertFalse(report['recoveredAndVerified'])
        self.assertTrue(Path(args.state).exists())
        with self.assertRaises(chaos.ChaosError):
            chaos.run_fault(args,nodes)

    def test_manual_recover_uses_exact_original_nodes(self):
        home=self.fixture()
        args=self.args(home,'host-stop')
        nodes={'a':'ops@a.example.org','b':'ops@b.example.org'}
        chaos.save_new(Path(args.state), {'schema':chaos.SCHEMA,'project':'launcher',
                'nodes':nodes,'fault':'host-stop','failedNode':'a'})
        with patch.object(chaos.multi,'remote_stop_start',return_value={}) as restart, \
             patch.object(chaos,'assert_baseline',return_value={'a':{},'b':{}}):
            with self.assertRaises(chaos.ChaosError):
                chaos.manual_recover(args, {'a':'ops@wrong.example.org','b':'ops@b.example.org'})
            answer=chaos.manual_recover(args,nodes)
        self.assertEqual(answer['status'],'RECOVERED')
        self.assertEqual(restart.call_args.args[-1], 'start')
        self.assertFalse(Path(args.state).exists())

    def test_monitor_generation_real_prometheus_rules_and_tls_only(self):
        home=self.fixture()
        args=argparse.Namespace(node_url=['a=https://node-a.example.org/ready',
                                        'b=https://node-b.example.org/ready'],
            edge_url='https://launcher.example.org/ready', output_directory=str(home))
        res=chaos.render_monitor(args)
        self.assertEqual(res['targets'],2)
        conf=json.loads((home/'prometheus-05110.yml').read_text())
        rules=json.loads((home/'alerts-05110.yml').read_text())
        self.assertEqual(len(conf['scrape_configs']),2)
        self.assertEqual(conf['scrape_configs'][0]['params']['module'],['https_2xx_strict'])
        self.assertEqual({r['alert'] for r in rules['groups'][0]['rules']},
                {'LauncherHostIngressDown','LauncherInsufficientHealthyHosts',
                 'LauncherPublicIngressDown'})
        with self.assertRaises(chaos.ChaosError):
            chaos.render_monitor(args)
        args.node_url=['a=http://plaintext.example.org/ready','b=https://node-b.example.org/ready']
        with self.assertRaises(chaos.multi.DeploymentError):
            chaos.validate_node_urls(args.node_url)

    def test_repeatable_suite_collects_real_case_receipts_and_stops_on_failure(self):
        home=self.fixture()
        args=self.args(home)
        args.suite_directory=str(home)
        args.iterations=1
        nodes={'a':'ops@a.example.org','b':'ops@b.example.org'}
        calls=[]
        def fake(child, labels):
            calls.append((child.failed_node,child.fault))
            chaos.save_new(Path(child.report), {'status':'PASS'})
            return {'status':'PASS','recoveredAndVerified':True}
        with patch.object(chaos,'run_fault',side_effect=fake):
            result=chaos.run_suite(args,nodes)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(len(result['cases']),4)
        self.assertEqual(len(calls),4)
        self.assertEqual(len({r['sha256'] for r in result['cases']}),1)
        self.assertTrue((home/'suite-report.json').exists())
        with self.assertRaises(chaos.ChaosError):
            chaos.run_suite(args,nodes)

    def test_suite_failed_case_does_not_touch_following_nodes(self):
        home=self.fixture()
        args=self.args(home)
        args.suite_directory=str(home)
        args.iterations=2
        calls=[]
        def fail(child, nodes):
            calls.append(child.failed_node)
            chaos.save_new(Path(child.report), {'status':'FAIL'})
            return {'status':'FAIL','recoveredAndVerified':False}
        with patch.object(chaos,'run_fault',side_effect=fail):
            result=chaos.run_suite(args, {'a':'ops@a.example.org','b':'ops@b.example.org'})
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(calls,['a'])
        self.assertEqual(len(result['cases']),1)

    def test_alertmanager_active_response_and_safe_origin(self):
        class MockResponse:
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def read(self,n): return json.dumps([{'labels':{'alertname':'LauncherHostIngressDown'},
                        'status':{'state':'active'}}]).encode()
        class Opener:
            def open(self, url, timeout): return MockResponse()
        with patch.object(chaos.urllib.request,'build_opener',return_value=Opener()):
            self.assertTrue(chaos.alertmanager_observe('https://alerts.example.org',
                    'LauncherHostIngressDown',deadline=1))
            with self.assertRaises(chaos.multi.DeploymentError):
                chaos.alertmanager_observe('http://alerts.example.org','LauncherHostIngressDown')
            with self.assertRaises(chaos.ChaosError):
                chaos.alertmanager_observe('https://alerts.example.org','../secret')


if __name__=='__main__':
    unittest.main()
