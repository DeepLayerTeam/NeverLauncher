"""Регрессионные тесты промышленной физической эксплуатации HA/DR 0.52.10.

Тестовые заменители проверяют только обработку ошибок; они НЕ являются физическими свидетельствами.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

import physical_ha_dr_05210 as physical
import dependency_ha_0513 as dependency


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        self.home.chmod(0o700)
        self.secret = self.home / 'bmc-token'
        self.secret.write_text('0123456789abcdef0123456789abcdef')
        self.secret.chmod(0o600)
        self.args = argparse.Namespace(
            mode='host', node=['a=user@node-a.test', 'b=user@node-b.test'],
            victim='a', project='launcher', directory='/opt/launcher/deploy/production',
            remote_script='/opt/launcher/scripts/operations/multi_host_0512.py',
            edge_url='https://edge.test/ready', redfish_url='https://bmc.test/redfish/v1/Systems/1',
            bmc_token_file=str(self.secret), bmc_ca='/etc/ssl/cert.pem',
            expected_serial='hardware-SN-1234', router='router@router.test',
            victim_ip='10.14.0.11', victim_port=443, ttl=190, timeout=120,
            alertmanager_url='https://alerts.test', delivery_url='https://notifications.test/events/current',
            alert_name='LauncherNodeUnavailable',
            allow_disruption='I-ACCEPT-PHYSICAL-OUTAGE',
            state=str(self.home / 'state.json'), report=str(self.home / 'report.json'),
            heal_mode='host', world_backup='', world_destination='', game_start='',
            game_stop='', game_config='', rcon_password_file='', expected_player='',
            marker_xyz='', marker_block='', source_fenced=True,
            ha_env_file='', ha_socket='/tmp/ha.sock', service='', backend_server='', target='')

    def test_private_journal_is_exclusive_and_durable(self):
        path = self.home / 'journal'
        physical.save(path, {'schema': physical.SCHEMA, 'phase': 'intent'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(physical.read_json(path)['phase'], 'intent')
        with self.assertRaises(FileExistsError):
            physical.save(path, {'status': 'fake-PASS'})
        self.home.chmod(0o755)
        with self.assertRaises(physical.Blocked):
            physical.save(self.home / 'second', {})

    def test_private_input_rejects_symlink_and_hardlink(self):
        self.assertEqual(len(physical.private_bytes(self.secret)), 32)
        link = self.home / 'alias'; link.symlink_to(self.secret)
        with self.assertRaises(physical.Blocked):
            physical.private_bytes(link)
        hard = self.home / 'hard'; os.link(self.secret, hard)
        with self.assertRaises(physical.Blocked):
            physical.private_bytes(self.secret)

    def test_reject_unsafe_bmc_endpoint(self):
        for url in ('http://bmc.test/redfish/v1/Systems/1',
                    'https://bmc.test/redfish/v1/Chassis/1',
                    'https://user:pass@bmc.test/redfish/v1/Systems/1',
                    'https://127.0.0.1/redfish/v1/Systems/1',
                    'https://bmc.test/redfish/v1/Systems/1#fragment'):
            with self.subTest(url=url), self.assertRaises(physical.Blocked):
                physical.redfish_parts(url)

    def test_reject_incorrect_hardware_serial(self):
        with patch.object(physical, 'redfish', return_value={'PowerState':'On','SerialNumber':'other'}):
            with self.assertRaises(physical.Blocked):
                physical.bmc_status(self.args)

    def test_bmc_only_accepts_supported_power_transitions(self):
        info = {'PowerState':'On', 'SerialNumber':self.args.expected_serial,
                'Actions':{'#ComputerSystem.Reset':{'ResetType@Redfish.AllowableValues':['GracefulRestart']}}}
        with patch.object(physical, 'redfish', return_value=info) as request:
            with self.assertRaises(physical.Blocked):
                physical.bmc_reset(self.args, 'ForceOff')
            self.assertEqual(request.call_count, 1)
        info['Actions']['#ComputerSystem.Reset']['ResetType@Redfish.AllowableValues'].append('ForceOff')
        with patch.object(physical, 'redfish', side_effect=[info, {'accepted':True}]) as request:
            self.assertTrue(physical.bmc_reset(self.args, 'ForceOff')['accepted'])
            self.assertEqual(request.call_args.args[3], 'POST')

    @staticmethod
    def nft_table(valid=True):
        return json.dumps({'nftables': [
          {'set':{'name':'victims4','flags':['timeout'],'type':'ipv4_addr'}},
          {'chain':{'name':'forwarding','hook':'forward'}},
          {'rule':{'chain':'forwarding','expr':[{'match': {'left':{'payload':{'field':'saddr'}},'right':{'set':'victims4'}}},{'drop':None}]}},
          {'rule':{'chain':'forwarding','expr':[{'match': {'left':{'payload':{'field':'daddr'}},'right':{'set':'victims4'}}},{'drop':None}]}}
        ] if valid else [{'chain':{'name':'forwarding','hook':'input'}}]})

    def test_partition_requires_verified_ttl_forwarding_policy(self):
        calls = []
        def remote(target, cmd, **kw):
            calls.append(cmd)
            if 'table' in cmd:
                return self.nft_table()
            if 'add' in cmd or 'delete' in cmd:
                return ''
            if 'set' in cmd:
                return json.dumps({'nftables':[{'set':{'name':'victims4','flags':['timeout'],
                    'elem':[{'elem':{'val': '10.14.0.11', 'timeout': 180000}}]}}]})
            raise AssertionError(cmd)
        with patch.object(physical, 'ssh', side_effect=remote):
            self.assertTrue(physical.firewall(self.args, 'add'))
        self.assertTrue(any('add' in cmd for cmd in calls))
        self.assertTrue(any('timeout' in cmd for cmd in calls))

    def test_invalid_router_policy_never_injects(self):
        calls = []
        def remote(target, cmd, **kw):
            calls.append(cmd)
            return self.nft_table(False)
        with patch.object(physical, 'ssh', side_effect=remote):
            with self.assertRaises(physical.Blocked):
                physical.firewall(self.args, 'add')
        self.assertFalse(any('add' in cmd for cmd in calls))

    def test_healthy_survivor_does_not_override_missing_alert(self):
        with patch.object(physical, 'baseline', return_value={'a':{},'b':{}}), \
             patch.object(physical, 'bmc_status', return_value={'PowerState':'On'}), \
             patch.object(physical, 'bmc_reset'), \
             patch.object(physical, 'await_power', side_effect=[True,True]), \
             patch.object(physical, 'ssh', side_effect=['node-a', None]), \
             patch.object(physical, 'survivor', return_value={'survivors':{'b':True},'edgeSamples':[1]*8}), \
             patch.object(physical, 'alert_delivery', side_effect=physical.Blocked('no alert')):
            self.assertEqual(physical.main(['host','--state',self.args.state,
                '--report',self.args.report, '--node',self.args.node[0], '--node',self.args.node[1],
                '--victim','a','--edge-url',self.args.edge_url,
                '--redfish-url',self.args.redfish_url,'--bmc-token-file',self.args.bmc_token_file,
                '--bmc-ca',self.args.bmc_ca,'--expected-serial',self.args.expected_serial,
                '--allow-disruption',self.args.allow_disruption]), 3)
            self.assertTrue(Path(self.args.state).exists(), 'Журнал неподтверждённого сбоя должен сохраняться')

    def test_successful_power_drill_closes_journal_only_after_live_recovery(self):
        statuses = [{'PowerState':'On'}, {'PowerState':'On'}, {'PowerState':'On'}]
        with patch.object(physical, 'baseline', return_value={'a':{},'b':{}}), \
             patch.object(physical, 'bmc_status', side_effect=statuses), \
             patch.object(physical, 'bmc_reset'), \
             patch.object(physical, 'await_power', side_effect=[True, True]), \
             patch.object(physical, 'ssh', side_effect=['node-a', None]), \
             patch.object(physical, 'survivor', return_value={'survivors':{'b':True},'edgeSamples':[1]*8}), \
             patch.object(physical, 'alert_delivery', return_value={'fingerprint':'def'}):
            self.assertEqual(physical.live_fault(self.args), 0)
        self.assertFalse(Path(self.args.state).exists())
        self.assertEqual(physical.read_json(self.args.report)['status'], 'PASS')

    def test_heal_requires_same_original_host_identity(self):
        physical.save(Path(self.args.state), {'schema':physical.SCHEMA,
            'mode':'host','victim':'a','victimTarget':'user@node-a.test',
            'bmcUrl':self.args.redfish_url,'recoveryRequired':True})
        self.args.heal_mode = 'partition'
        with self.assertRaises(physical.Blocked):
            physical.heal(self.args)
        self.assertTrue(Path(self.args.state).exists())

    def test_world_recovery_requires_independent_fencing(self):
        self.args.source_fenced = False
        with self.assertRaises(physical.Blocked):
            physical.game_restore(self.args)

    def test_restores_actual_world_bytes_before_live_game_protocol(self):
        # Файловое восстановление использует промышленный алгоритм DR; имитируется
        # только внешний сокет Minecraft (без поддельных нативных свидетельств GA).
        from test_network_ha_recovery_0454 import make_world
        backup = make_world(self.home / 'backup')
        dest = self.home / 'restored-game'
        config = self.home / 'game.json'
        config.write_text(json.dumps({'serverDir': str(dest), 'minecraftVersion': '1.21.1',
                                      'minecraftPort': 25565, 'rconPort': 25575}))
        config.chmod(0o600)
        rconpw = self.home / 'rcon'
        rconpw.write_text('verylongtestpassword')
        rconpw.chmod(0o600)
        self.args.world_backup = str(backup)
        self.args.world_destination = str(dest)
        self.args.game_config = str(config)
        self.args.game_start = '/bin/true'
        self.args.game_stop = '/bin/true'
        self.args.rcon_password_file = str(rconpw)
        self.args.expected_player = 'RealPlayer'
        self.args.marker_xyz = '0 64 0'
        self.args.marker_block = 'minecraft:diamond_block'
        self.args.timeout = 5
        def rcon(*args):
            cmd = args[-1]
            if cmd == 'list': return 'There are 1 of 20 players online: RealPlayer'
            if cmd == 'time query gametime':
                if not hasattr(rcon, 'seen'):
                    rcon.seen = True
                    return '4200'
                return '4220'
            if cmd.startswith('execute if block '):
                return '[Server] ' + cmd.split()[-1]
            raise AssertionError(cmd)
        with patch.object(physical, 'bmc_status', return_value={'PowerState':'Off'}), \
             patch.object(physical.vanilla, 'status', return_value={'version':'1.21.1'}), \
             patch.object(physical.vanilla, 'rcon', side_effect=rcon), \
             patch.object(physical.time, 'sleep'):
            self.assertEqual(physical.game_restore(self.args), 0)
        self.assertEqual((dest/'world/region/r.0.0.mca').read_bytes(),
                         b'actual Minecraft region bytes')
        self.assertEqual(physical.read_json(self.args.report)['status'], 'PASS')
        self.assertEqual(physical.read_json(self.args.report)['gameStopped'], True)

    def test_peer_network_visibility_is_measured_on_survivors_not_bmc(self):
        targets = {'a':'ops@host-a', 'b':'ops@host-b'}
        with patch.object(physical, 'ssh', return_value='') as control:
            self.assertTrue(all(physical.peer_connectivity(self.args, targets, 'a').values()))
            self.assertEqual(control.call_args.args[0], 'ops@host-b')
            self.assertIn('socket.create_connection', control.call_args.args[1][2])
        with patch.object(physical, 'ssh', return_value=None):
            self.assertFalse(any(physical.peer_connectivity(self.args, targets, 'a').values()))

    def test_dependency_primary_cannot_pass_if_replica_was_stopped(self):
        baseline = {'ingress_nodes':{'a':'UP','b':'UP'},
                    'postgres_primary':{'pg-a':'UP','pg-b':'DOWN'},
                    'redis_primary':{'redis-a':'UP','redis-b':'DOWN'},
                    's3_gateways':{'s3-a':'UP','s3-b':'UP'}}
        with patch.object(dependency, 'stats', return_value=baseline), \
             patch.object(dependency, 'perform_verification', return_value={'healthy':True}):
            with self.assertRaises(dependency.HAError):
                dependency.drill(Path('/tmp/sock'),'https://edge.test',{},'patroni',
                                 'pg-b','operator@node-b',20,{'postgres':[('pg-b','10.0.2.12',5432)]})

if __name__ == '__main__':
    unittest.main()
