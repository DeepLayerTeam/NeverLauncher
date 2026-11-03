"""Tests for 0.51.3 edge and dependency failover executor."""
from __future__ import annotations

import copy
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

import dependency_ha_0513 as ha


class DependencyHATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.password = self.base / 'secret'
        self.password.write_text('strong-redis-secret-value\n')
        self.password.chmod(0o600)
        self.env = dict(
            HA_INTERFACE='eth1', HA_PUBLIC_VIP='10.0.0.100',
            HA_DEPENDENCY_VIP='10.0.0.101', HA_LB_LOCAL_IP='10.0.0.11',
            HA_LB_PEER_IP='10.0.0.12', HA_VIP_PREFIX='24',
            HA_PRIORITY='150', HA_VRRP_ID='51',
            HA_PUBLIC_NAME='launcher.example', HA_REDIS_NAME='redis-ha.internal',
            HA_S3_NAME='s3-ha.internal',
            HA_REDIS_HEALTH_USER='healthcheck',
            HA_REDIS_HEALTH_PASSWORD_FILE=str(self.password),
            HA_INGRESS='api-a@10.0.1.11:443,api-b@10.0.1.12:443',
            HA_POSTGRES='pg-a@10.0.2.11:5432,pg-b@10.0.2.12:5432',
            HA_REDIS='redis-a@10.0.3.11:6380,redis-b@10.0.3.12:6380',
            HA_S3='s3-a@10.0.4.11:443,s3-b@10.0.4.12:443',
            HA_S3_SHARED_BACKEND_CONFIRMED='yes',
        )

    def config(self):
        return ha.validate(self.env)

    def test_render_operational_pg_master_redis_master_s3_and_edge_checks(self):
        cfg = self.config()
        text = ha.generate_haproxy(cfg)
        self.assertIn('http-check send meth GET uri /primary', text)
        self.assertIn('tcp-check expect rstring role:master', text)
        self.assertIn('tcp-check send-binary ' + ha.resp('AUTH', 'healthcheck', 'strong-redis-secret-value'), text)
        self.assertIn('http-check send meth GET uri /minio/health/cluster', text)
        self.assertIn('http-check send meth GET uri /ready', text)
        self.assertIn('verifyhost launcher.example', text)
        self.assertIn('verifyhost redis-ha.internal', text)
        self.assertIn('verifyhost s3-ha.internal', text)
        self.assertIn('bind 10.0.0.100:443', text)
        self.assertIn('bind 10.0.0.101:5432', text)
        self.assertIn('bind 10.0.0.101:6380', text)
        self.assertIn('bind 10.0.0.101:443', text)
        keepalived = ha.generate_keepalived(cfg)
        self.assertIn('unicast_src_ip 10.0.0.11', keepalived)
        self.assertIn('10.0.0.12', keepalived)
        self.assertIn('track_script', keepalived)
        self.assertIn('net.ipv4.ip_nonlocal_bind', 'net.ipv4.ip_nonlocal_bind = 1')

    def test_reject_duplicate_nodes_vip_and_no_storage_cluster(self):
        cases = [
            ('HA_DEPENDENCY_VIP', '10.0.0.100'),
            ('HA_INGRESS', 'a@10.0.1.11:443,b@10.0.1.11:443'),
            ('HA_POSTGRES', 'a@10.0.1.11:5432'),
            ('HA_S3_SHARED_BACKEND_CONFIRMED', 'no'),
            ('HA_PUBLIC_NAME', 'bad name;inject'),
            ('HA_INTERFACE', 'eth0\nbackend evil'),
            ('HA_VRRP_ID', '999'),
            ('HA_REDIS_LISTEN_PORT', '0'),
            ('HA_S3_HEALTH_PATH', '/minio/health/cluster?bad=1'),
        ]
        for key, value in cases:
            test_env = {**self.env, key: value}
            with self.subTest(key=key), self.assertRaises(ha.HAError):
                ha.validate(test_env)

    def test_reject_open_secret_and_symlink(self):
        self.password.chmod(0o644)
        with self.assertRaises(ha.HAError):
            self.config()
        self.password.chmod(0o600)
        alias = self.base / 'alias'
        alias.symlink_to(self.password)
        self.env['HA_REDIS_HEALTH_PASSWORD_FILE'] = str(alias)
        with self.assertRaises(ha.HAError):
            self.config()

    def test_env_never_executes_shell_code(self):
        path = self.base / 'env'
        path.write_text('HA_INTERFACE=$(touch /tmp/should-never-be-run)\n')
        path.chmod(0o600)
        self.assertEqual(ha.load_env(path)['HA_INTERFACE'], '$(touch /tmp/should-never-be-run)')
        with self.assertRaises(ha.HAError):
            ha.validate({**self.env, 'HA_INTERFACE': ha.load_env(path)['HA_INTERFACE']})

    def test_atomic_new_file_only_and_permissions(self):
        out = self.base / 'output'
        out.mkdir()
        report = ha.render(self.config(), out)
        self.assertTrue(report['configured'])
        self.assertEqual(len(report['files']), 3)
        self.assertEqual(stat.S_IMODE((out / 'haproxy.launcher-0513.cfg').stat().st_mode), 0o600)
        with self.assertRaises(ha.HAError):
            ha.render(self.config(), out)
        self.assertIn('strong-redis-secret-value'.encode().hex(), (out / 'haproxy.launcher-0513.cfg').read_text())
        self.assertNotIn('strong-redis-secret-value', str(report))

    def test_live_health_required_and_two_writers_rejected(self):
        s = {'ingress_nodes': {'a': 'UP', 'b': 'UP'},
             'postgres_primary': {'a': 'UP', 'b': 'DOWN'},
             'redis_primary': {'a': 'DOWN', 'b': 'UP'},
             's3_gateways': {'a': 'UP', 'b': 'UP'}}
        self.assertTrue(ha.health(s)['healthy'])
        s['postgres_primary']['b'] = 'UP'
        self.assertFalse(ha.health(s)['healthy'])
        self.assertTrue(any('split-brain' in x for x in ha.health(s)['issues']))
        s['postgres_primary']['b'] = 'DOWN'
        s['s3_gateways']['a'] = 'DOWN'
        self.assertFalse(ha.health(s, redundant=True)['healthy'])
        self.assertTrue(ha.health(s, redundant=False)['healthy'])
        s['redis_primary']['b'] = 'DOWN'
        self.assertFalse(ha.health(s, redundant=False)['healthy'])

    def test_mock_live_socket_stats_parse(self):
        csv = b'# pxname,svname,status\ningress_nodes,a,UP\ningress_nodes,b,UP\npostgres_primary,p1,UP\nredis_primary,r1,UP\ns3_gateways,s1,UP\ns3_gateways,s2,UP\n'
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def settimeout(self, n): pass
            def connect(self, path): pass
            def sendall(self, data): self.sent = data
            def recv(self, n):
                if not hasattr(self, 'read'):
                    self.read = True
                    return csv
                return b''
        with patch.object(ha.socket, 'socket', return_value=Conn()):
            result = ha.stats(Path('/run/haproxy/launcher-ha.sock'))
        self.assertTrue(ha.health(result)['healthy'])

    def test_sigv4_signed_headers_never_place_secret_in_request(self):
        import datetime
        credentials = {'access': 'EXAMPLEACCESSKEY', 'secret': 'EXAMPLESECRETKEY',
                       'region': 'eu-west-1', 'token': ''}
        instant = datetime.datetime(2026, 11, 3, 12, 0, tzinfo=datetime.timezone.utc)
        a = ha.aws_sigv4('PUT', '/launcher/launcher-ha-probe-0513/key',
                         's3-ha.internal', b'hello', credentials, instant)
        b = ha.aws_sigv4('PUT', '/launcher/launcher-ha-probe-0513/key',
                         's3-ha.internal', b'hello', credentials, instant)
        self.assertEqual(a, b)
        self.assertEqual(a['x-amz-date'], '20261103T120000Z')
        self.assertNotIn(credentials['secret'], str(a))
        self.assertIn('Signature=', a['Authorization'])

    def test_cross_gateway_s3_content_and_cleanup(self):
        gateways = [('a', '10.0.1.1', 443), ('b', '10.0.1.2', 443)]
        data = {}
        def request(cfg, creds, gateway, method, key, payload=b''):
            if method == 'PUT':
                data[key] = payload
                return 200, b''
            if method == 'GET':
                if gateway[0] == 'b' and getattr(request, 'corrupt', False):
                    return 200, b'corrupted'
                return (200, data[key]) if key in data else (404, b'')
            if method == 'DELETE':
                data.pop(key, None)
                return 204, b''
            raise AssertionError('unexpected method')
        with patch.object(ha, 's3_request', side_effect=request):
            report = ha.s3_object_probe(self.config(), {}, gateways)
            self.assertTrue(report['crossGatewayReadBack'])
            self.assertEqual(data, {})
            request.corrupt = True
            with self.assertRaisesRegex(ha.HAError, 'mismatched'):
                ha.s3_object_probe(self.config(), {}, gateways)
            self.assertEqual(data, {})

    def test_edge_drill_requires_real_vip_transfer_and_restoration(self):
        state = {'initial': True}
        calls = []
        stable = {'ingress_nodes': {'a': 'UP', 'b': 'UP'},
                  'postgres_primary': {'a': 'UP'},
                  'redis_primary': {'a': 'UP'},
                  's3_gateways': {'a': 'UP', 'b': 'UP'}}
        def command(target, service, verb):
            calls.append(verb)
            state['initial'] = False
        with patch.object(ha, 'stats', return_value=stable), \
             patch.object(ha, 'local_owns_vip', side_effect=lambda *args: not state['initial']), \
             patch.object(ha, 'remote_owns_vip', return_value=True), \
             patch.object(ha, 'systemd_ssh', side_effect=command), \
             patch.object(ha, 'probe_edge', return_value=(True, {})), \
             patch.object(ha.time, 'sleep'):
            result = ha.edge_drill(Path('/tmp/sock'), 'https://launcher.example', {},
                                   self.config(), 'operator@lb-primary', 15)
        self.assertTrue(result['testPassed'])
        self.assertEqual(calls, ['stop', 'start'])

    def test_drill_restarts_after_failing_checks(self):
        baseline = {'ingress_nodes': {'api-a': 'UP', 'api-b': 'UP'},
                    'postgres_primary': {'pg-a': 'UP', 'pg-b': 'DOWN'},
                    'redis_primary': {'redis-a': 'UP', 'redis-b': 'DOWN'},
                    's3_gateways': {'s3-a': 'UP', 's3-b': 'UP'}}
        during = copy.deepcopy(baseline)
        during['postgres_primary']['pg-a'] = 'DOWN'
        during['postgres_primary']['pg-b'] = 'UP'
        calls = []
        with patch.object(ha, 'stats', side_effect=[baseline, during, during]) as stats, \
             patch.object(ha, 'systemd_ssh', side_effect=lambda *args: calls.append(args)), \
             patch.object(ha, 'perform_verification', return_value={'healthy': True}), \
             patch.object(ha.time, 'sleep'):
            report = ha.drill(Path('/tmp/sock'), 'https://launcher.example', {}, 'patroni',
                              'pg-a', 'operator@hosta', 20)
        self.assertTrue(report['testPassed'])
        self.assertEqual([a[2] for a in calls], ['stop', 'start'])
        with patch.object(ha, 'stats', return_value=baseline), \
             patch.object(ha, 'systemd_ssh', side_effect=lambda *args: calls.append(args)), \
             patch.object(ha, 'perform_verification', side_effect=RuntimeError('interruption')):
            with self.assertRaises(RuntimeError):
                ha.drill(Path('/tmp/sock'), 'https://launcher.example', {}, 'patroni',
                         'pg-a', 'operator@hosta', 20)
        self.assertEqual(calls[-1][2], 'start')


if __name__ == '__main__':
    unittest.main()
