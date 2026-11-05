#!/usr/bin/env python3
"""Утверждения по реальной объединённой конфигурации Docker Compose для 0.45.5.

Запускать через docker compose config --format json. Одного статического overlay YAML недостаточно:
extends/merge Compose может незаметно сохранить общие тома.
"""
import json
import sys
import unittest
from pathlib import Path


COMPOSE_JSON = Path(sys.argv[1]) if len(sys.argv) > 1 else None

class MultiNodeHA0455(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = json.loads(COMPOSE_JSON.read_text(encoding='utf-8'))
        cls.services = cls.cfg['services']

    def test_four_replicas_are_real(self):
        for name, role in [('api', 'api'), ('api-b', 'api'), ('worker-a', 'worker'), ('worker-b', 'worker')]:
            s = self.services[name]
            self.assertEqual(s['environment']['LAUNCHER_PROCESS_ROLE'], role)
            self.assertEqual(s['environment']['LAUNCHER_DEPLOYMENT_MODE'], 'network-ha')
            self.assertEqual(s['environment']['LAUNCHER_DATABASE_AUTO_MIGRATE'], 'false')
            self.assertEqual(s['environment']['LAUNCHER_STORAGE_DRIVER'], 's3')
            self.assertEqual(s['environment']['LAUNCHER_SERVERBRIDGE_HA_REQUIRED'], 'true')
            self.assertTrue(s['environment']['LAUNCHER_REDIS_URL'].startswith('redis://:'))
            self.assertEqual(s['environment']['LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH'], '')
            self.assertTrue(s.get('restart'))

    def test_unique_owners_and_private_working_volumes(self):
        owners = [self.services[n]['environment']['LAUNCHER_REPLICA_ID'] for n in ['api','api-b','worker-a','worker-b']]
        self.assertEqual(len(set(owners)), 4)
        for target in ['/var/lib/launcher/storage', '/var/lib/launcher/backups', '/var/lib/launcher/factory', '/var/lib/launcher/coordinator']:
            sources = []
            for n in ['api','api-b','worker-a','worker-b']:
                matches = [v['source'] for v in self.services[n]['volumes'] if v['target']==target]
                self.assertEqual(len(matches),1,(n,target,matches))
                sources.append(matches[0])
            self.assertEqual(len(set(sources)), 4, (target,sources))

    def test_healthchecks_and_no_public_worker_ports(self):
        for n in ['api','api-b','worker-a','worker-b']:
            s = self.services[n]
            self.assertIn('healthcheck',s,n)
            self.assertFalse(s.get('ports'),n)
        for n in ['worker-a','worker-b']:
            self.assertFalse(self.services[n].get('expose') and 'public' in self.services[n]['expose'])
        nginx = self.services['nginx']
        self.assertTrue(any(v['target']=='/etc/nginx/conf.d/default.conf' and v['source'].endswith('nginx.network-ha.conf') for v in nginx['volumes']))


if __name__ == '__main__':
    file_arg = sys.argv[1]
    sys.argv = [sys.argv[0]]
    unittest.main()
