import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inventory_0501 import MATRIX_SCHEMA, REQUIRED, TARGETS, EXPECTED_VERSION, validate_report

TOOL = Path(__file__).with_name('inventory_0501.py')

def fixture(os_name='linux', arch='x86_64'):
    checks = [
        {'id': name, 'status': ('UNSUPPORTED' if os_name != 'windows' and name.startswith('sensor.') else 'BLOCKED'), 'detail': 'not exercised'}
        for name in sorted(REQUIRED | {f"loader.runtime.{loader}" for loader in ("vanilla", "fabric", "quilt", "forge", "neoforge")})
    ]
    return {'schema': 'guard/local-inventory/v1', 'productVersion': EXPECTED_VERSION,
            'os': os_name, 'architecture': arch, 'javaMajor': 21,
            'minecraftVersion': None, 'loader': None,
            'checks': checks, 'status': 'BLOCKED'}

class Inventory0501Tests(unittest.TestCase):
    def test_accepts_truthful_blocked_native_report(self):
        self.assertEqual(validate_report(fixture())['status'], 'BLOCKED')

    def test_rejects_missing_check(self):
        obj = fixture()
        obj['checks'].pop()
        with self.assertRaises(ValueError): validate_report(obj)

    def test_rejects_duplicate_check(self):
        obj = fixture()
        obj['checks'].append(obj['checks'][0])
        with self.assertRaises(ValueError): validate_report(obj)

    def test_rejects_forged_game_pass(self):
        obj = fixture('windows')
        next(x for x in obj['checks'] if x['id'] == 'minecraft.real-join')['status'] = 'PASS'
        with self.assertRaises(ValueError): validate_report(obj)

    def test_rejects_windows_sensor_without_game(self):
        obj = fixture('windows')
        next(x for x in obj['checks'] if x['id'] == 'sensor.jvm-awareness')['status'] = 'PASS'
        with self.assertRaises(ValueError): validate_report(obj)

    def test_rejects_runtime_loader_without_game(self):
        obj = fixture()
        next(x for x in obj['checks'] if x['id'] == 'loader.runtime.fabric')['status'] = 'PASS'
        with self.assertRaises(ValueError): validate_report(obj)

    def test_rejects_non_windows_sensor_pass(self):
        obj = fixture()
        next(x for x in obj['checks'] if x['id'] == 'sensor.jvm-awareness')['status'] = 'PASS'
        with self.assertRaises(ValueError): validate_report(obj)

    def test_matrix_does_not_invent_missing_os_arch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = root / 'report.json'
            report.write_text(json.dumps(fixture()))
            matrix = root / 'matrix.json'
            proc = subprocess.run([sys.executable, str(TOOL), 'matrix', '--output', str(matrix), str(report)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(matrix.read_text())
            self.assertEqual(result['schema'], MATRIX_SCHEMA)
            self.assertEqual(len(result['targets']), len(TARGETS))
            self.assertFalse(result['certified'])
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(sum(row['reason'] == 'Отсутствует отчёт нативного исполняющего компонента' for row in result['targets']), len(TARGETS)-1)

    def test_matrix_rejects_duplicate_native_platform(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src = root / 'one.json'
            src.write_text(json.dumps(fixture()))
            proc = subprocess.run([sys.executable, str(TOOL), 'matrix', '--output', str(root / 'matrix.json'), str(src), str(src)], capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)

if __name__ == '__main__':
    unittest.main()
