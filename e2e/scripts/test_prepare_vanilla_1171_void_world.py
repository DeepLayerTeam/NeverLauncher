#!/usr/bin/env python3
"""Регрессионные Python-тесты автономного преобразования пустого мира для версии 1.17.1."""
import importlib.util
import hashlib
import tempfile
import zipfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name('prepare-vanilla-1171-void-world.py')
spec = importlib.util.spec_from_file_location('void_world', MODULE)
world = importlib.util.module_from_spec(spec)
spec.loader.exec_module(world)


def sample(generator_type='minecraft:flat'):
    return {
        'Data': (10, {
            'WorldGenSettings': (10, {
                'seed': (4, -40000),
                'generate_features': (1, 1),
                'dimensions': (10, {
                    'minecraft:overworld': (10, {
                        'type': (8, 'minecraft:overworld'),
                        'generator': (10, {
                            'type': (8, generator_type),
                            'settings': (10, {
                                'biome': (8, 'minecraft:plains'),
                                'layers': (9, (10, [
                                    {'height': (3, 1), 'block': (8, 'minecraft:bedrock')},
                                    {'height': (3, 2), 'block': (8, 'minecraft:dirt')},
                                ])),
                                'structures': (10, {'structures': (10, {})}),
                                'features': (1, 1),
                            }),
                        }),
                    }),
                    'minecraft:the_nether': (10, {'type': (8, 'minecraft:the_nether')}),
                }),
            }),
        }),
    }


def unpack(data):
    reader = world.Reader(data)
    tag = reader.number('B')
    title = reader.name()
    result = reader.payload(tag)
    assert reader.pos == len(data)
    return tag, title, result


class VoidWorldTests(unittest.TestCase):
    def test_overworld_becomes_air_and_other_registry_data_is_preserved(self):
        before = b'\x0a' + world.encode_name('') + world.encode_payload(10, sample())
        after = world.prepare(before)
        tag, title, root = unpack(after)
        self.assertEqual((tag, title), (10, ''))
        data = root['Data'][1]
        settings = data['WorldGenSettings'][1]
        self.assertEqual(settings['seed'], (4, -40000))
        self.assertEqual(settings['generate_features'], (1, 0))
        dims = settings['dimensions'][1]
        self.assertEqual(dims['minecraft:the_nether'][1]['type'], (8, 'minecraft:the_nether'))
        generator = dims['minecraft:overworld'][1]['generator'][1]
        self.assertEqual(generator['settings'][1]['layers'], (9, (10, [
            {'height': (3, 1), 'block': (8, 'minecraft:air')}
        ])))
        self.assertEqual(generator['settings'][1]['structures'], (10, {'structures': (10, {})}))

    def test_non_flat_generator_refused(self):
        before = b'\x0a' + world.encode_name('') + world.encode_payload(10, sample('minecraft:noise'))
        with self.assertRaisesRegex(world.NBTError, 'плоский генератор, созданный сервером'):
            world.prepare(before)

    def test_corrupt_nbt_refused(self):
        before = b'\x0a' + world.encode_name('') + world.encode_payload(10, sample())
        with self.assertRaises(world.NBTError):
            world.prepare(before[:-15])

    def test_trailing_data_refused(self):
        before = b'\x0a' + world.encode_name('') + world.encode_payload(10, sample()) + b'\x00'
        with self.assertRaisesRegex(world.NBTError, 'Лишние данные в конце level.dat'):
            world.prepare(before)

    def test_missing_registry_refused(self):
        before = b'\x0a' + world.encode_name('') + world.encode_payload(10, {'Data': (10, {})})
        with self.assertRaisesRegex(world.NBTError, 'WorldGenSettings'):
            world.prepare(before)

    def test_1171_server_properties_use_normal_world_and_matching_witness(self):
        from staged_matching import MatchingServer
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'server.zip'
            with zipfile.ZipFile(bundle, 'w') as archive:
                archive.writestr('server.jar', b'fixture only, not a real server')
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            for version, expected in [('1.17.1', 'default'), ('1.17', 'flat')]:
                work = root / version
                work.mkdir()
                server = MatchingServer(work, 'java', 'cli', version, 'vanilla', '',
                                        bundle=str(bundle), bundle_sha=digest)
                server.prepare()
                props = dict(line.split('=', 1) for line in
                             (server.root / 'server.properties').read_text().splitlines())
                self.assertEqual(props['level-type'], expected)
                self.assertEqual(props['server-ip'], '127.0.0.1')
                self.assertEqual(props['enable-rcon'], 'true')
                self.assertEqual(props['rcon.port'], str(server.rcon_port))
                if version == '1.17.1':
                    self.assertEqual(props['level-seed'], '1')
        script = Path(__file__).with_name('run-vanilla-matching-e2e.sh').read_text()
        self.assertIn('run-vanilla-certification-case.sh', script)
        self.assertIn('matching_live_report.py', script)
        self.assertIn('--minecraft "$MINECRAFT_VERSION"', script)

if __name__ == '__main__':
    unittest.main()
