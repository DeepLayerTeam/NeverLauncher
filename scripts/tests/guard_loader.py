#!/usr/bin/env python3
"""Проверка настоящей интеграции JVM-агента/загрузчика с источником классов на синтетических JAR.
Это не E2E Minecraft или upstream-загрузчика.
"""
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
AGENT = REPO / 'sdk/java/trusted-agent/build/agent.jar'
MARKERS = {
    'fabric': 'net.fabricmc.loader.impl.launch.knot.KnotClient',
    'quilt': 'org.quiltmc.loader.impl.launch.knot.KnotClient',
    'forge': 'net.minecraftforge.fml.loading.FMLLoader',
    'neoforge': 'net.neoforged.fml.loading.FMLLoader',
    'modlauncher': 'cpw.mods.modlauncher.Launcher',
    'mixin': 'org.spongepowered.asm.mixin.transformer.MixinTransformer',
}


def cmd(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=35)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stdout} {result.stderr}')
    return result


class GuardLoaderLiveJVM0504(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cmd('sh', str(REPO/'sdk/java/trusted-agent/build.sh'))
        cls.temp = tempfile.TemporaryDirectory(prefix='nl0504-')
        cls.root = Path(cls.temp.name)
        cls.jars = {}
        for key, clsname in dict(MARKERS, game='fixture.Main').items():
            if key == 'game':
                source = f'package fixture; public class Main {{ public static void main(String[] args) throws Exception {{ Class.forName(args[0]); System.out.println("GAME_MAIN_OK"); }} }}'
            else:
                package, _, name = clsname.rpartition('.')
                source = f'package {package}; public class {name} {{}}'
            sources = cls.root / key / 'src'
            classes = cls.root / key / 'classes'
            filename = sources / (clsname.replace('.', '/')+'.java')
            filename.parent.mkdir(parents=True, exist_ok=True)
            classes.mkdir(parents=True, exist_ok=True)
            filename.write_text(source, encoding='utf-8')
            cmd('javac', '--release', '8', '-d', str(classes), str(filename))
            archive = cls.root / (key + '.jar')
            cmd('jar', 'cf', str(archive), '-C', str(classes), '.')
            cls.jars[key] = archive

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, loader, marker, authorized, available=None, corrupt=False, class_sha=None):
        config = [
            'main='+base64.b64encode(b'fixture.Main').decode(), 'count=0',
            'guard.policy.active=true', 'transform.count=0', 'loader.id='+loader,
            'loader.count='+str(len(authorized)),
        ]
        for i, key in enumerate(authorized):
            file = self.jars[key]
            checksum = hashlib.sha256(file.read_bytes()).hexdigest()
            if corrupt and i == 0:
                checksum = '0'*64
            config.extend((f'loader.{i}.path='+base64.b64encode(str(file).encode()).decode(),
                           f'loader.{i}.sha256='+checksum))
        if class_sha is not None:
            config.extend(('loader.class.count=1',
                           'loader.class.0.name='+base64.b64encode(b'fixture.Main').decode(),
                           'loader.class.0.sha256='+class_sha))
        with tempfile.TemporaryDirectory(prefix='nl0504-conf-') as tmp:
            path = Path(tmp) / 'agent.properties'
            path.write_text('\n'.join(config)+'\n', encoding='ascii')
            names = authorized if available is None else available
            cp = os.pathsep.join(str(self.jars[name]) for name in (['game']+list(names)))
            args = ['java','-javaagent:'+str(AGENT)+'='+str(path),'-cp',str(AGENT)+os.pathsep+cp,
                    'ru.launcher.trusted.MinecraftMain',MARKERS[marker]]
            return subprocess.run(args, capture_output=True, text=True, timeout=30)

    def test_authorized_loader_and_mixin(self):
        for loader in ('fabric','quilt','forge','neoforge'):
            signed=[loader,'mixin']+(['modlauncher'] if loader in ('forge','neoforge') else [])
            for marker in signed:
                with self.subTest(loader=loader, marker=marker):
                    result=self.invoke(loader,marker,signed)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn('GAME_MAIN_OK',result.stdout)

    def test_pinned_class_bytes_are_checked_in_live_jvm(self):
        path=self.root/'game/classes/fixture/Main.class'
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        good=self.invoke('fabric','fabric',['fabric'],class_sha=digest)
        self.assertEqual(good.returncode,0,good.stderr)
        wrong=self.invoke('fabric','fabric',['fabric'],class_sha='0'*64)
        self.assertNotEqual(wrong.returncode,0)
        self.assertIn('Байткод классов загрузчика не совпадает',wrong.stderr)

    def test_reject_wrong_loader(self):
        result=self.invoke('fabric','quilt',['quilt'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('loader mismatch',result.stderr)

    def test_reject_unpinned_class_source(self):
        result=self.invoke('fabric','fabric',['mixin'],available=['mixin','fabric'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('not operator-authorized',result.stderr)

    def test_reject_missing_loader_binding(self):
        result=self.invoke('fabric','fabric',[],available=['fabric'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Исходники загрузчика отсутствуют',result.stderr)

    def test_reject_vanilla_mixin(self):
        result=self.invoke('vanilla','mixin',[],available=['mixin'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('loader mismatch',result.stderr)

    def test_reject_tampered_loader_before_main(self):
        result=self.invoke('fabric','fabric',['fabric'],corrupt=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Хеш JAR-файла загрузчика изменился',result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
