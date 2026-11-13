#!/usr/bin/env python3
"""Настоящие регрессии Linux/OpenJDK по политикам процессов и подписанным модам для 0.50.8.

Тесты процессов используют настоящую JVM и системные prctl/setpgid/RLIMIT_CORE. Они не утверждают
сертификацию реального входа Minecraft или нативной сборки Rust Guard.
"""
import base64
import ctypes
import hashlib
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / 'sdk/java/trusted-agent/build/agent.jar'


def run(*command):
    proc = subprocess.run(command, text=True, capture_output=True, timeout=40)
    if proc.returncode:
        raise RuntimeError(f'{command}: {proc.stderr}')


def encoded(text):
    return base64.b64encode(str(text).encode()).decode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def linux_harden():
    # PR_SET_NO_NEW_PRIVS — фактический системный вызов, используемый Linux
    # Runtime.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
    os.setpgid(0, 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


@unittest.skipUnless(sys.platform.startswith('linux'), 'Защита процесса только для Linux')
class RealLinuxJVM0508(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run('sh', str(ROOT / 'sdk/java/trusted-agent/build.sh'))
        cls.tmp = tempfile.TemporaryDirectory(prefix='nl-0508-java-')
        src = Path(cls.tmp.name) / 'src/fixture/Game.java'
        src.parent.mkdir(parents=True)
        src.write_text('''package fixture;
public class Game {
 public static void main(String[] a) throws Exception {
  System.out.println("GAME_STARTED");System.out.flush();
  if(a.length>0) Thread.sleep(6800);
 }
}''')
        classes = Path(cls.tmp.name) / 'classes'
        classes.mkdir()
        run('javac', '--release', '8', '-d', str(classes), str(src))
        cls.game = Path(cls.tmp.name) / 'game.jar'
        run('jar', 'cf', str(cls.game), '-C', str(classes), '.')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nl-0508-protected-')
        self.root = Path(self.temp.name)
        self.agent = self.root / 'agent.jar'
        self.game = self.root / 'game.jar'
        shutil.copy2(AGENT, self.agent)
        shutil.copy2(self.__class__.game, self.game)
        pins = [(self.agent, 'code'), (self.game, 'code')]
        config = [f'main={encoded("fixture.Game")}', 'count=0',
                  'guard.policy.active=true', 'transform.count=0',
                  'loader.id=vanilla', 'loader.count=0', 'loader.class.count=0',
                  'integrity.required=true', 'integrity.code.strict=true',
                  'integrity.linux.process.required=true',
                  f'integrity.root={encoded(self.root)}', f'integrity.count={len(pins)}']
        for i, (file, kind) in enumerate(pins):
            config += [f'integrity.{i}.path={encoded(file)}',
                       f'integrity.{i}.sha256={digest(file)}',
                       f'integrity.{i}.kind={kind}']
        self.config = self.root / 'config.properties'
        self.config.write_text('\n'.join(config) + '\n')

    def tearDown(self):
        self.temp.cleanup()

    def start(self, harden=True, extra=()):
        return subprocess.Popen(
            ['java', '-javaagent:' + str(self.agent) + '=' + str(self.config),
             '-cp', str(self.game), 'ru.launcher.trusted.MinecraftMain', *extra],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=linux_harden if harden else None,
        )

    def finish(self, process):
        try:
            return process.returncode, *process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail('Защищённый процесс Java не завершил работу')

    def test_hardened_real_jvm_passes(self):
        process = self.start()
        out, err = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, err)
        self.assertIn('GAME_STARTED', out)

    def test_unhardened_real_jvm_denied(self):
        process = self.start(harden=False)
        out, err = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('Guard Linux JVM', err)
        self.assertNotIn('GAME_STARTED', out)

    def test_hardened_game_detects_unauthorized_live_mod(self):
        moddir = self.root / 'mods'
        moddir.mkdir()
        process = self.start(extra=('hold',))
        self.assertEqual(process.stdout.readline().strip(), 'GAME_STARTED')
        (moddir / 'untrusted.jar').write_bytes(b'unapproved module')
        out, err = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('Неодобренный файл среды выполнения', err)

    def test_hardened_game_detects_signed_jar_mutation(self):
        process = self.start(extra=('hold',))
        self.assertEqual(process.stdout.readline().strip(), 'GAME_STARTED')
        self.game.write_bytes(b'replaced during game')
        out, err = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('Подписанный файл среды выполнения отсутствует или заменён', err)


if __name__ == '__main__':
    unittest.main(verbosity=2)
