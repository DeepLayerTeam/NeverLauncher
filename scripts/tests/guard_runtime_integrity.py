#!/usr/bin/env python3
"""Исполняемая регрессия целостности JVM на реальных хешах файлов, отображениях памяти и изменениях во
время работы.
Только синтетическая игра и нативная библиотека; не сертификация сервера/входа Minecraft.
"""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
AGENT=ROOT/'sdk/java/trusted-agent/build/agent.jar'

def run(*cmd, timeout=40):
    result=subprocess.run(cmd,encoding='utf-8',capture_output=True,timeout=timeout)
    if result.returncode: raise RuntimeError(f'{cmd}: {result.stderr}')
    return result

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def b64(s): return base64.b64encode(str(s).encode()).decode()

class RuntimeIntegrityLive0505(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name == 'nt':
            sdk = ROOT/'sdk/java/trusted-agent'
            classes = sdk/'build/classes'; classes.mkdir(parents=True,exist_ok=True)
            sources = sorted(map(str, (sdk/'src/main/java').rglob('*.java')))
            run('javac','--release','8','-encoding','UTF-8','-d',str(classes),*sources)
            manifest = sdk/'build/MANIFEST.MF'
            manifest.write_text('Manifest-Version: 1.0\nPremain-Class: ru.launcher.trusted.Agent\n'
                                'Can-Retransform-Classes: false\nCan-Redefine-Classes: false\n\n')
            run('jar','cfm',str(AGENT),str(manifest),'-C',str(classes),'.')
        else:
            run('sh', str(ROOT/'sdk/java/trusted-agent/build.sh'))
        cls.tmp=tempfile.TemporaryDirectory(prefix='nl0505-jvm-')
        cls.base=Path(cls.tmp.name)
        source=cls.base/'source/fixture/Game.java';source.parent.mkdir(parents=True)
        source.write_text('''package fixture;
public class Game {
    public static void main(String[] args) throws Exception {
        System.out.println("GAME_STARTED");System.out.flush();
        if(args.length>0 && args[0].endsWith(".so")) System.load(args[0]);
        if(args.length>0) Thread.sleep(12500);
    }
}''', encoding='utf-8')
        cls.classes=cls.base/'classes';cls.classes.mkdir()
        run('javac','--release','8','-d',str(cls.classes),str(source))
        cls.jar=cls.base/'game.jar'
        run('jar','cf',str(cls.jar),'-C',str(cls.classes),'.')
        if sys.platform.startswith('linux') and shutil.which('gcc'):
            c=cls.base/'probe.c';c.write_text('int runtime_integrity_probe_0505(void){return 3;}\n')
            cls.native=cls.base/'libnative.so'
            run('gcc','-shared','-fPIC','-o',str(cls.native),str(c))
        else: cls.native=None

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='nl0505-game-')
        self.root=Path(self.work.name)
        self.agent=self.root/'agent.jar';shutil.copy2(AGENT,self.agent)
        self.game=self.root/'game.jar';shutil.copy2(self.jar,self.game)

    def tearDown(self): self.work.cleanup()

    def invoke(self, extra=(), optional=(), strict=True, args=(), external=()):
        pins=[(self.agent,'code'),(self.game,'code')]+list(optional)
        config=[f'main={b64("fixture.Game")}', 'count=0', 'guard.policy.active=true',
                'transform.count=0','loader.id=vanilla','loader.count=0',
                'loader.class.count=0', 'integrity.required=true',
                f'integrity.root={b64(self.root)}',f'integrity.code.strict={str(strict).lower()}',
                f'integrity.count={len(pins)}', f'integrity.external.count={len(external)}']
        for i,(path,kind) in enumerate(pins):
            config.extend((f'integrity.{i}.path={b64(path)}',f'integrity.{i}.sha256={digest(path)}',
                           f'integrity.{i}.kind={kind}'))
        for i,path in enumerate(external):
            config.extend((f'integrity.external.{i}.path={b64(path)}',
                           f'integrity.external.{i}.sha256={digest(path)}'))
        self.config=self.root/'guard.properties';self.config.write_text('\n'.join(config)+'\n')
        cmd=['java','-javaagent:'+str(self.agent)+'='+str(self.config),'-cp',
             os.pathsep.join([str(self.game)]+list(map(str,extra))),
             'ru.launcher.trusted.MinecraftMain']+list(map(str,args))
        return subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

    def finish(self, proc, timeout=20):
        try: out,err=proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill();proc.communicate();self.fail('Защищённая JVM не завершила работу')
        return proc.returncode,out,err

    def test_valid_signed_game(self):
        rc,out,err=self.finish(self.invoke())
        self.assertEqual(rc,0,err);self.assertIn('GAME_STARTED',out)

    def test_unlisted_runtime_classpath(self):
        unknown=self.root/'unexpected.jar';shutil.copy2(self.jar,unknown)
        rc,out,err=self.finish(self.invoke(extra=[unknown]))
        self.assertNotEqual(rc,0);self.assertIn('Путь классов не подписан',err)

    def test_wrong_initial_hash(self):
        proc=self.invoke(args=['wait'])
        # Premain загружает конфигурацию до main. Отказ после подмены файла
        # закреплённых ключей проверяется живым тестом ниже. Некорректный закреплённый
        # ключ проверяется отдельно.
        proc.kill();proc.communicate()
        self.config.write_text(self.config.read_text().replace(digest(self.game),'0'*64))
        cmd=['java','-javaagent:'+str(self.agent)+'='+str(self.config),'-cp',str(self.game),
             'ru.launcher.trusted.MinecraftMain']
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
        self.assertNotEqual(r.returncode,0)
        self.assertIn('Подписанный файл среды выполнения отсутствует или заменён',r.stderr)

    def test_live_jar_replacement(self):
        proc=self.invoke(args=['wait'])
        line=proc.stdout.readline().strip()
        self.assertEqual(line,'GAME_STARTED')
        self.game.write_bytes(b'untrusted replacement')
        rc,_,err=self.finish(proc,timeout=16)
        self.assertNotEqual(rc,0);self.assertIn('Подписанный файл среды выполнения отсутствует или заменён',err)

    def test_live_unapproved_mod(self):
        (self.root/'mods').mkdir()
        proc=self.invoke(args=['wait'])
        self.assertEqual(proc.stdout.readline().strip(),'GAME_STARTED')
        (self.root/'mods/injected.jar').write_bytes(b'unsigned')
        rc,_,err=self.finish(proc,timeout=16)
        self.assertNotEqual(rc,0);self.assertIn('Неутверждённый файл Runtime',err)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc'),'Linux /proc/maps+gcc required')
    def test_live_unapproved_mapped_native(self):
        lib=self.root/'libunlisted.so';shutil.copy2(self.native,lib)
        # Нативную библиотеку вне управляемого дерева /natives нельзя увидеть только
        # в дисковой инвентаризации; живая проверка /proc/self/maps обязана её
        # обнаружить.
        proc=self.invoke(args=[lib])
        rc,out,err=self.finish(proc,timeout=16)
        self.assertNotEqual(rc,0);self.assertIn('Неутверждённый загруженный нативный модуль',err)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc'),'Linux /proc/maps+gcc required')
    def test_live_authorized_native(self):
        lib=self.root/'libapproved.so';shutil.copy2(self.native,lib)
        proc=self.invoke(optional=[(lib,'native')],args=[lib])
        rc,out,err=self.finish(proc,timeout=18)
        self.assertEqual(rc,0,err);self.assertIn('GAME_STARTED',out)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc'), 'Требуется нативный слой защиты Linux')
    def test_external_native_unapproved_during_live_game(self):
        path=self.base/'unapproved-external-overlay.so'
        shutil.copy2(self.native,path)
        proc=self.invoke(args=[path]);rc,_,err=self.finish(proc,timeout=17)
        self.assertNotEqual(rc,0)
        self.assertIn('Неутверждённый внешний нативный модуль',err)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc'), 'Требуется нативный слой защиты Linux')
    def test_external_native_signed_and_pinned_allowed(self):
        path=self.base/'approved-external-overlay.so'
        shutil.copy2(self.native,path)
        proc=self.invoke(args=[path], external=[path])
        rc,out,err=self.finish(proc,timeout=18)
        self.assertEqual(rc,0,err)
        self.assertIn('GAME_STARTED',out)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc'), 'Требуется нативный слой защиты Linux')
    def test_external_native_replaced_during_game(self):
        path=self.base/'replace-external-overlay.so'
        shutil.copy2(self.native,path)
        proc=self.invoke(args=[path],external=[path])
        self.assertEqual(proc.stdout.readline().strip(),'GAME_STARTED')
        alternate=self.base/'replacement.so'
        alternate.write_bytes(b'not an approved ELF overlay')
        os.replace(alternate,path)
        rc,_,err=self.finish(proc,timeout=16)
        self.assertNotEqual(rc,0)
        self.assertIn('Внешний нативный модуль изменён',err)

if __name__=='__main__': unittest.main(verbosity=2)
