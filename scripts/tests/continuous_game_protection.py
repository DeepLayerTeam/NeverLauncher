#!/usr/bin/env python3
"""Настоящий процесс JDK проверяет независимый Java-монитор целостности 0.50.6.
Это НЕ реальный запуск Minecraft и не нативная сертификация Guard для ОС.
"""
import base64,hashlib,os,pathlib,shutil,subprocess,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
AGENT=ROOT/'sdk/java/trusted-agent/build/agent.jar'

def call(*args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    if p.returncode: raise RuntimeError(p.stderr)
    return p

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def b64(value): return base64.b64encode(str(value).encode()).decode()

class ContinuousJVM0506(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='nl-0506-jvm-')
        cls.temp=pathlib.Path(cls.tmp.name)
        sdk=ROOT/'sdk/java/trusted-agent'
        if os.name=='nt':
            classes=sdk/'build/classes';classes.mkdir(parents=True,exist_ok=True)
            src=sorted(map(str,(sdk/'src/main/java').rglob('*.java')))
            call('javac','--release','8','-encoding','UTF-8','-d',str(classes),*src)
            mf=sdk/'build/MANIFEST.MF';mf.write_text('Manifest-Version: 1.0\nPremain-Class: ru.launcher.trusted.Agent\n\n')
            call('jar','cfm',str(AGENT),str(mf),'-C',str(classes),'.')
        else: call('sh',str(sdk/'build.sh'))
        java=cls.temp/'src/fixture/Game.java';java.parent.mkdir(parents=True)
        java.write_text('''package fixture;
public class Game {
 public static void main(String[] args) throws Exception {
  System.out.println("GAME_STARTED");System.out.flush();
  if (args.length>0 && args[0].equals("interrupt-monitor")) {
   boolean found=false;
   for (Thread t : Thread.getAllStackTraces().keySet()) {
    if (t.getName().equals("launcher-runtime-integrity-0505")) {t.interrupt();found=true;}
   }
   if(!found) throw new IllegalStateException("монитор целостности не запущен");
  }
  Thread.sleep(args.length==0 ? 3500 : 9000);
 }
}''')
        classes=cls.temp/'classes';classes.mkdir()
        call('javac','--release','8','-d',str(classes),str(java))
        cls.jar=cls.temp/'game.jar';call('jar','cf',str(cls.jar),'-C',str(classes),'.')
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='nl-0506-launch-')
        self.base=pathlib.Path(self.tmp.name).resolve()
        self.agent=self.base/'agent.jar';self.game=self.base/'game.jar'
        shutil.copy2(AGENT,self.agent);shutil.copy2(self.jar,self.game)
        pins=[(self.agent,'code'),(self.game,'code')]
        config=[f'main={b64("fixture.Game")}', 'count=0','guard.policy.active=true',
                'transform.count=0','loader.id=vanilla','loader.count=0','loader.class.count=0',
                'integrity.required=true','integrity.code.strict=true',
                f'integrity.root={b64(self.base)}',f'integrity.count={len(pins)}']
        for i,(file,kind) in enumerate(pins):
            config.extend((f'integrity.{i}.path={b64(file)}',f'integrity.{i}.sha256={digest(file)}',f'integrity.{i}.kind={kind}'))
        self.config=self.base/'guard.properties';self.config.write_text('\n'.join(config)+'\n')
    def tearDown(self): self.tmp.cleanup()
    def run_game(self,*args):
        return subprocess.run(['java','-Dfile.encoding=UTF-8','-Dsun.stderr.encoding=UTF-8',f'-javaagent:{self.agent}={self.config}',
            '-cp',str(self.game),'ru.launcher.trusted.MinecraftMain',*args],
            capture_output=True,encoding="utf-8",timeout=15)
    def test_healthy_game_not_killed(self):
        result=self.run_game()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('GAME_STARTED',result.stdout)
    def test_interrupted_integrity_watcher_terminates_game(self):
        result=self.run_game('interrupt-monitor')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Контроль целостности остановился во время работы JVM',result.stderr)

if __name__=='__main__': unittest.main(verbosity=2)
