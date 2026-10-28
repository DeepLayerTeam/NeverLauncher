import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from staged_readiness_0343 import (StartupObserver, capture_menu, find_window,
                                   is_descendant, log_health)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'logs').mkdir()
        (self.root/'logs'/'latest.log').write_text('Loading Minecraft 1.21.1 with Fabric Loader 0.16.0\n', encoding='utf8')
        self.launch = {'timed_out':True,'success':False,'exit_code':None}

    def tearDown(self):
        self.temporary.cleanup()

    def observer(self, loader='fabric'):
        with patch.dict(os.environ, {'DISPLAY':':99'}), patch('staged_readiness_0343.command',side_effect=lambda args, timeout=7: 'OpenGL renderer string: llvmpipe\nOpenGL version string: 4.5' if args[0]=='glxinfo' else '/usr/bin/tool'):
            return StartupObserver(100,self.root,self.root/'proof',loader,time.time()-2)

    def test_fabric_loader_matches_real_log(self):
        self.assertTrue(log_health(self.root,None,'fabric')[0])
        self.assertFalse(log_health(self.root,None,'quilt')[0])
        self.assertFalse(log_health(self.root,None,'neoforge')[0])
        self.assertTrue(log_health(self.root,None,'vanilla')[0])
        self.assertFalse(log_health(self.root,None,'unknown')[0])

    def test_all_supported_loader_signals_and_rejections(self):
        samples = {
            'quilt':'Loading Minecraft 1.20.1 with Quilt Loader 0.23',
            'forge':'ModLauncher running: --fml.forgeVersion 47.1.0',
            'neoforge':'ModLauncher running: --fml.neoForgeVersion 21.1.0',
            'fabric':'Loading Minecraft 1.21 with Fabric Loader 0.16',
        }
        for loader, message in samples.items():
            with self.subTest(loader=loader):
                (self.root/'logs'/'latest.log').write_text(message)
                self.assertTrue(log_health(self.root, None, loader)[0])
                for other in samples:
                    if other != loader:
                        self.assertFalse(log_health(self.root, None, other)[0],
                                         f'{loader} log incorrectly accepted as {other}')

    def test_guard_violation_and_jvm_crash(self):
        for message in ('NeverGuard policy violation blocked launch',
                        'A fatal error has been detected by the Java Runtime Environment',
                        'EXCEPTION_ACCESS_VIOLATION'):
            with self.subTest(message=message):
                (self.root/'logs'/'latest.log').write_text('Loading Minecraft with Fabric Loader 0.16\n'+message)
                ok, reason = log_health(self.root, None, 'fabric')
                self.assertFalse(ok)
                self.assertIn('fatal', reason)

    def test_fatal_and_crash_override_loader_and_rendered_menu(self):
        obs = self.observer()
        obs.samples=[{'sha256':'0'*64},{'sha256':'1'*64}]
        obs.last_change_monotonic = time.monotonic()
        obs.window_last_seen_monotonic = time.monotonic()
        (self.root/'logs'/'latest.log').write_text('Loading Minecraft 1.21.1 with Fabric Loader 0.16.0\njava.lang.OutOfMemoryError: Java heap space\n')
        self.assertEqual(obs.conclude(self.launch)[0], 'failed')
        (self.root/'logs'/'latest.log').write_text('Loading Minecraft 1.21.1 with Fabric Loader 0.16.0\n')
        (self.root/'hs_err_pid123.log').write_text('fatal')
        self.assertEqual(obs.conclude(self.launch)[0], 'failed')

    def test_timeout_and_marker_never_pass_without_window(self):
        obs = self.observer()
        (self.root/'logs'/'latest.log').write_text('Loading Minecraft with Fabric Loader 0.16\nLWJGL version 3.3\n')
        self.assertEqual(obs.conclude(self.launch)[0],'failed')
        self.assertEqual(len(obs.evidence()['samples']),0)

    def test_real_window_samples_required_and_frozen_menu_rejected(self):
        obs = self.observer()
        data = iter(['a'*64, 'b'*64])
        def fake_capture(_wid, path):
            digest = next(data)
            path.write_bytes(b'12345')
            return {'sha256':digest,'menuControls':['multiplayer','singleplayer']}
        with patch('staged_readiness_0343.find_window',return_value=('0x12',222)), \
             patch('staged_readiness_0343.capture_menu',side_effect=fake_capture):
            obs.tick()
            obs.last_probe -= 5
            obs.samples[0]['observedMonotonic'] -= 5
            obs.tick()
        self.assertEqual(obs.conclude(self.launch)[0],'passed')
        obs.last_change_monotonic -= 40
        self.assertEqual(obs.conclude(self.launch)[0],'failed')
        obs.last_change_monotonic=time.monotonic()
        self.assertEqual(obs.conclude({'timed_out':False,'success':False,'exit_code':1})[0],'failed')

    def test_actual_x11_window_must_belong_to_child(self):
        fake_tree='0x12 "Minecraft 1.21" ("minecraft" "Minecraft")\n'
        with patch('staged_readiness_0343.command',side_effect=[fake_tree, '_NET_WM_PID(CARDINAL) = 5']), \
             patch('staged_readiness_0343.is_descendant',return_value=False):
            self.assertIsNone(find_window(100))
        with patch('staged_readiness_0343.command',side_effect=[fake_tree, '_NET_WM_PID(CARDINAL) = 345']), \
             patch('staged_readiness_0343.is_descendant',return_value=True):
            self.assertEqual(find_window(100),('0x12',345))
        self.assertTrue(is_descendant(os.getpid(),os.getpid()))
        self.assertFalse(is_descendant(1,os.getpid()))

    def test_menu_recognition_from_actual_pixels_not_log(self):
        def sample_command(argv, timeout=7):
            if argv[0] == 'scrot':
                Path(argv[-1]).write_bytes(b'x'*3000)
            if argv[0] == 'identify':
                return '1280 720 0.47'
            if argv[0] == 'tesseract':
                return 'Minecraft\nSingleplayer\nMultiplayer\nOptions\n'
            return ''
        with patch('staged_readiness_0343.command',side_effect=sample_command):
            frame = capture_menu('0xab',self.root/'frame.png')
        self.assertIn('singleplayer',frame['menuControls'])
        self.assertIn('multiplayer',frame['menuControls'])
        with patch('staged_readiness_0343.command',side_effect=lambda argv,timeout=7: '1280 720 0.02' if argv[0]=='identify' else 'Singleplayer Multiplayer'):
            self.assertIsNone(capture_menu('0xab',self.root/'frame.png'))

    def test_no_display_is_blocked_not_minecraft_incompatible(self):
        with patch.dict(os.environ, {'DISPLAY':''}):
            obs=StartupObserver(100,self.root,self.root/'proof','vanilla',time.time())
        self.assertEqual(obs.conclude(self.launch)[0],'blocked')


if __name__ == '__main__':
    unittest.main()
