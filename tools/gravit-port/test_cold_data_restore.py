import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cold_data_restore_04912 as cold
import test_operational_rollback_04912 as earlier


class ColdRestoreTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.src = self.root/'backup'
        self.dst = self.root/'game'
        self.journal = self.root/'journal'
        for p in (self.src, self.dst, self.journal): p.mkdir(mode=0o700)
        (self.src/'world'/'playerdata').mkdir(parents=True)
        (self.dst/'world').mkdir()
        (self.src/'world'/'level.dat').write_bytes(b'reconciled world')
        (self.src/'world'/'playerdata'/'player.dat').write_bytes(b'reconciled inventory')
        (self.dst/'world'/'level.dat').write_bytes(b'old world')
        self.manifest = self.root/'backup.json'
        self.run = 'run_12345678'
        cold.write_manifest(self.src,self.manifest,self.run)

    def test_verified_restore_retains_old_data(self):
        cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)
        self.assertEqual((self.dst/'world'/'level.dat').read_bytes(),b'reconciled world')
        self.assertEqual((self.dst/'world'/'playerdata'/'player.dat').read_bytes(),b'reconciled inventory')
        self.assertEqual((self.root/('game.before-'+self.run)/'world'/'level.dat').read_bytes(),b'old world')
        self.assertEqual(json.loads((self.journal/'file-restore-state.json').read_text())['phase'],'verified_installed')

    def test_tampered_backup_refuses_to_replace(self):
        (self.src/'world'/'level.dat').write_bytes(b'tampered')
        with self.assertRaises(cold.co.Blocked):
            cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)
        self.assertEqual((self.dst/'world'/'level.dat').read_bytes(),b'old world')

    def test_symlink_and_path_traversal_rejected(self):
        (self.src/'world'/'playerdata'/'player.dat').unlink()
        (self.src/'world'/'playerdata'/'player.dat').symlink_to(self.root/'outside')
        with self.assertRaises(cold.co.Blocked): cold.entries(self.src)
        data=cold.co.document(self.manifest)
        data['files'][0]['path']='../../escape'
        with self.assertRaises(cold.co.Blocked): cold.validate_manifest(data,self.run)

    def test_recover_after_kill_between_directory_renames(self):
        # Имитируйте состояние на диске после target -> old, но до staged -> target.
        old = self.root/('game.before-'+self.run)
        stage = self.root/'.never-restoring-crash'
        stage.mkdir()
        self.dst.rename(old)
        record={'format':cold.FORMAT,'runId':self.run,'phase':'old_moved',
                'target':str(self.dst),'retained':str(old),'stage':str(stage),
                'manifestSha256':cold.co.digest(json.dumps(cold.co.document(self.manifest),sort_keys=True).encode())}
        p = self.journal/'file-restore-state.json'
        p.write_text(json.dumps(record))
        p.chmod(0o600)
        self.assertEqual(cold.recover(self.dst,cold.co.document(self.manifest),self.journal,self.run),
                         'restored_previous_after_failure')
        self.assertEqual((self.dst/'world'/'level.dat').read_bytes(),b'old world')

    def test_recover_after_install_verifies_bytes(self):
        cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)
        self.assertEqual(cold.recover(self.dst,cold.co.document(self.manifest),self.journal,self.run),
                         'verified_installed')
        (self.dst/'world'/'level.dat').write_bytes(b'corrupted')
        with self.assertRaises(cold.co.Blocked):
            cold.recover(self.dst,cold.co.document(self.manifest),self.journal,self.run)

    def test_restore_is_one_shot(self):
        cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)
        with self.assertRaises(cold.co.Blocked):
            cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)

    def test_failure_in_rename_window_restores_original(self):
        original=cold.os.replace
        def failing(src,dst):
            if str(src).startswith(str(self.root/'.never-restoring-')) and dst==self.dst:
                raise OSError('injected power-failure-style rename error')
            return original(src,dst)
        with patch.object(cold.os,'replace',side_effect=failing):
            with self.assertRaises(OSError):
                cold.restore(self.src,self.dst,cold.co.document(self.manifest),self.journal,self.run)
        self.assertEqual((self.dst/'world'/'level.dat').read_bytes(),b'old world')
        self.assertEqual(json.loads((self.journal/'file-restore-state.json').read_text())['phase'],
                         'restored_previous_after_failure')


if __name__ == '__main__': unittest.main()
