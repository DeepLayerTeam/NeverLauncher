"""Детерминированные регрессии упаковки; синтетические заголовки исполняемых файлов используются только в тестах."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import test_reproducible as fixture
from unsigned_package import make_package
from reproducible import EXPECTED, visit_archive


class PackerTests(unittest.TestCase):
    def test_two_independent_directories_and_mtimes_produce_identical_bytes(self):
        for platform in ('linux','windows','macos'):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                key='darwin' if platform=='macos' else platform
                prefix='launcher/' if platform=='linux' else 'Launcher.app/' if platform=='macos' else ''
                names=[prefix+x for x in EXPECTED[key]]
                digests=[]
                for number in (1,2):
                    directory=root/f'host-{number}'
                    directory.mkdir()
                    mapping={}
                    for name in names:
                        src=directory/Path(name).name
                        src.write_bytes(fixture.fake_binary(key,'x64'))
                        src.chmod(0o755)
                        os.utime(src,(number*1000,number*1000))
                        mapping[name]=src
                    output=make_package(platform,'x64',root/f'out-{number}',mapping)
                    digests.append(hashlib.sha256(output.read_bytes()).hexdigest())
                    self.assertEqual(set(names),set(visit_archive(output,key,'x64')))
                self.assertEqual(digests[0],digests[1])

    def test_reject_overwrite_and_invalid_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);inputs=root/'in';inputs.mkdir()
            mapping={}
            for name in EXPECTED['linux']:
                src=inputs/name;src.write_bytes(fixture.fake_binary('linux','x64'));src.chmod(0o755)
                mapping['launcher/'+name]=src
            out=make_package('linux','x64',root/'out',mapping)
            with self.assertRaisesRegex(ValueError,'перезаписывать'):
                make_package('linux','x64',root/'out',mapping)
            (inputs/'launcher-cli').write_bytes(fixture.fake_binary('linux','arm64'))
            with self.assertRaisesRegex(ValueError,'архитектура'):
                make_package('linux','x64',root/'out-other',mapping)

if __name__=='__main__':unittest.main()
