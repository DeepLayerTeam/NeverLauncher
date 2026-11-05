"""Регрессионные тесты нативной проверки: подпись ОС никогда не имитируется как PASS."""
from __future__ import annotations
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import native_verify_0470 as native
import test_reproducible_0470 as fixtures


class NativeTests(unittest.TestCase):
    def test_authenticode_only_changes_certificate_and_checksum(self):
        original=fixtures.fake_binary('windows','x64')
        signed=bytearray(original)+b'CERTDATA'
        off=0x118
        struct.pack_into('<II',signed,off+112+4*8,len(original),8)
        struct.pack_into('<I',signed,off+64,0x12345678)
        native.normalize_pe(original,bytes(signed))
        signed[0x300]^=0xff
        with self.assertRaisesRegex(ValueError,'изменил байты исполняемого файла'):
            native.normalize_pe(original,bytes(signed))

    def test_native_host_only(self):
        with patch.object(native.platform,'system',return_value='Linux'):
            with self.assertRaisesRegex(ValueError,'native Windows'):
                native.native_report('windows-arm64',Path('/nonexistent'),Path('/nonexistent'),
                                     release_cli=Path('/nonexistent'), public_key=Path('/nonexistent'),
                                     trust_policy=Path('/nonexistent'),trust_state=Path('/nonexistent'))

if __name__=='__main__':unittest.main()
