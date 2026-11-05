from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile

import delivery_verify_0462 as delivery
import staged_accept_0462 as stage


def elf(arch):
    b=bytearray(4096);b[:4]=b'\x7fELF';b[4:6]=b'\x02\x01';struct.pack_into('<HH',b,16,2,delivery.ARCH[arch]['elf']);b[64:]=hashlib.shake_256(arch.encode()).digest(4032);return bytes(b)


def pe(arch, signed=True):
    b=bytearray(4096);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x100)
    b[0x100:0x104]=b'PE\0\0';struct.pack_into('<H',b,0x104,delivery.ARCH[arch]['pe'])
    opt=0x118;struct.pack_into('<H',b,opt,0x20b)
    if signed:struct.pack_into('<II',b,opt+112+4*8,3600,256)
    return bytes(b)


def macho(arch, signed=True):
    b=bytearray(4096);b[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',b,4,delivery.ARCH[arch]['macho'])
    struct.pack_into('<II',b,16,1,16)
    struct.pack_into('<IIII',b,32,0x1d if signed else 0x1b,16,3800,128)
    return bytes(b)


class ReleaseDeliveryTests(unittest.TestCase):
    def test_real_binary_header_required(self):
        for platform,fn in [('windows',pe),('darwin',macho),('linux',elf)]:
            for arch in ('x64','arm64'):
                delivery.exe_arch(fn(arch),platform,arch)
                with self.assertRaisesRegex(ValueError,r'(?:architecture|архитектура)'):
                    delivery.exe_arch(fn(arch),platform,'arm64' if arch=='x64' else 'x64')
        with self.assertRaisesRegex(ValueError,'Authenticode'):
            delivery.exe_arch(pe('x64',False),'windows','x64')
        with self.assertRaisesRegex(ValueError,'CODE_SIGNATURE'):
            delivery.exe_arch(macho('x64',False),'darwin','x64')
    def test_signed_windows_zip_manifest_and_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'launcher-desktop-0.46.2-windows-x64.zip'
            records=[]
            for name in delivery.EXPECTED['windows']:
                data=pe('x64');records.append({'name':name,'sha256':delivery.digest(data),'size':len(data)})
            manifest={'productVersion':'0.46.2','architecture':'x64','authenticodeRequired':True,
                      'signingMode':'authenticode-rfc3161','artifacts':records}
            with zipfile.ZipFile(archive,'w') as z:
                for row in records:z.writestr(row['name'],pe('x64'))
                z.writestr('WINDOWS_PACKAGE_MANIFEST.json',json.dumps(manifest))
            self.assertEqual(delivery.verify_target(root,'windows-x64',archive.name,'0.46.2')['executablesVerified'],5)
            with zipfile.ZipFile(archive,'w') as z:
                for row in records:z.writestr(row['name'],pe('arm64') if row['name']=='guard.exe' else pe('x64'))
                z.writestr('WINDOWS_PACKAGE_MANIFEST.json',json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,r'(?:architecture|архитектура)'):
                delivery.verify_target(root,'windows-x64',archive.name,'0.46.2')
    def test_linux_tar_manifest_and_payload_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'launcher-linux-arm64-0.46.2.tar.gz'
            rows=[]
            for name in delivery.EXPECTED['linux']:
                data=elf('arm64');rows.append({'packagePath':'launcher/'+name,'sha256':delivery.digest(data),'size':len(data)})
            manifest={'productVersion':'0.46.2','architecture':'arm64','artifacts':rows}
            with tarfile.open(archive,'w:gz') as t:
                for row in rows:
                    data=elf('arm64');i=tarfile.TarInfo(row['packagePath']);i.size=len(data);t.addfile(i,io.BytesIO(data))
                data=json.dumps(manifest).encode();i=tarfile.TarInfo('launcher/LINUX_PACKAGE_MANIFEST.json');i.size=len(data);t.addfile(i,io.BytesIO(data))
            self.assertEqual(delivery.verify_target(root,'linux-arm64',archive.name,'0.46.2')['executablesVerified'],5)
            manifest['artifacts'][1]['sha256']='0'*64
            with tarfile.open(archive,'w:gz') as t:
                for row in rows:
                    data=elf('arm64');i=tarfile.TarInfo(row['packagePath']);i.size=len(data);t.addfile(i,io.BytesIO(data))
                data=json.dumps(manifest).encode();i=tarfile.TarInfo('launcher/LINUX_PACKAGE_MANIFEST.json');i.size=len(data);t.addfile(i,io.BytesIO(data))
            with self.assertRaisesRegex(ValueError,'хеш или размер'):
                delivery.verify_target(root,'linux-arm64',archive.name,'0.46.2')
    def test_mac_finalized_manifest_binary_binding(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'launcher-desktop-0.46.2-macos-x64.zip';rows=[]
            for name in delivery.EXPECTED['darwin']:
                key='Launcher.app/'+name;data=macho('x64');rows.append({'bundlePath':key,'sha256':delivery.digest(data),'size':len(data)})
            (root/'MACOS_PACKAGE_MANIFEST_X64.json').write_text(json.dumps({'productVersion':'0.46.2','architecture':'x64','hashBindingMode':'final-artifact-sha256','artifacts':rows}))
            with zipfile.ZipFile(archive,'w') as z:
                for row in rows:z.writestr(row['bundlePath'],macho('x64'))
            self.assertEqual(delivery.verify_target(root,'darwin-x64',archive.name,'0.46.2')['executablesVerified'],4)
    def test_staging_requires_immutable_https_origin(self):
        for origin in ('http://example.com/v0.46.2','https://example.com/current',
                       'https://user:pass@example.com/v0.46.2','https://example.com/v0.46.2?x=1'):
            with self.assertRaises(ValueError):stage.require_remote(origin,'0.46.2')
        self.assertTrue(stage.require_remote('https://example.com/releases/v0.46.2','0.46.2').endswith('/'))

if __name__=='__main__':unittest.main()
