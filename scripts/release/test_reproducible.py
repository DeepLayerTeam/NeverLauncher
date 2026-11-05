"""Без сети, паролей, настоящих сертификатов или выдуманных производственных PASS-квитанций.
Синтетические файлы-фикстуры используются ТОЛЬКО для проверки валидатора, блокирующего при неопределённости.
"""
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
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption

import reproducible_0470 as repro


def fake_binary(platform, arch):
    b=bytearray(4096)
    if platform=='windows':
        b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x100)
        b[0x100:0x104]=b'PE\0\0'
        struct.pack_into('<H',b,0x104,repro.ARCH[arch]['pe'])
        struct.pack_into('<H',b,0x118,0x20b)
    elif platform=='linux':
        b[:4]=b'\x7fELF';b[4:6]=b'\x02\x01';struct.pack_into('<H',b,18,repro.ARCH[arch]['elf'])
    else:
        b[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',b,4,repro.ARCH[arch]['macho'])
        struct.pack_into('<II',b,16,1,16)
        struct.pack_into('<II',b,32,0x1b,16)
    b[512:544]=hashlib.sha256((platform+arch).encode()).digest()
    return bytes(b)


def create_bundle(where:Path, mutate=False):
    where.mkdir(parents=True,exist_ok=True)
    for target, filename in repro.contract()['targets'].items():
        platform,arch=target.split('-')
        prefix='launcher/' if platform=='linux' else 'Launcher.app/' if platform=='darwin' else ''
        files={prefix+name:fake_binary(platform,arch) for name in repro.EXPECTED[platform]}
        files[prefix+'version.txt']=(repro.RELEASE_VERSION+'\n').encode('ascii')
        if mutate and target=='linux-arm64':files[prefix+'version.txt']=b'TAMPER!\n'
        if filename.endswith('.zip'):
            with zipfile.ZipFile(where/filename,'w',compression=zipfile.ZIP_STORED) as z:
                for name,blob in sorted(files.items()):
                    item=zipfile.ZipInfo(name,(1980,1,1,0,0,0))
                    item.create_system=3
                    item.external_attr=((0o100755 if name!=prefix+'version.txt' else 0o100644)<<16)
                    z.writestr(item,blob)
        else:
            import gzip
            with (where/filename).open('wb') as f, gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as gz:
                with tarfile.open(fileobj=gz,mode='w') as t:
                    for name,blob in sorted(files.items()):
                        info=tarfile.TarInfo(name);info.size=len(blob);info.mode=0o755 if name!=prefix+'version.txt' else 0o644;info.mtime=0
                        t.addfile(info,io.BytesIO(blob))


class ReproTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name)
        self.a=self.dir/'one';self.b=self.dir/'two'
        create_bundle(self.a);create_bundle(self.b)
        self.commit='a'*40
        self.keys=[]
        for i in range(3):
            k=Ed25519PrivateKey.generate()
            private=self.dir/f'{i}.pem';public=self.dir/f'{i}.pub'
            private.write_bytes(k.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
            public.write_bytes(k.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
            self.keys.append((k,private,public))

    def reports(self):
        a=repro.capture(self.a,builder='builder-a',runner='host-1',commit=self.commit)
        b=repro.capture(self.b,builder='builder-b',runner='host-2',commit=self.commit)
        for i,data in enumerate((a,b)):
            path=self.dir/f'{i}.json';sig=self.dir/f'{i}.sig'
            repro.atomic_json(path,data)
            sig.write_bytes(self.keys[i][0].sign(path.read_bytes()))
        return a,b

    def test_independent_six_target_capture_and_exact_comparison(self):
        a,b=self.reports()
        result=repro.compare(repro.signed_json(self.dir/'0.json',self.dir/'0.sig',self.keys[0][2]),
                             repro.signed_json(self.dir/'1.json',self.dir/'1.sig',self.keys[1][2]),self.a,self.b)
        self.assertEqual(set(result['targets']),repro.TARGETS)
        self.assertEqual(result['status'],'six-unsigned-targets-byte-identical')

    def test_real_file_tamper_blocked_even_with_old_signed_report(self):
        a,b=self.reports()
        create_bundle(self.b,mutate=True)
        with self.assertRaisesRegex(ValueError,'disagrees with actual files'):
            repro.compare(a,b,self.a,self.b)

    def test_missing_target_and_wrong_architecture_blocked(self):
        name=repro.contract()['targets']['windows-x64']
        (self.a/name).unlink()
        with self.assertRaisesRegex(ValueError,'Артефакт отсутствует'):
            repro.capture(self.a,builder='a',runner='1',commit=self.commit)
        create_bundle(self.a)
        with zipfile.ZipFile(self.a/name,'a') as z:
            z.writestr('launcher-desktop.exe',fake_binary('windows','arm64'))
        with self.assertRaisesRegex(ValueError,'duplicate'):
            repro.capture(self.a,builder='a',runner='1',commit=self.commit)

    def test_signing_identity_and_signature_replacement_blocked(self):
        a,b=self.reports()
        with self.assertRaisesRegex(ValueError,'Некорректная независимая подпись доказательных данных'):
            repro.signed_json(self.dir/'0.json',self.dir/'0.sig',self.keys[1][2])
        b['builder']=a['builder']
        with self.assertRaisesRegex(ValueError,'independent builders'):
            repro.compare(a,b,self.a,self.b)

    def test_signed_link_requires_real_native_approval_and_manifest_binding(self):
        a,b=self.reports();comparison=repro.compare(a,b,self.a,self.b)
        approval={'schema':'neverlauncher.native-signing-approval.v1','version':repro.RELEASE_VERSION,
                  'commit':self.commit,'comparisonSha256':hashlib.sha256(repro.canonical(comparison)).hexdigest(),
                  'operator':'independent-native-operator','releaseSignatureVerified':True,
                  'releaseManifestSha256':'f'*64,'targets':{}}
        signed={'targets':{target:{'sha256':hashlib.sha256(target.encode()).hexdigest()} for target in repro.TARGETS}}
        for target in repro.TARGETS:
            native=('authenticode-chain-and-timestamp-verified' if target.startswith('windows') else
                    'codesign-gatekeeper-and-notarization-verified' if target.startswith('darwin') else
                    'release-ed25519-and-digest-verified')
            approval['targets'][target]={'unsignedSha256':comparison['targets'][target]['sha256'],
                                         'signedSha256':signed['targets'][target]['sha256'],
                                         'boundPayload':True,'nativeCheck':native}
        (self.dir/'RELEASE_MANIFEST.json').write_bytes(b'actual manifest')
        native_dir=self.dir/'native';native_dir.mkdir()
        for target in repro.TARGETS:
            row=approval['targets'][target]
            report={'schema':'neverlauncher.native-verification.v1','version':repro.RELEASE_VERSION,
                    'target':target,'unsignedSha256':row['unsignedSha256'],
                    'signedSha256':row['signedSha256'],'nativeCheck':row['nativeCheck'],
                    'releaseManifestSha256':repro.sha256_file(self.dir/'RELEASE_MANIFEST.json'),
                    'status':'native-verified-transform-audit-separate'}
            path=native_dir/(target+'.json')
            repro.atomic_json(path,report)
            (native_dir/(target+'.sig')).write_bytes(self.keys[2][0].sign(path.read_bytes()))
            row['nativeReceiptSha256']=repro.sha256_file(path)
        with patch.object(repro,'verify_bundle',return_value=signed):
            with self.assertRaisesRegex(ValueError,'Не подтверждена привязка финальной подписи релиза'):
                repro.link(comparison,approval,self.dir,a_key=self.keys[0][2],b_key=self.keys[1][2],approval_key=self.keys[2][2],native_reports_dir=native_dir)
            (self.dir/'RELEASE_MANIFEST.json').write_bytes(b'actual manifest')
            approval['releaseManifestSha256']=repro.sha256_file(self.dir/'RELEASE_MANIFEST.json')
            result=repro.link(comparison,approval,self.dir,a_key=self.keys[0][2],b_key=self.keys[1][2],approval_key=self.keys[2][2],native_reports_dir=native_dir)
            self.assertEqual(set(result['targets']),repro.TARGETS)
            approval['targets']['darwin-arm64']['nativeCheck']='skipped'
            with self.assertRaisesRegex(ValueError,'OS-native'):
                repro.link(comparison,approval,self.dir,a_key=self.keys[0][2],b_key=self.keys[1][2],approval_key=self.keys[2][2],native_reports_dir=native_dir)

if __name__=='__main__':unittest.main()
