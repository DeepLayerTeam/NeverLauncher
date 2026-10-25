#!/usr/bin/env python3
"""Build real Java SDK Maven artifacts and validate them with a downstream JVM.

No network, Maven installation or signing key required. This produces a local
staging Maven repository, not a public Maven Central publication or a GA receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
GROUP = 'ru.neverlauncher'
MODULES = {'neverlauncher-java-sdk-core': 'sdk/java/core',
           'neverlauncher-gravit-compat': 'sdk/java/gravit-compat'}
VERSION = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')
EPOCH = (1980, 1, 1, 0, 0, 0)


def run(*args: str, cwd: Path = ROOT) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def deterministic_jar(target: Path, entries: list[tuple[str, bytes]]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as jar:
        for name, content in sorted(entries):
            if not name or name.startswith('/') or '\\' in name or '..' in name.split('/'):
                raise ValueError('unsafe jar entry')
            info = zipfile.ZipInfo(name, EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            jar.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def from_directory(base: Path, suffix: str) -> list[tuple[str, bytes]]:
    if not base.is_dir():
        raise RuntimeError(f'missing compiled Java classes/sources: {base}')
    result=[]
    for f in sorted(base.rglob('*')):
        if f.is_symlink():
            raise RuntimeError(f'symlink in publication input: {f}')
        if f.is_file() and f.name.endswith(suffix):
            result.append((f.relative_to(base).as_posix(), f.read_bytes()))
    if not result:
        raise RuntimeError(f'empty Java publication input: {base}')
    return result


def pom(name: str, version: str) -> bytes:
    project = ET.Element('project', {'xmlns':'http://maven.apache.org/POM/4.0.0',
                                     'xmlns:xsi':'http://www.w3.org/2001/XMLSchema-instance',
                                     'xsi:schemaLocation':'http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd'})
    for tag, val in [('modelVersion','4.0.0'), ('groupId',GROUP), ('artifactId',name),
                     ('version',version),('packaging','jar'),('name',name),
                     ('description','NeverLauncher public Java 17 SDK / porting adapter'),
                     ('url','https://github.com/DeepLayerTeam/NeverLauncher')]:
        ET.SubElement(project,tag).text=val
    licenses=ET.SubElement(project,'licenses')
    license=ET.SubElement(licenses,'license')
    ET.SubElement(license,'name').text='Apache License, Version 2.0'
    ET.SubElement(license,'url').text='https://www.apache.org/licenses/LICENSE-2.0.txt'
    if name == 'neverlauncher-gravit-compat':
        deps=ET.SubElement(project,'dependencies')
        dep=ET.SubElement(deps,'dependency')
        for tag,val in [('groupId',GROUP),('artifactId','neverlauncher-java-sdk-core'),('version',version),('scope','compile')]:
            ET.SubElement(dep,tag).text=val
    return ET.tostring(project, encoding='utf-8', xml_declaration=True)+b'\n'


def publish(output: Path, *, build: bool = True) -> dict[str, Path]:
    version=(ROOT/'VERSION').read_text().strip()
    if not VERSION.fullmatch(version):
        raise RuntimeError('canonical VERSION is not an acceptable Maven release version')
    if build:
        for name, path in MODULES.items():
            run('sh', f'{path}/build.sh', 'test')
    output=output.resolve()
    if output.exists() and (output.is_symlink() or not output.is_dir() or any(output.iterdir())):
        raise RuntimeError(f'publication destination must be a new/empty directory: {output}')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.mkdir(parents=True,exist_ok=True)
    artifacts={}
    with tempfile.TemporaryDirectory(prefix='.nl-sdk-publish-', dir=output.parent) as stage:
        staging=Path(stage)
        for name, path in MODULES.items():
            module=ROOT/path
            base=staging/'maven'/GROUP.replace('.','/')/name/version
            basename=f'{name}-{version}'
            manifest = (f'Manifest-Version: 1.0\r\nImplementation-Version: {version}\r\nCreated-By: NeverLauncher Java SDK\r\n\r\n').encode('utf8')
            deterministic_jar(base/f'{basename}.jar', [('META-INF/MANIFEST.MF',manifest),('META-INF/LICENSE', (ROOT/'LICENSE').read_bytes())] + from_directory(module/'build/classes','.class'))
            deterministic_jar(base/f'{basename}-sources.jar', from_directory(module/'src/main/java','.java'))
            # Produce offline Javadoc from actual public API, not stub HTML.
            docs=staging/'docs'/name
            sources=sorted(str(p) for p in (module/'src/main/java').rglob('*.java'))
            command=['javadoc','-quiet','-Xdoclint:none','-encoding','UTF-8', '-notimestamp',
                     '-d',str(docs)]
            if name == 'neverlauncher-gravit-compat':
                core=staging/'maven'/GROUP.replace('.','/')/'neverlauncher-java-sdk-core'/version/f'neverlauncher-java-sdk-core-{version}.jar'
                command += ['-classpath',str(core)]
            run(*command,*sources)
            deterministic_jar(base/f'{basename}-javadoc.jar', from_directory(docs,''))
            (base/f'{basename}.pom').write_bytes(pom(name,version))
            for f in sorted(base.iterdir()):
                if f.is_file() and not f.name.endswith(('.sha256','.sha512')):
                    for algo in ('sha256','sha512'):
                        (base/(f.name+'.'+algo)).write_text(getattr(hashlib,algo)(f.read_bytes()).hexdigest()+'\n')
            artifacts[name]=output/'maven'/GROUP.replace('.','/')/name/version/f'{basename}.jar'
        # Compile + run a client importing both published artifacts, without
        # using source tree classes. This is the distribution ABI smoke test.
        smoke=staging/'Consumer.java'
        smoke.write_text('''import ru.neverlauncher.sdk.core.SemVer;
import pro.gravit.utils.Version;
public final class Consumer {
  public static void main(String[] args) {
    if (!SemVer.parse("0.31.0").matches("^0.31.0")) throw new AssertionError("SemVer");
    if (!new Version(1, 2, 3, Version.Type.RELEASE).getVersionString().equals("1.2.3.0"))
      throw new AssertionError("adapter API");
    System.out.println("NeverLauncher Java public SDK consumer OK");
  }
}
''')
        jars=[str(staging/'maven'/GROUP.replace('.','/')/n/version/f'{n}-{version}.jar') for n in MODULES]
        cp=os.pathsep.join(jars)
        run('javac','--release','17','-cp',cp,'-d',str(staging),str(smoke))
        run('java','-cp',os.pathsep.join([str(staging),*jars]),'Consumer')
        # Validate all emitted digests by reading the staged repository.
        for sidecar in (staging/'maven').rglob('*.sha256'):
            payload=sidecar.with_suffix('')
            if hashlib.sha256(payload.read_bytes()).hexdigest() != sidecar.read_text().strip():
                raise RuntimeError(f'published Maven artifact digest mismatch: {payload}')
        # Save the validated repository, not temporary docs/consumer classes.
        (staging/'maven').rename(output/'maven')
    return artifacts


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='new or empty local Maven staging directory')
    parser.add_argument('--skip-build',action='store_true',help='reuse precompiled classes (CI only)')
    args=parser.parse_args()
    try:
        for name,path in publish(args.output, build=not args.skip_build).items():
            print(f'{name}: {path}')
    except (OSError,subprocess.CalledProcessError,RuntimeError,ValueError) as e:
        parser.exit(1,f'Java SDK publication failed: {e}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
