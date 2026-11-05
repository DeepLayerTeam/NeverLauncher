#!/usr/bin/env python3
"""Дважды собрать настоящий Go CLI NeverLauncher с разными корнями исходников и временем файлов.

Это ЛОКАЛЬНАЯ регрессионная проверка, а не внешне подписанное подтверждение шести платформ.
Имитированный исполняемый файл или предоставленная фикстура не удовлетворяют проверке.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix='launcher-go-repro-') as temp:
        hashes=[]
        for index in (0,1):
            root=Path(temp)/f'checkout-{index}'
            shutil.copytree(ROOT/'cli',root,ignore=shutil.ignore_patterns('.git','dist','target','node_modules'))
            for path in root.rglob('*.go'):
                os.utime(path,(1700000000+index*300,1700000000+index*300))
            executable=Path(temp)/f'launcher-cli-{index}'
            env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0')
            completed=subprocess.run(['go','build','-trimpath','-buildvcs=false','-mod=readonly','-o',str(executable),'./cmd/launcher'],
                                     cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            if completed.returncode:
                print('Локальная проверка воспроизводимости Go заблокирована: '+completed.stderr[-3000:],file=sys.stderr)
                return 2
            hashes.append(hashlib.sha256(executable.read_bytes()).hexdigest())
        if hashes[0]!=hashes[1]:
            print('Локальная проверка воспроизводимости Go не пройдена: реальные исполняемые файлы различаются '+str(hashes),file=sys.stderr)
            return 2
        print('Локальная проверка воспроизводимости Go пройдена: реальный CLI собран дважды из разных путей и с разным временем изменения: '+hashes[0])
    return 0

if __name__=='__main__':raise SystemExit(main())
