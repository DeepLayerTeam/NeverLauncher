#!/usr/bin/env python3
"""Независимое подписание повторно проверенных настоящих длительных прогонов 0.52.12.

Запускать на отдельном защищённом хосте рецензента. Перед подписью повторно проверяется *каждый*
исходный сеанс Minecraft. Ключ подписи не должен находиться в рабочей копии репозитория.
"""
import argparse
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sweep_05211 import raw_soak, signed_soak, ROOT
import inventory_0521 as inventory
from inventory_0521 import safe_file, public_key, canonical, write_exclusive

DOMAIN = ('neverlauncher.soak.real.' + inventory.VERSION + '\x00').encode()

def sign(a):
    raw_soak(a.report_dir, a.commit, a.run_id, a.attempt, a.mode)
    if a.private_key.resolve().is_relative_to(ROOT):
        raise ValueError('Ключ подписи проверяющего должен находиться вне рабочей копии исходников')
    key_file = safe_file(a.private_key,8192)
    if key_file.stat().st_mode & 0o077:
        raise ValueError('У закрытого ключа подписанта должны быть права 0600')
    key = serialization.load_pem_private_key(key_file.read_bytes(),password=None)
    pub = public_key(a.public_key,a.pin)
    if not isinstance(key,Ed25519PrivateKey) or key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw) != pub.public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw):
        raise ValueError('Несоответствие независимого ключа подписи')
    from inventory_0521 import read_json
    payload = read_json(a.report_dir / 'soak.json')
    dest = a.report_dir / 'soak.sig'
    write_exclusive(dest,key.sign(DOMAIN + canonical(payload)))
    signed_soak(a.report_dir,a.public_key,a.pin,a.commit,a.run_id,a.attempt,a.mode)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report-dir',type=Path,required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--run-id',required=True)
    p.add_argument('--attempt',type=int,required=True)
    p.add_argument('--mode',choices=('game','https'),required=True)
    p.add_argument('--private-key',type=Path,required=True)
    p.add_argument('--public-key',type=Path,required=True)
    p.add_argument('--pin',required=True)
    a=p.parse_args()
    try:
        sign(a)
        print('PASS: фактические результаты длительного тестирования независимо проверены и подписаны (НЕ GA)')
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Проверка результатов длительного тестирования заблокирована: ' + str(exc),file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
