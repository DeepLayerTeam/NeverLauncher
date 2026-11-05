#!/usr/bin/env python3
"""Побайтово сравнивает каждый публичный Maven-артефакт независимых промежуточных сборок."""
import hashlib
from pathlib import Path
import sys

def tree(path):
    root = Path(path)
    if not root.is_dir():
        raise ValueError(f'not a repository: {root}')
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: compare_sdk_repos_04812.py STAGING_A/maven STAGING_B/maven')
    try:
        left, right = tree(sys.argv[1]), tree(sys.argv[2])
        if not left or left != right:
            raise ValueError('SDK Maven publication is not reproducible, or contains missing files')
        print(f'PASS: {len(left)} SDK publication files byte-for-byte identical')
    except ValueError as err:
        sys.exit(f'FAIL: {err}')
