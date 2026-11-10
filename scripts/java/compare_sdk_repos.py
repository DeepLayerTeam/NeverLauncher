#!/usr/bin/env python3
"""Побайтово сравнивает каждый публичный Maven-артефакт независимых промежуточных сборок."""
import hashlib
from pathlib import Path
import sys

def tree(path):
    root = Path(path)
    if not root.is_dir():
        raise ValueError(f'Каталог не является репозиторием: {root}')
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Использование: compare_sdk_repos_04812.py STAGING_A/maven STAGING_B/maven')
    try:
        left, right = tree(sys.argv[1]), tree(sys.argv[2])
        if not left or left != right:
            raise ValueError('Публикация SDK в Maven невоспроизводима либо в ней отсутствуют файлы')
        print(f'ПРОЙДЕНО: {len(left)} файлов публикации SDK побайтово совпадают')
    except ValueError as err:
        sys.exit(f'ОШИБКА: {err}')
