#!/usr/bin/env python3
"""Переписать *сгенерированный* NBT плоского мира 1.17.1 для теста подходящего сервера.

Minecraft 1.17.1 может молча отклонить JSON генератора плоского мира в server.properties
(MC-195468). Менять только существующий генератор level.dat обычного мира после того, как настоящий
выделенный сервер сам создаст корректную структуру реестра NBT. Перед запуском скрипта сервер должен
быть полностью остановлен.
"""
from __future__ import annotations

import gzip
import os
from pathlib import Path
import struct
import sys
import tempfile

MAX_NBT_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 64


class NBTError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise NBTError('обрезанное или недопустимое поле длины NBT')
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def number(self, fmt: str):
        return struct.unpack('>' + fmt, self.take(struct.calcsize('>' + fmt)))[0]

    def name(self):
        n = self.number('H')
        return self.take(n).decode('utf-8')

    def payload(self, tag: int, depth: int = 0):
        if depth > MAX_DEPTH:
            raise NBTError('Слишком большая глубина вложенности NBT')
        if tag in (1, 2, 3, 4, 5, 6):
            return self.number({1: 'b', 2: 'h', 3: 'i', 4: 'q', 5: 'f', 6: 'd'}[tag])
        if tag in (7, 11, 12):
            n = self.number('i')
            width = {7: 1, 11: 4, 12: 8}[tag]
            return self.take(n * width)
        if tag == 8:
            return self.name()
        if tag == 9:
            item_tag = self.number('B')
            n = self.number('i')
            if n < 0 or n > MAX_NBT_BYTES or (item_tag == 0 and n):
                raise NBTError('Некорректный список NBT')
            return item_tag, [self.payload(item_tag, depth + 1) for _ in range(n)]
        if tag == 10:
            result = {}
            while True:
                child_tag = self.number('B')
                if child_tag == 0:
                    return result
                name = self.name()
                if name in result:
                    raise NBTError('Повторяющееся поле составного тега NBT')
                result[name] = (child_tag, self.payload(child_tag, depth + 1))
        raise NBTError(f'Неизвестный тег NBT {tag}')


def encode_name(s: str) -> bytes:
    raw = s.encode('utf-8')
    if len(raw) > 65535:
        raise NBTError('Строка NBT слишком длинная')
    return struct.pack('>H', len(raw)) + raw


def encode_payload(tag: int, val, depth: int = 0) -> bytes:
    if depth > MAX_DEPTH:
        raise NBTError('Слишком большая глубина вложенности NBT')
    if tag in (1, 2, 3, 4, 5, 6):
        return struct.pack('>' + {1: 'b', 2: 'h', 3: 'i', 4: 'q', 5: 'f', 6: 'd'}[tag], val)
    if tag in (7, 11, 12):
        return struct.pack('>i', len(val) // {7: 1, 11: 4, 12: 8}[tag]) + val
    if tag == 8:
        return encode_name(val)
    if tag == 9:
        kind, items = val
        return bytes([kind]) + struct.pack('>i', len(items)) + b''.join(encode_payload(kind, x, depth + 1) for x in items)
    if tag == 10:
        return b''.join(bytes([kind]) + encode_name(name) + encode_payload(kind, item, depth + 1)
                        for name, (kind, item) in val.items()) + b'\0'
    raise NBTError(f'Неизвестный тег NBT {tag}')


def compound(parent, key: str):
    entry = parent.get(key)
    if entry is None or entry[0] != 10:
        raise NBTError(f'Отсутствует составной тег NBT: {key}')
    return entry[1]


def prepare(data: bytes) -> bytes:
    parser = Reader(data)
    tag = parser.number('B')
    if tag != 10:
        raise NBTError('Корень level.dat должен быть составным тегом NBT')
    root_name = parser.name()
    root = parser.payload(tag)
    if parser.pos != len(data):
        raise NBTError('Лишние данные в конце level.dat')
    world = compound(root, 'Data')
    worldgen = compound(world, 'WorldGenSettings')
    dims = compound(worldgen, 'dimensions')
    overworld = compound(dims, 'minecraft:overworld')
    generator = compound(overworld, 'generator')
    if generator.get('type') != (8, 'minecraft:flat'):
        raise NBTError('Мир 1.17.1 должен использовать плоский генератор, созданный сервером')
    settings = compound(generator, 'settings')
    if settings.get('layers', (0, None))[0] != 9:
        raise NBTError('Отсутствуют слои плоского генератора мира')
    # Сохраняйте исходные настройки реестра и структур, созданные сервером.
    # Замена одного списка полностью обходит ошибку кодека server.properties.
    settings['layers'] = (9, (10, [{'height': (3, 1), 'block': (8, 'minecraft:air')}]))
    settings['features'] = (1, 0)
    settings['lakes'] = (1, 0)
    worldgen['generate_features'] = (1, 0)
    return b'\x0a' + encode_name(root_name) + encode_payload(10, root)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit('Использование: prepare-vanilla-1171-void-world.py path/to/world/level.dat')
    path = Path(sys.argv[1])
    if path.is_symlink() or not path.is_file():
        raise SystemExit('level.dat должен быть обычным файлом, а не символической ссылкой')
    raw = path.read_bytes()
    uncompressed = gzip.decompress(raw)
    if len(uncompressed) > MAX_NBT_BYTES:
        raise SystemExit('Превышен допустимый размер level.dat')
    changed = prepare(uncompressed)
    if changed == uncompressed:
        raise SystemExit('Генератор мира в level.dat не изменился')
    # Перед заменой файла проверьте, что данные полностью поддаются разбору.
    parsed = Reader(changed)
    assert parsed.number('B') == 10
    parsed.name()
    parsed.payload(10)
    if parsed.pos != len(changed):
        raise NBTError('Сериализованный level.dat содержит лишние байты')
    fd, tmp = tempfile.mkstemp(prefix='.level-dat-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(gzip.compress(changed, mtime=0))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print('[matching-e2e] созданный сервером файл level.dat 1.17.1 изменён: обычный мир заменён пустотой (только воздух)')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (NBTError, EOFError, OSError, ValueError, struct.error) as exc:
        raise SystemExit(f'[matching-e2e] level.dat validation: ошибка — {exc}') from exc
