#!/usr/bin/env python3
"""Выполнять проверки противодействия атакам на настоящих подготовленных бинарных файлах Runtime и CLI.

Запускать только в одноразовом подготовленном валидирующем исполнителе после успешного наблюдения
игры на подходящем сервере. Ни одна фикстура не является свидетельством Runtime. После повреждения
установленный клиент восстанавливается и независимо перепроверяется.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

MAX_OUTPUT = 2 * 1024 * 1024


def _run(command: list[str], env: dict[str, str], timeout: int = 90) -> tuple[int, bytes]:
    try:
        proc = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Проверка обходов превысила время ожидания; факт отклонения не подтверждён") from exc
    if len(proc.stdout) > MAX_OUTPUT:
        raise RuntimeError("Диагностический вывод проверки обходов превысил лимит")
    return proc.returncode, proc.stdout


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _positive_runtime_verify(runtime: str, manifest: Path, key: str, env: dict[str, str]) -> None:
    rc, output = _run([runtime, "verify", "--manifest", str(manifest),
                       "--pinned-public-key", key], env)
    if rc:
        raise RuntimeError("Реальный Runtime не смог проверить неизменённый подписанный манифест")
    try:
        data = json.loads(output)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Реальный Runtime не вернул действительное доказательство подписи") from exc
    if data.get("status") != "ready" or data.get("signature", {}).get("valid") is not True:
        raise RuntimeError("Реальный Runtime не принял исходную подпись")


def reject_tampered_manifest(runtime: str, manifest: Path, key: str,
                             work: Path, env: dict[str, str]) -> dict:
    _positive_runtime_verify(runtime, manifest, key, env)
    original = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(original, dict) or not isinstance(original.get("version"), str):
        raise RuntimeError("В подготовленном подписанном манифесте отсутствует версия")
    attack = dict(original)
    attack["version"] = original["version"] + ".untrusted-04314"
    altered = work / "adversarial-manifest-04314.json"
    altered.write_text(json.dumps(attack, sort_keys=True), encoding="utf-8")
    try:
        rc, _ = _run([runtime, "verify", "--manifest", str(altered),
                      "--pinned-public-key", key], env)
        if rc == 0:
            raise RuntimeError("Производственный Runtime ошибочно принял изменённый подписанный манифест")
        return {"status": "denied", "baselineVerified": True,
                "alteredManifestSha256": _digest(altered)}
    finally:
        altered.unlink(missing_ok=True)


def reject_corrupted_client(cli: str, package: Path, client: Path,
                            files: list[dict], work: Path, env: dict[str, str]) -> dict:
    # CLI уже установил побайтовую корректность установки. Выбирайте настоящий
    # ОБЯЗАТЕЛЬНЫЙ обычный файл и отклоняйте ссылки, в том числе ссылки на каталоги.
    candidate = None
    for entry in files:
        if not entry.get("required", True) or not isinstance(entry.get("path"), str):
            continue
        name = entry["path"]
        if (name.startswith("/") or "\\" in name or "\x00" in name or
            any(part in ("", ".", "..") for part in name.split("/"))):
            continue
        path = client / name
        def redirected(node: Path) -> bool:
            return node.is_symlink() or (hasattr(node, "is_junction") and node.is_junction())
        if redirected(client):
            continue
        if any(redirected(client.joinpath(*name.split("/")[:i]))
               for i in range(1, len(name.split("/")) + 1)):
            continue
        if path.is_file() and path.stat().st_size > 0:
            candidate = (path, entry)
            break
    if candidate is None:
        raise RuntimeError("Не найден обязательный установленный обычный файл клиента для проверки повреждения")
    path, entry = candidate
    baseline = _digest(path)
    if baseline != str(entry.get("sha256", "")).lower():
        raise RuntimeError("Для выбранного файла клиента отсутствует первоначальная побайтовая проверка")
    # Храните всё в изолированном рабочем процессе. Убитый тест может повредить
    # только этот ВРЕМЕННЫЙ клиент, но не настоящую установку пользователя.
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.read(fd, 1)
        if len(before) != 1:
            raise RuntimeError("Клиент изменился до проверки обходов")
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, bytes((before[0] ^ 0x80,)))
        os.fsync(fd)
        if _digest(path) == baseline:
            raise RuntimeError("Намеренное повреждение клиента не было выполнено")
        try:
            rc, _ = _run([
                cli, "client", "verify", "--package", str(package),
                "--client-dir", str(client), "--output", str(work / "adversarial-client-result.json"),
            ], env)
            if rc == 0:
                raise RuntimeError("Производственная CLI ошибочно приняла повреждённый установленный файл")
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, before)
            os.fsync(fd)
    finally:
        os.close(fd)
    if _digest(path) != baseline:
        raise RuntimeError("Файл клиента не восстановлен после отрицательной проверки")
    restored = work / "adversarial-restored-04314.json"
    rc, _ = _run([
        cli, "client", "verify", "--package", str(package),
        "--client-dir", str(client), "--output", str(restored),
    ], env)
    if rc or not restored.is_file():
        raise RuntimeError("Ранее исправный клиент не восстановился после проверки обходов")
    try:
        valid = json.loads(restored.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Проверка восстановления клиента вернула некорректный JSON") from exc
    if valid.get("status") != "valid":
        raise RuntimeError("После восстановления клиент не помечен как действительный")
    return {"status": "denied-and-restored", "filePath": entry["path"],
            "baselineSha256": baseline, "restoredFileSha256": _digest(path),
            "restoredVerificationSha256": _digest(restored)}


def execute(runtime: str, cli: str, signed_manifest: Path, key: str,
            package: Path, client: Path, package_files: list[dict],
            work: Path, env: dict[str, str]) -> dict:
    """Не подписывать эти результаты; связывать их хеш с подлинным подтверждением игрового процесса."""
    signed = reject_tampered_manifest(runtime, signed_manifest, key, work, env)
    damaged = reject_corrupted_client(cli, package, client, package_files, work, env)
    return {"schemaVersion": "launcher.adversarial-gameplay.04314.v1",
            "manifestTamper": signed, "installedFileTamper": damaged}
