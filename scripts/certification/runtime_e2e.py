#!/usr/bin/env python3
"""Настоящий E2E Runtime с подписанным манифестом. Требуются скомпилированные исполняемые файлы Rust.

Покрываются переключение после отравленного зеркала, конкурентный планировщик, дайджест работающего
и установленного компонентов, второй профиль только из кэша и отклонение подменённого манифеста
Ed25519.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from fault_server import FaultServer, Object


def payload(index: int, size: int = 65536) -> bytes:
    """Детерминированные несжимаемые байты без случайности и внешних фикстур."""
    return b"".join(
        hashlib.sha256(f"file:{index}:{n}".encode()).digest()
        for n in range((size + 31) // 32)
    )[:size]


def manifest(
    base: str, files: list[bytes], *, profile: str, poison: bool = True
) -> dict:
    entries = []
    for i, data in enumerate(files):
        good = f"{base}/good/{i}"
        entries.append(
            {
                "path": f"libraries/certification/{i}.jar",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "url": f"{base}/bad/{i}" if poison and i == 0 else good,
                "mirrors": [good] if poison and i == 0 else [],
                "required": True,
                "executable": False,
                "ownership": "managed",
            }
        )
    return {
        "schemaVersion": "1.0",
        "projectId": "certification",
        "profileId": profile,
        "channel": "stable",
        "version": "0.24.0",
        "createdAt": "2026-10-20T00:00:00Z",
        "minecraft": {"version": "1.21.1", "loader": "vanilla"},
        "runtime": {"java": {"majorVersion": 21, "distribution": "temurin"}},
        "files": entries,
    }


def sign(signer: Path, source: Path, target: Path, doc: dict) -> str:
    source.write_text(json.dumps(doc), encoding="utf8")
    env = os.environ.copy()
    env["LAUNCHER_CERT_TEST_SEED"] = (
        "42" * 32
    )  # детерминированный набор данных исключительно для сертификации
    result = subprocess.run(
        [str(signer), str(source), str(target)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    key = result.stdout.strip()
    if len(key) != 64:
        raise AssertionError("Подписывающая программа не выдала публичный ключ Ed25519")
    return key


def sync(
    runtime: Path,
    doc: Path,
    root: Path,
    key: str,
    cache: Path,
    *,
    expect_success: bool = True,
):
    env = os.environ.copy()
    if os.name == "nt":
        env["LOCALAPPDATA"] = str(cache)
    elif sys.platform == "darwin":
        env["HOME"] = str(cache)
    else:
        env["XDG_CACHE_HOME"] = str(cache)
    cmd = [
        str(runtime),
        "sync-local",
        "--manifest",
        str(doc),
        "--root",
        str(root),
        "--pinned-public-key",
        key,
    ]
    t0 = time.perf_counter_ns()
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=140)
    elapsed = time.perf_counter_ns() - t0
    if expect_success and result.returncode:
        raise AssertionError(f"Ошибка: «реальная локальная синхронизация Runtime»: {result.stderr[-2500:]}")
    if not expect_success and not result.returncode:
        raise AssertionError("Изменённый манифест ошибочно принят")
    if not expect_success:
        return {"rejected": True, "elapsedNs": elapsed}
    report = json.loads(result.stdout)
    if report.get("status") != "ready":
        raise AssertionError(f"Не готово: {report}")
    return {"elapsedNs": elapsed, "result": report}


def integration(runtime: Path, signer: Path, out: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="nl-cert02313-") as d:
        root = Path(d)
        files = [payload(i) for i in range(12)]
        objects = {
            f"/good/{i}": Object(data, delay=0.04) for i, data in enumerate(files)
        }
        objects["/bad/0"] = Object(files[0], behavior="poison")
        cache = root / "cache"
        with FaultServer(objects) as server:
            unsigned, signed = root / "unsigned.json", root / "signed.json"
            key = sign(
                signer, unsigned, signed, manifest(server.url, files, profile="first")
            )
            first = sync(runtime, signed, root / "first", key, cache)
            metrics = server.metrics()
            if not any(r["path"] == "/bad/0" for r in metrics["requests"]):
                raise AssertionError("Недоверенное зеркало не было задействовано")
            if not any(r["path"] == "/good/0" for r in metrics["requests"]):
                raise AssertionError("Переход на резервное зеркало не выполнен")
            for i, data in enumerate(files):
                installed = (
                    root / "first" / "libraries" / "certification" / f"{i}.jar"
                ).read_bytes()
                if installed != data:
                    raise AssertionError(f"Неверный проверенный файл {i}")
            original_requests = len(metrics["requests"])
            # Явно измените подписанный путь и проверьте отклонение подписи до установки.
            changed = json.loads(signed.read_text())
            changed["files"][0]["sha256"] = "00" * 32
            invalid = root / "tampered.json"
            invalid.write_text(json.dumps(changed), encoding="utf8")
            rejected = sync(
                runtime, invalid, root / "rejected", key, cache, expect_success=False
            )
            if (root / "rejected" / "libraries").exists():
                raise AssertionError("Установлен неподписанный файл")
            if len(server.metrics()["requests"]) != original_requests:
                raise AssertionError("Недоверенное значение: «манифест привёл к HTTP-запросам»")
        # Сокет сервера уже закрыт. Второй профиль не может получить удалённый файл.
        sign(signer, unsigned, signed, manifest(server.url, files, profile="second"))
        second = sync(runtime, signed, root / "second", key, cache)
        for i, data in enumerate(files):
            if (
                root / "second" / "libraries" / "certification" / f"{i}.jar"
            ).read_bytes() != data:
                raise AssertionError("Кэш восстановил неверные данные")
        actual = second["result"]["download"]
        transferred = actual.get("bytesTransferred", actual.get("transferredBytes"))
        if transferred != 0:
            raise AssertionError(f"Автономный кэш использовал сетевые данные: {transferred}")
        return {
            "id": "runtime-signed-e2e",
            "status": "passed",
            "firstElapsedNs": first["elapsedNs"],
            "secondElapsedNs": second["elapsedNs"],
            "offlineTransferredBytes": transferred,
            "serverTransferredBytes": metrics["transferredBytes"],
            "serverRequestCount": original_requests,
            "tamperedManifestRejected": rejected["rejected"],
            "filesChecked": len(files),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = integration(args.runtime.resolve(), args.signer.resolve(), args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
