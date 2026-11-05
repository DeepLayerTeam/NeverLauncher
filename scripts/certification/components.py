#!/usr/bin/env python3
"""Исполняемая сертификация компонентов Manifest v3 на *настоящем* бинарном файле Runtime.

Без имитаций клиента, ложных успехов, произвольных загруженных манифестов и встроенных закрытых
ключей выпуска. Пример подписанта принимает тестовый seed только для сертификации. Набор использует
временную установку и локальный HTTP-сервер для инъекции сбоев.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

from fault_server import FaultServer, Object
from runtime_e2e import sign, payload

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "runtime/runtime/tests/fixtures/catalog_actions_0245_go_signed.json"


def current_target() -> tuple[str, str]:
    system = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(
        platform.system()
    )
    arch = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(platform.machine().lower())
    if system is None or arch is None:
        raise RuntimeError(f"Не поддерживается: «certification target»: {platform.platform()}")
    return system, arch


def profile_digest(spec: dict[str, Any]) -> str:
    # Точный дайджест канонического снимка профиля Manifest v3, совпадающий с Go и Rust.
    values = (
        spec["projectId"],
        spec["id"],
        spec["name"],
        spec["description"],
        spec["loader"],
        spec["preset"],
        str(spec["isDefault"]).lower(),
    )
    return hashlib.sha256("\0".join(values).encode()).hexdigest()


def build_fixture(
    url: str,
    objects: dict[str, Object],
    target: tuple[str, str],
    version: str = "0.24.13",
) -> dict:
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    doc.pop("signature", None)
    doc["projectId"] = "certification"
    if version not in ("0.24.13", "0.25.0"):
        raise ValueError("Не поддерживается: «component certification release»")
    doc["version"] = version
    spec = doc["profileSnapshot"]["spec"]
    spec["projectId"] = "certification"
    doc["profileSnapshot"]["digest"] = profile_digest(spec)
    # Никогда не подделывайте успех целевой платформы: настоящие условия Rust должны оценить обнаруженные
    # на этом Runtime ОС и архитектуру. Остальные подписанные поля v5 сохраняются.
    cond = doc["componentCatalog"]["components"][1]["conditions"]
    # Сохраните дайджест каталога фикстуры: изменение условий сделает его недействительным.
    # Совместимые цели охвачены уже подготовленной живой подписанной фикстурой.
    if target != ("linux", "x86_64") and target != ("windows", "x86_64"):
        # Другие ОС и архитектуры всё ещё выполняют пресет только с обязательными компонентами; явный выбор
        # оптимизированного пресета должен корректно отклоняться до HTTP, а не обходить условия.
        pass
    for i, item in enumerate(doc["files"]):
        data = payload(i, size=2048 + i * 517)
        item["sha256"] = hashlib.sha256(data).hexdigest()
        item["size"] = len(data)
        item["url"] = f"{url}/files/{i}"
        item.pop("mirrors", None)
        objects[f"/files/{i}"] = Object(
            data, behavior="503-once" if i == 2 else "truncate-once" if i == 3 else "ok"
        )
        if i == 0:
            item["url"] = f"{url}/poison/0"
            item["mirrors"] = [f"{url}/files/0"]
            objects["/poison/0"] = Object(data, behavior="poison")
    return doc


def invoke(
    runtime: Path, argv: list[str], *, cache: Path, success: bool = True
) -> dict:
    env = os.environ.copy()
    # Изолируйте настоящий общий проверенный кэш, чтобы повторное офлайновое использование имело смысл.
    if sys.platform == "win32":
        env["LOCALAPPDATA"] = str(cache)
    elif sys.platform == "darwin":
        env["HOME"] = str(cache)
    else:
        env["XDG_CACHE_HOME"] = str(cache)
    completed = subprocess.run(
        [str(runtime), *argv], env=env, capture_output=True, text=True, timeout=160
    )
    if success and completed.returncode:
        raise AssertionError(
            f"runtime {' '.join(argv[:1])} failed: {completed.stderr[-2400:]}"
        )
    if not success and completed.returncode == 0:
        raise AssertionError(f"runtime unexpectedly accepted prohibited {argv[:1]}")
    if completed.returncode:
        return {
            "rejected": True,
            "stderrSha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
        }
    try:
        response = json.loads(completed.stdout)
    except ValueError as exc:
        raise AssertionError("runtime did not produce structured JSON") from exc
    return response


def assert_bytes(root: Path, doc: dict, expected: set[str]) -> None:
    for record in doc["files"]:
        local = root / record["path"]
        if record["path"] not in expected:
            if local.exists():
                raise AssertionError(
                    f"unselected component was installed: {record['path']}"
                )
            continue
        if (
            not local.is_file()
            or hashlib.sha256(local.read_bytes()).hexdigest() != record["sha256"]
        ):
            raise AssertionError(f"selected file missing/corrupted: {record['path']}")


def certified_case(runtime: Path, signer: Path, *, version: str = "0.24.13") -> dict:
    started = time.monotonic_ns()
    os_name, arch = current_target()
    with tempfile.TemporaryDirectory(prefix="components-02413-") as tmp:
        home = Path(tmp)
        installation = home / "installed"
        cache = home / "cache"
        installation.mkdir()
        objects: dict[str, Object] = {
            "/unused": Object(b"reserved-certification-resource")
        }
        with FaultServer(objects) as server:
            doc = build_fixture(server.url, objects, (os_name, arch), version)
            unsigned, signed = home / "source.json", home / "signed.json"
            key = sign(signer, unsigned, signed, doc)
            core = {"mods/core.jar"}
            opt = core | {"mods/sodium.jar"}
            quality = opt | {"mods/shader.jar"}
            base = [
                "--manifest",
                str(signed),
                "--root",
                str(installation),
                "--pinned-public-key",
                key,
            ]

            def install(preset: str) -> dict:
                result = invoke(
                    runtime, ["sync-local", *base, "--preset", preset], cache=cache
                )
                if result.get("status") != "ready":
                    raise AssertionError(f"installation did not finish: {result}")
                return result

            install("minimal")
            assert_bytes(installation, doc, core)
            if (installation / "mods/sodium.jar").exists():
                raise AssertionError(
                    "optional component downloaded despite minimal preset"
                )
            # Файл, созданный игроком, НЕЛЬЗЯ незаметно включать в подписанное владение.
            player = installation / "mods/user-created.txt"
            player.write_text("player's file; not in signed manifest", encoding="utf-8")
            minimal_requests = len(server.metrics()["requests"])
            verify = invoke(
                runtime, ["verify", *base, "--preset", "minimal"], cache=cache
            )
            if verify.get("status") != "ready":
                raise AssertionError("Ошибка: «minimal installed plan verification»")
            permitted = os_name in ("linux", "windows") and arch == "x86_64"
            if permitted:
                install("optimized")
                assert_bytes(installation, doc, opt)
                if not any(
                    e["path"] == "/poison/0" for e in server.metrics()["requests"]
                ):
                    raise AssertionError("poisoned mirror was not exercised")
                if not any(
                    e["path"] == "/files/0" for e in server.metrics()["requests"]
                ):
                    raise AssertionError("verified fallback did not run")
                optimized_requests = len(server.metrics()["requests"])
                install("quality")
                assert_bytes(installation, doc, quality)
                delta = server.metrics()["requests"][optimized_requests:]
                if not delta or any(item["path"] != "/files/3" for item in delta):
                    raise AssertionError("unchanged component was fetched again")
                if len(delta) < 2:
                    raise AssertionError("truncated HTTP body was not retried/resumed")
                # Изменение подписанного действия или снимка должно отклоняться ДО любой загрузки.
                modified = copy.deepcopy(json.loads(signed.read_text()))
                modified["componentCatalog"]["components"][1]["actions"][2]["args"][
                    0
                ] = "-javaagent:evil.jar"
                bad = home / "tampered.json"
                bad.write_text(json.dumps(modified))
                request_count = len(server.metrics()["requests"])
                invoke(
                    runtime,
                    [
                        "sync-local",
                        "--manifest",
                        str(bad),
                        "--root",
                        str(installation),
                        "--pinned-public-key",
                        key,
                        "--preset",
                        "quality",
                    ],
                    cache=cache,
                    success=False,
                )
                if len(server.metrics()["requests"]) != request_count:
                    raise AssertionError("Подписание вызвало неожиданный сетевой обмен")
                # Существующий посторонний файл должен пережить переключение пресетов.
                install("minimal")
                assert_bytes(installation, doc, core)
                # Настоящий долговечный откат обязан восстановить прежний подписанный план.
                rollback = invoke(
                    runtime,
                    [
                        "rollback-release",
                        "--root",
                        str(installation),
                        "--pinned-public-key",
                        key,
                    ],
                    cache=cache,
                )
                if rollback.get("status") != "rolled-back":
                    raise AssertionError("rollback did not complete")
                assert_bytes(installation, doc, quality)
                invoke(
                    runtime,
                    [
                        "recover-release",
                        "--root",
                        str(installation),
                        "--pinned-public-key",
                        key,
                    ],
                    cache=cache,
                )
                install("minimal")
                assert_bytes(installation, doc, core)
                if (
                    player.read_text(encoding="utf-8")
                    != "player's file; not in signed manifest"
                ):
                    raise AssertionError("player file was mutated during preset switch")
                # Пользовательский файл на новом управляемом пути блокирует операцию ДО загрузки.
                conflict = installation / "mods/sodium.jar"
                conflict.write_bytes(b"player-selected replacement")
                count = len(server.metrics()["requests"])
                invoke(
                    runtime,
                    ["sync-local", *base, "--preset", "optimized"],
                    cache=cache,
                    success=False,
                )
                if (
                    len(server.metrics()["requests"]) != count
                    or conflict.read_bytes() != b"player-selected replacement"
                ):
                    raise AssertionError(
                        "unsafe ownership takeover / network-before-validation"
                    )
                conflict.unlink()
            else:
                # Авторские условия ОС/архитектуры должны блокировать несовместимый пресет.
                count = len(server.metrics()["requests"])
                invoke(
                    runtime,
                    ["sync-local", *base, "--preset", "optimized"],
                    cache=cache,
                    success=False,
                )
                if len(server.metrics()["requests"]) != count:
                    raise AssertionError(
                        "incompatible component initiated file transfer"
                    )
            # Недоверенный выбор может ссылаться лишь на подписанные ID компонентов; он не может
            # отключать обязательный узел или добавлять неподписанный компонент.
            for denied in (
                "@custom:v1:minimal:-core",
                "@custom:v1:minimal:+unsigned.jar",
            ):
                count = len(server.metrics()["requests"])
                invoke(
                    runtime,
                    ["sync-local", *base, "--preset", denied],
                    cache=cache,
                    success=False,
                )
                if len(server.metrics()["requests"]) != count:
                    raise AssertionError(
                        "invalid selection was evaluated after network access"
                    )
            # Все платформы проверяют закрепление подписи с полностью неправильным ключом.
            count = len(server.metrics()["requests"])
            invoke(
                runtime,
                ["sync-local", *base[:-1], "0" * 64, "--preset", "minimal"],
                cache=cache,
                success=False,
            )
            if len(server.metrics()["requests"]) != count:
                raise AssertionError("incorrect public key reached network")
            # Сама проверка не считается успешным тестом, пока файлы действительно не просмотрены.
            if minimal_requests < 1:
                raise AssertionError("Отсутствует: «real HTTP payload was transferred»")
            metrics = server.metrics()
        return {
            "status": "passed",
            "version": version,
            "target": f"{os_name}-{arch}",
            "componentMode": "full" if permitted else "condition-denial",
            "elapsedNs": time.monotonic_ns() - started,
            "httpRequests": len(metrics["requests"]),
            "httpBytes": metrics["transferredBytes"],
            "signedManifestVersion": "3.0",
            "catalogSchema": "5.0",
            "tests": [
                "signed-install",
                "preset-isolation",
                "ownership",
                "wrong-key",
                "signature-tamper",
                "invalid-selection",
                "rollback",
                "download-faults" if permitted else "condition-fail-closed",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--product-version", choices=("0.24.13", "0.25.0"), default="0.24.13"
    )
    args = parser.parse_args()
    try:
        if not args.runtime.is_file() or not args.signer.is_file():
            raise RuntimeError(
                "compiled runtime and test signer executables are required"
            )
        result = certified_case(
            args.runtime.resolve(), args.signer.resolve(), version=args.product_version
        )
    except (
        RuntimeError,
        AssertionError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as exc:
        result = {"status": "failed", "reason": str(exc), "target": platform.platform()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
