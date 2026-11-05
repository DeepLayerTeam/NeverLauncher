#!/usr/bin/env python3
"""Итоговая приёмка с блокировкой при неопределённости для *собранной* сети ServerBridge 0.42.0.

Это исполняемая граница выпуска, а не генератор сертификатов. Проверяются точные скопированные
JAR-файлы выпуска, независимо записанные реальные свидетельства Minecraft/JVM/Proxy, настоящее
восстановление мира Paper и сценарии игрока/отката. Одного успешного модульного теста, подписанного
манифеста или сборки недостаточно.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from serverbridge.live_matrix_04113 import certify  # noqa: E402

HEX = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
TARGETS = (
    "velocity",
    "bungeecord",
    "waterfall",
    "bukkit",
    "spigot",
    "paper",
    "purpur",
    "folia",
    "fabric",
    "quilt",
    "forge",
    "neoforge",
    "sponge",
    "vanilla",
)


class ReleaseBlocked(Exception):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ReleaseBlocked(why)


def read_json(path: Path) -> dict:
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= 16 * 1024 * 1024,
        f"Свидетельство отсутствует, является ссылкой или превышает размер: {path}",
    )

    def unique(pairs):
        obj = {}
        for k, v in pairs:
            require(k not in obj, f"Повторяющееся поле JSON {k}: {path.name}")
            obj[k] = v
        return obj

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    require(type(value) is dict, f"Ожидался объект JSON: {path.name}")
    return value


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_final_jars(root: Path, release: Path, version: str) -> dict:
    # Сравнивайте три независимых набора байтов и утверждений: JAR сборки Gradle,
    # поставляемый JAR финального каталога и замороженный сборочный манифест.
    manifest = read_json(release / "BRIDGE_PLUGIN_MANIFEST.json")
    require(manifest.get("toolVersion") == version, "Версия манифеста ServerBridge не совпадает")
    rows = manifest.get("artifacts")
    require(
        type(rows) is list and len(rows) == len(TARGETS),
        "Неполный набор артефактов Bridge",
    )
    require(
        [row.get("id") for row in rows if type(row) is dict] == list(TARGETS),
        "Целевая платформа ServerBridge отсутствует в ожидаемом порядке, повторяется или не предусмотрена выпуском",
    )
    results = {}
    seen = set()
    for target, row in zip(TARGETS, rows):
        filename = f"launcher-{target}-bridge-{version}.jar"
        require(
            row.get("file") == filename
            and HEX.fullmatch(str(row.get("sha256"))) is not None,
            f"{target}: неверное имя манифеста или хеш",
        )
        original = root / "artifacts/plugins" / filename
        shipped = release / filename
        for item in (original, shipped):
            require(
                item.is_file()
                and not item.is_symlink()
                and item.stat().st_size >= 1024,
                f"{target}: Отсутствует или вызывает сомнения итоговый артефакт Java: {item}",
            )
        original_hash = digest(original)
        shipped_hash = digest(shipped)
        require(
            original_hash == shipped_hash == row["sha256"],
            f"{target}: Итоговый JAR выпуска отличается от фактически сертифицированной сборки",
        )
        require(
            shipped_hash not in seen, f"{target}: повторяющийся JAR Runtime с идентичным содержимым"
        )
        seen.add(shipped_hash)
        results[target] = shipped_hash
    for name in ("BRIDGE_RELEASE_ALLOWLIST.json", "SERVERBRIDGE3_CERTIFICATION.json"):
        require(
            (release / name).is_file() and not (release / name).is_symlink(),
            f"Отсутствует артефакт безопасности выпуска: {name}",
        )
    return results


def verify_faults(runtime: Path, version: str, commit: str) -> None:
    from scripts.ga.record_network_faults_0420 import REQUIRED, validate

    proof = read_json(runtime / "network-faults-0420.json")
    require(
        proof.get("version") == version
        and proof.get("sourceCommit") == commit
        and proof.get("status") == "passed"
        and proof.get("raceDetector") is True,
        "Отчёт о сбоях хоста, JVM и состязательных условиях не соответствует точному выпуску",
    )
    require(
        proof.get("logFile") == "network-faults-0420.go-test.jsonl",
        "Неверный журнал отказа узла",
    )
    log = runtime / proof["logFile"]
    fresh = validate(log, commit, version)
    require(
        proof == fresh and set(proof["tests"]) == set(REQUIRED),
        "отчёт о сбоях хоста не соответствует фактическим событиям JSON-тестов",
    )


def verify_e2e_files(runtime: Path, version: str, commit: str) -> None:
    result = read_json(runtime / "result.json")
    require(
        result.get("version") == version
        and result.get("mode") == "full"
        and result.get("status") == "passed",
        "Полная реальная проверка Minecraft E2E не пройдена",
    )
    checks = result.get("checks") or {}
    require(
        all(
            checks.get(k) is True
            for k in (
                "actualClient",
                "paperJoin",
                "sessionRevokeDeny",
                "realWorldBackupRestore",
                "realGameUpdateRollback",
                "liveServerBridgeCore",
            )
        ),
        "Отсутствует полное подтверждение работы клиента, подключения, отзыва, восстановления мира и отката обновления",
    )
    evidence_names = result.get("evidence")
    require(
        type(evidence_names) is list
        and len(evidence_names) == len(set(evidence_names)),
        "Повторяющийся или некорректный индекс свидетельств Runtime",
    )
    required = (
        "world-backup-0290.json",
        "game-cycle-0364-result.json",
        "live-matrix-core-04113.json",
    )
    require(
        all(name in evidence_names for name in required),
        "В индексе отсутствует свидетельство выполнения",
    )
    for name in required:
        read_json(runtime / name)
    # Прежние независимые верификаторы проверяют реальные счётчики игрового процесса, хеши
    # файлов, одноразовые билеты, идентичности игроков и восстановление.
    checks_to_run = (
        (
            "scripts/ga/verify_server_control_0290.py",
            [
                "--e2e-dir",
                str(runtime),
                "--version",
                version,
                "--source-commit",
                commit,
            ],
        ),
        (
            "scripts/ga/verify_game_cycle_0364.py",
            [
                "--e2e-dir",
                str(runtime),
                "--version",
                version,
                "--source-commit",
                commit,
            ],
        ),
        (
            "scripts/ga/verify_player_cycle_0398.py",
            [
                "--e2e-dir",
                str(runtime),
                "--version",
                version,
                "--source-commit",
                commit,
            ],
        ),
    )
    for script, arguments in checks_to_run:
        try:
            proc = subprocess.run(
                [sys.executable, str(ROOT / script), *arguments],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReleaseBlocked(f"{script}: истекло время проверки подтверждений") from exc
        require(
            proc.returncode == 0,
            f"{script}: отклонено реальное свидетельство E2E: {proc.stderr[-1000:]}",
        )


def accept(root: Path, release: Path, runtime: Path, commit: str) -> dict:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    from scripts.ga.record_network_faults_0420 import network_gate_version

    require(network_gate_version(version), "Для сетевой проверки требуется версия не ниже 0.42.0")
    require(COMMIT.fullmatch(commit) is not None, "Требуется SHA-код реального исходного коммита")
    hashes = verify_final_jars(root, release, version)
    matrix = certify(root, runtime, "all")
    require(
        matrix.get("status") == "passed" and matrix.get("passedCount") == len(TARGETS),
        "Неполная матрица реальных JVM/Minecraft/Proxy: "
        + ", ".join(
            f"{name}={matrix.get('cases', {}).get(name, {}).get('reason', 'no live proof')}"
            for name in TARGETS
            if matrix.get("cases", {}).get(name, {}).get("status") != "passed"
        ),
    )
    for name in TARGETS:
        proof_path = runtime / f"live-{name}-04113.json"
        proof = read_json(proof_path)
        require(
            proof.get("sourceCommit") == commit,
            f"{name}: Свидетельство работы JVM получено для другого исходного коммита",
        )
        require(
            matrix["cases"][name].get("bridgeJarSha256") == hashes[name],
            f"{name}: реальное подтверждение не привязано к финальным байтам JAR",
        )
    verify_faults(runtime, version, commit)
    verify_e2e_files(runtime, version, commit)
    return {
        "schemaVersion": "launcher.server-network.acceptance.0420/v1",
        "version": version,
        "sourceCommit": commit,
        "status": "passed",
        "runtime": "real-minecraft-jvm-proxy",
        "targetCount": len(TARGETS),
        "checks": {
            "allTargetsRealJvm": True,
            "allReleaseJarDigestsMatch": True,
            "actualMinecraftClientJoin": True,
            "sessionRevocation": True,
            "worldBackupRestore": True,
            "gameUpdateRollback": True,
            "playerAuthorizationNegativeCases": True,
            "realJvmHostFaultsAndRaceDetector": True,
        },
        "bridgeJarsSha256": hashes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        outcome = accept(args.root, args.release, args.runtime, args.source_commit)
    except (
        ReleaseBlocked,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"РАБОЧИЙ СЕТЕВОЙ РЕЛИЗ ЗАБЛОКИРОВАН: {exc}", file=sys.stderr)
        return 2
    serialized = (
        json.dumps(outcome, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.out.with_suffix(args.out.suffix + ".tmp")
        temporary.write_text(serialized, encoding="utf-8")
        temporary.replace(args.out)
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
