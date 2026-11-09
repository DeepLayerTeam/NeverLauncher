#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 8):
    raise SystemExit(f"Loader-native E2E: требуется версия не ниже 0.17.8, получено {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


compose = read("e2e/docker-compose.minecraft-e2e.yml")
require(
    compose,
    [
        "loader-native:",
        "itzg/minecraft-server:java21",
        "LAUNCHER_E2E_NATIVE_SERVER_TYPE",
        "LAUNCHER_E2E_NATIVE_MINECRAFT_VERSION",
        "FABRIC_LOADER_VERSION",
        "QUILT_LOADER_VERSION",
        "FORGE_VERSION",
        "NEOFORGE_VERSION",
        '"25580:25565"',
        "mc-health",
        "./runtime/loader-native-server:/data",
    ],
    "Выделенный сервер для нативного загрузчика",
)

native = read("e2e/scripts/run-loader-native-e2e.sh")
require(
    native,
    [
        "RESOLVED_LOADER_VERSION",
        "mutable loader selector is forbidden",
        "fabric-loader",
        "quilt-loader",
        "minecraftforge/forge",
        "neoforged/neoforge",
        "certify-vanilla",
        "--server 127.0.0.1",
        "--server-port",
        "NL_Cert_Client joined the game",
        "loader-native-server-artifacts.txt",
        "exact loader version",
        "nativeHandshake",
        "actual-client-joined-dedicated-loader-server",
    ],
    "Исполнение нативного загрузчика",
)

integration = read("e2e/scripts/run-minecraft-e2e.sh")
require(
    integration,
    [
        "LAUNCHER_E2E_RESOLVED_LOADER_VERSION",
        "LAUNCHER_E2E_LOADER_CLIENT_PROFILE_ID",
        "run-loader-native-e2e.sh",
        "loader-native-server.json",
        "loaderNativeE2E",
        "loaderNativeServer",
        "loaderNativeClientJoin",
        "loaderVersionMatched",
    ],
    "Интеграция маршрутизации нативных загрузчиков",
)

compat = read("e2e/scripts/run-compatibility-case.sh")
require(
    compat,
    [
        "loader-native-server.json",
        "loader-native-client.json",
        "health-loader-native.json",
        "loaderNativeServer",
        "loaderVersionMatched",
        "loaderServerHealthy",
        "loaderNativeClientJoin",
    ],
    "Свидетельства совместимости нативных загрузчиков",
)

matrix = read("scripts/compatibility/matrix.py")
require(
    matrix,
    [
        "loader_native_e2e_0178_required",
        "Loader-native E2E 0.17.8 requires exactly one",
        "loaderNativeServer",
        "loaderVersionMatched",
        "loaderServerHealthy",
        "loaderNativeClientJoin",
        "loader-native-server-artifacts.txt",
        "health-loader-native.json",
    ],
    "Обязательная проверка нативных загрузчиков в матрице",
)

release = read("cli/cmd/launcher/compatibility_release.go")
require(
    release,
    [
        "LoaderNativeTargets",
        "compatibilityLoaderNativeE2E0178Required",
        "loaderNativeServer",
        "loaderVersionMatched",
        "loaderServerHealthy",
        "loaderNativeClientJoin",
        "fabric-1.21.1-linux-x64",
        "quilt-1.21.1-linux-x64",
        "forge-1.21.1-linux-x64",
        "neoforge-1.21.1-linux-x64",
        "loader-native-e2e-0.17.8-fabric-quilt-forge-neoforge-client-server-exact-loader-join",
    ],
    "Обязательная сертификация нативных загрузчиков",
)

tests = read("cli/cmd/launcher/compatibility_release_test.go") + read(
    "scripts/compatibility/test_matrix.py"
)
require(
    tests,
    [
        "TestCompatibilityCertificationLoaderNativeE2E0178",
        "TestCompatibilityCertificationLoaderNativeE2E0178RejectsMissingJoin",
        "TestCompatibilityCertificationLoaderNativeE2E0178BundleRejectsTamperedCoverage",
        "test_validate_0178_requires_loader_native_integration_anchor",
        "test_0178_aggregate_rejects_missing_loader_native_join",
        "test_0178_aggregate_rejects_missing_loader_native_evidence",
    ],
    "Регрессионные тесты нативных загрузчиков 0.17.8",
)

workflow = read(".github/workflows/compatibility.yml")
for required in [
    "loader-native-server.json",
    "loader-native-client.json",
    "loader-native-server.log",
    "loader-native-server-artifacts.txt",
    "loader-native-server-process.txt",
    "health-loader-native.json",
]:
    if f"e2e/runtime/{required}" not in workflow:
        raise SystemExit(
            f"Сценарий проверки совместимости не сохраняет нативные подтверждения загрузчика: {required}"
        )

print(
    "Проверка нативного E2E загрузчиков 0.17.8: OK (реальный клиент Fabric/Quilt/Forge/NeoForge, сервер точной версии и подтверждение подключения)"
)
