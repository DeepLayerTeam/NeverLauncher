#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 8):
    raise SystemExit(f"Нативный для загрузчика E2E требует VERSION>=0.17.8, получил {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствующий {missing}")

compose = read("e2e/docker-compose.minecraft-e2e.yml")
require(compose, [
    "loader-native:", "itzg/minecraft-server:java21",
    "NEVERLAUNCHER_E2E_NATIVE_SERVER_TYPE", "NEVERLAUNCHER_E2E_NATIVE_MINECRAFT_VERSION",
    "FABRIC_LOADER_VERSION", "QUILT_LOADER_VERSION", "FORGE_VERSION", "NEOFORGE_VERSION",
    '"25580:25565"', "mc-health", "./runtime/loader-native-server:/data",
], "loader-native dedicated server")

native = read("e2e/scripts/run-loader-native-e2e.sh")
require(native, [
    "RESOLVED_LOADER_VERSION", "mutable loader selector is forbidden",
    "fabric-loader", "quilt-loader", "minecraftforge/forge", "neoforged/neoforge",
    "certify-vanilla", "--server 127.0.0.1", "--server-port",
    "NeverLauncherCertification joined the game", "loader-native-server-artifacts.txt",
    "exact loader version", "nativeHandshake", "actual-client-joined-dedicated-loader-server",
], "loader-native execution")

integration = read("e2e/scripts/run-minecraft-e2e.sh")
require(integration, [
    "NEVERLAUNCHER_E2E_RESOLVED_LOADER_VERSION", "NEVERLAUNCHER_E2E_LOADER_CLIENT_PROFILE_ID",
    "run-loader-native-e2e.sh", "loader-native-server.json", "loaderNativeE2E",
    "loaderNativeServer", "loaderNativeClientJoin", "loaderVersionMatched",
], "integration loader-native routing")

compat = read("e2e/scripts/run-compatibility-case.sh")
require(compat, [
    "loader-native-server.json", "loader-native-client.json", "health-loader-native.json",
    "loaderNativeServer", "loaderVersionMatched", "loaderServerHealthy", "loaderNativeClientJoin",
], "compatibility loader-native evidence")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, [
    "loader_native_e2e_0178_required", "Loader-native E2E 0.17.8 requires exactly one",
    "loaderNativeServer", "loaderVersionMatched", "loaderServerHealthy", "loaderNativeClientJoin",
    "loader-native-server-artifacts.txt", "health-loader-native.json",
], "matrix loader-native enforcement")

release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, [
    "LoaderNativeTargets", "compatibilityLoaderNativeE2E0178Required",
    "loaderNativeServer", "loaderVersionMatched", "loaderServerHealthy", "loaderNativeClientJoin",
    "fabric-1.21.1-linux-x64", "quilt-1.21.1-linux-x64", "forge-1.21.1-linux-x64", "neoforge-1.21.1-linux-x64",
    "loader-native-e2e-0.17.8-fabric-quilt-forge-neoforge-client-server-exact-loader-join",
], "release certification loader-native enforcement")

tests = read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("scripts/compatibility/test_matrix.py")
require(tests, [
    "TestCompatibilityCertificationLoaderNativeE2E0178",
    "TestCompatibilityCertificationLoaderNativeE2E0178RejectsMissingJoin",
    "TestCompatibilityCertificationLoaderNativeE2E0178BundleRejectsTamperedCoverage",
    "test_validate_0178_requires_loader_native_integration_anchor",
    "test_0178_aggregate_rejects_missing_loader_native_join",
    "test_0178_aggregate_rejects_missing_loader_native_evidence",
], "0.17.8 loader-native regression tests")

workflow = read(".github/workflows/compatibility.yml")
for required in [
    "loader-native-server.json", "loader-native-client.json", "loader-native-server.log",
    "loader-native-server-artifacts.txt", "loader-native-server-process.txt", "health-loader-native.json",
]:
    if f"e2e/runtime/{required}" not in workflow:
        raise SystemExit(f"совместимость процесс делает не сохранять нативный для загрузчика свидетельство: {required}")

print("Нативный для загрузчика E2E 0.17.8 контроль: OK (Fabric/Quilt/Forge/NeoForge реальный клиент ↔ точная версия выделенный загрузчик сервер + реальный подключение свидетельство)")
