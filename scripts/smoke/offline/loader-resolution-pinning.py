#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 7):
    raise SystemExit(
        f"Loader Resolution & Pinning: требуется версия не ниже 0.17.7, получено {version}"
    )


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


resolution = read("cli/cmd/launcher/loader_resolution.go")
require(
    resolution,
    [
        "loaderResolutionLockSchema",
        "ResolvedVersion",
        "ResolutionSourceSHA256",
        "PayloadSHA256",
        "RuntimeProfileSHA256",
        "MaterializationSHA256",
        "ReproducibilitySHA256",
        "persistLoaderResolutionLock",
        "readLoaderResolutionLock",
        "assertPinnedPayload",
        "assertPinnedRuntimeProfile",
    ],
    "Фиксация разрешения зависимостей загрузчика",
)

meta = read("cli/cmd/launcher/loader_runtime.go")
require(
    meta,
    [
        "--resolution-lock",
        "resolveMetaLoaderVersionWithEvidence",
        "resolutionSourceSHA256",
        "persistLoaderResolutionLock",
        "ResolutionPinned",
        "assertPinnedPayload",
        "assertPinnedRuntimeProfile",
    ],
    "Закрепление версий при разрешении зависимостей Fabric/Quilt",
)

forge = read("cli/cmd/launcher/forge_runtime.go")
require(
    forge,
    [
        "--resolution-lock",
        "resolveForgeLikeVersionWithEvidence",
        "sha256HexBytes(data)",
        "persistLoaderResolutionLock",
        "ResolutionPinned",
        "assertPinnedPayloadSHA256",
        "assertPinnedRuntimeProfile",
    ],
    "Закрепление версий при разрешении зависимостей Forge/NeoForge",
)

for loader in ("fabric", "quilt", "forge", "neoforge"):
    case = read(f"e2e/scripts/run-{loader}-certification-case.sh")
    require(
        case,
        [
            "--resolution-lock",
            "resolutionPinned",
            "reproducibilitySha256",
            "resolutionLockSha256",
            f"{loader}-resolution-lock.json",
        ],
        f"{loader} replay certification",
    )

integration = read("e2e/scripts/run-minecraft-e2e.sh")
require(
    integration,
    [
        "--resolution-lock",
        "FIRST_LOCK_SHA256",
        "resolutionPinned",
        "reproducibilitySha256",
        "loaderResolution",
        "sourceSha256",
    ],
    "Интеграционная сертификация защиты от повторов",
)

compat = read("e2e/scripts/run-compatibility-case.sh")
require(
    compat,
    [
        "resolutionLockSha256",
        "resolutionSourceSha256",
        "reproducibilitySha256",
        '"loaderPinned"',
        '"reproducibleResolution"',
        "-resolution-lock.json",
    ],
    "Свидетельства фиксации версий по результатам проверки совместимости",
)

matrix = read("scripts/compatibility/matrix.py")
require(
    matrix,
    [
        "loader_resolution_pinning_0177_required",
        "resolutionLockSha256",
        "resolutionSourceSha256",
        "reproducibilitySha256",
        "loaderPinned",
        "reproducibleResolution",
    ],
    "Обязательная фиксация версий в сводной проверке совместимости",
)

release = read("cli/cmd/launcher/compatibility_release.go")
require(
    release,
    [
        "releaseCompatibilityLoaderPin",
        "LoaderPins",
        "compatibilityLoaderResolution0177Required",
        "loader-resolution-pinning-0.17.7-immutable-lock-upstream-sha256-profile-sha256-replay",
    ],
    "Обязательная проверка закреплённых версий при сертификации",
)

tests = (
    read("cli/cmd/launcher/loader_resolution_test.go")
    + read("cli/cmd/launcher/loader_runtime_test.go")
    + read("cli/cmd/launcher/compatibility_release_test.go")
    + read("scripts/compatibility/test_matrix.py")
)
require(
    tests,
    [
        "TestLoaderResolutionLockRoundTripAndTamperDetection",
        "TestFabricAndQuiltMaterializersProduceConsumableClientTree",
        "TestCompatibilityCertificationLoaderResolutionPinning0177",
        "test_0177_aggregate_rejects_missing_loader_resolution_pin",
    ],
    "Регрессионные тесты закрепления версий 0.17.7",
)

workflow = read(".github/workflows/compatibility.yml")
for loader in ("fabric", "quilt", "forge", "neoforge"):
    if f"e2e/runtime/{loader}-resolution-lock.json" not in workflow:
        raise SystemExit(
            f"Сценарий проверки совместимости не архивирует блокировку разрешения версии {loader}"
        )

print(
    "Проверка разрешения и закрепления загрузчика 0.17.7: OK (неизменяемый загрузчик, SHA-256 источника, данных и профиля, воспроизводимость по файлу блокировки)"
)
