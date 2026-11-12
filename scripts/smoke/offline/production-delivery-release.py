#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def triple(v: str) -> tuple[int, int, int]:
    core = v.split("-", 1)[0].split("+", 1)[0]
    return tuple(int(x) for x in core.split(".")[:3])  # type: ignore[return-value]


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


if triple(VERSION) < (0, 16, 0):
    raise SystemExit(
        f"Production Delivery Release: требуется версия не ниже 0.16.0, получено {VERSION}"
    )
if "-" in VERSION or "+" in VERSION:
    raise SystemExit(f"Промышленный выпуск поставки: требуется семантическая версия GA, получено {VERSION}")

impl = (ROOT / "cli/cmd/launcher/production_delivery_release_0160.go").read_text(
    encoding="utf-8"
)
tests = (ROOT / "cli/cmd/launcher/production_delivery_release_0160_test.go").read_text(
    encoding="utf-8"
)
release = (ROOT / "cli/cmd/launcher/release_commands.go").read_text(encoding="utf-8")
build = (ROOT / "scripts/release/build-release.sh").read_text(encoding="utf-8")
bundle = (ROOT / "scripts/smoke/release-required/release-bundle.sh").read_text(
    encoding="utf-8"
)
public_delivery = (ROOT / "cli/cmd/launcher/public_delivery_matrix.go").read_text(
    encoding="utf-8"
)
public_workflow = (ROOT / ".github/workflows/public-production-delivery.yml").read_text(
    encoding="utf-8"
)

require(
    impl,
    [
        "PRODUCTION_DELIVERY_RELEASE.json",
        "production-delivery-release",
        "stable-versioned-public-origin",
        "productionDeliveryReleaseBoundaryDigest0160",
        "versionedPublicBaseURL0160",
        "verifyProductionDeliveryRelease0160",
        "productionReleaseCandidateFile01511",
        "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json"
        if False
        else "publicProductionDeliveryMatrixFile0159",
        "PostPublishE2E",
    ],
    "Реализация промышленной поставки релиза",
)
require(
    release,
    [
        'case "production-verify":',
        "writeProductionDeliveryRelease0160",
        "verifyProductionDeliveryRelease0160",
        "production-delivery-release-stable-six-target-ga",
        "productionDeliveryReleaseSha256",
        'manifest["channel"] = productionDeliveryReleaseChannel0160',
    ],
    "Интеграция релиза",
)
require(
    build,
    [
        "PRODUCTION_DELIVERY_RELEASE_REQUIRED",
        "PRODUCTION_DELIVERY_RELEASE.json",
        "release production-verify",
        "неизменяемый сегмент версии",
    ],
    "Интеграция промышленной сборки",
)
require(
    bundle,
    ["PRODUCTION_DELIVERY_RELEASE.json", "release publish-check"],
    "Обязательная проверка комплекта релиза",
)
require(
    public_delivery,
    [
        "production-delivery-release",
        "ProductionDeliveryReleaseVerified",
        "verifyProductionDeliveryRelease0160",
    ],
    "Публичная сквозная интеграция",
)
require(
    public_workflow,
    [
        "PRODUCTION_DELIVERY_RELEASE.json",
        "release production-verify",
        "productionDeliveryReleaseVerified",
    ],
    "Проверка готовности GA после публикации",
)
require(
    tests,
    [
        "TestProductionDeliveryRelease0160BindsCandidateAndAnchors",
        "TestProductionDeliveryRelease0160RejectsUnversionedPublicOrigin",
        "TestProductionDeliveryRelease0160RejectsPrereleaseSemver",
    ],
    "Тесты промышленной поставки релиза",
)

subprocess.run(
    [
        "go",
        "test",
        "./cmd/launcher",
        "-run",
        "TestProductionDeliveryRelease0160",
        "-count=1",
    ],
    cwd=ROOT / "cli",
    check=True,
)
print(f"Launcher {VERSION}: проверка производственной поставки 0.16.0: OK")
