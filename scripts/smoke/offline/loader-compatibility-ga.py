#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(
    int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3]
)
if core < (0, 18, 0):
    raise SystemExit(f"приёмка совместимости загрузчиков: требуется версия не ниже 0.18.0, получено {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


runtime = read("cli/cmd/launcher/loader_ga.go")
require(
    runtime,
    [
        "loaderGASupport0180",
        "enforceLoaderGASupport0180",
        "validateLoaderGASupportPolicy0180",
        "loaderGASupportSHA2560180",
        "fabricCompatibilityII0171",
        "quiltCompatibilityII0172",
        "forgeModern0173",
        "forgeLegacy1122_0174",
        "forgeLegacy1710_0175",
        "neoForgeCompatibilityII0176",
        "не входит в сертифицированный набор GA",
        "requires Java",
    ],
    "Политика поддержки Runtime для GA",
)

meta = read("cli/cmd/launcher/loader_runtime.go")
forge = read("cli/cmd/launcher/forge_runtime.go")
for name, text in [
    ("Fabric/Quilt materializer", meta),
    ("Forge/NeoForge materializer", forge),
]:
    require(
        text,
        [
            "EnforceGASupport",
            "enforceLoaderGASupport0180",
            "compatibilityLoaderGA0180Required(version)",
        ],
        name,
    )

cert = read("cli/cmd/launcher/compatibility_release_certificate.go")
require(
    cert,
    [
        'status = "ga-certified"',
        'releaseStage = "ga"',
        "RuntimeSupportSHA256",
        "RuntimeSupportEntries",
        "LegacyForgeVersions",
        "gaRuntimeSupportEnforced",
        "legacyForgeGA",
        "loader-compatibility-ga-0.18.0-runtime-enforced-fabric-quilt-forge-neoforge-legacy-all-292-targets-signed-bundle",
    ],
    "Сертификат релиза GA",
)

release = read("cli/cmd/launcher/release_commands.go")
require(
    release,
    [
        "loaderCompatibilityGA",
        "loaderCompatibilityGASupportSha256",
        "Loader Compatibility GA 0.18.0",
        "loaderGASupportSHA2560180",
        "ga-certified",
    ],
    "Принудительная проверка публикации релиза GA",
)

workflow = read(".github/workflows/production-release-candidate.yml")
require(
    workflow,
    [
        'status == "ga-certified"',
        "loaderCompatibilityGA == true",
        "loaderCompatibilityGASupportSha256",
    ],
    "Проверка рабочего процесса промышленного выпуска GA",
)

tests = read("cli/cmd/launcher/loader_ga_test.go") + read(
    "cli/cmd/launcher/compatibility_release_certificate_test.go"
)
require(
    tests,
    [
        "TestLoaderGASupport0180ExactCertifiedSurface",
        "TestLoaderGASupport0180RejectsJavaDrift",
        "TestLoaderGA0180ProductionParsersEnableRuntimeGuard",
        "TestLoaderGA0180ProductionParsersRejectUnsupportedConcreteVersionBeforeInstall",
        "TestLoaderCompatibilityGA0180CertificateBindsRuntimeSupport",
        "TestLoaderCompatibilityGA0180RejectsCertifiedRuntimeSurfaceDrift",
        "TestLoaderCompatibilityGA0180RejectsTamperedRuntimeSupportHash",
    ],
    "Регрессионные тесты GA",
)

targets = json.loads(read("compatibility/targets.json"))["targets"]
# Покрытие каталога отличается от сертификации релизов. Недоступные у
# издателя комбинации видны с явной причиной, но не засчитываются как PASS.
required = [row for row in targets if row.get("required")]
unavailable = [row for row in targets if not row.get("required")]
blocked = {
    ("quilt", minecraft): "upstream-missing"
    for minecraft in ("1.14", "1.14.1", "1.14.2", "1.14.3")
} | {
    ("neoforge", minecraft): "upstream-prerelease-only"
    for minecraft in (
        "1.20.3",
        "1.20.5",
        "1.21.2",
        "1.21.6",
        "1.21.7",
        "1.21.9",
        "26.1",
        "26.1.1",
    )
}
if len(targets) != 292 or len(required) != 280 or len(unavailable) != len(blocked):
    raise SystemExit(
        "Каталог совместимости должен содержать 292 целевые конфигурации: 280 обязательных и 12 явно недоступных у поставщика"
    )
if {
    (row.get("loader"), row.get("minecraft")): row.get("unavailableReason")
    for row in unavailable
} != blocked:
    raise SystemExit("Набор целей или причина недоступности источника не соответствует ожидаемым")
if any((row.get("os"), row.get("arch")) != ("linux", "x86_64") for row in unavailable):
    raise SystemExit("Неожиданное значение: «недоступная платформа»")
family_counts = Counter(row.get("loader") for row in targets)
expected_families = {
    "vanilla": 109,
    "fabric": 53,
    "quilt": 53,
    "forge": 50,
    "neoforge": 27,
}
if dict(family_counts) != expected_families:
    raise SystemExit(
        f"Охват семейств загрузчиков общедоступного выпуска: несоответствие — {dict(family_counts)}"
    )

unique_versions = {
    loader: sorted({row["minecraft"] for row in targets if row.get("loader") == loader})
    for loader in ("fabric", "quilt", "forge", "neoforge")
}
expected_unique = {"fabric": 48, "quilt": 48, "forge": 45, "neoforge": 22}
for loader, want in expected_unique.items():
    if len(unique_versions[loader]) != want:
        raise SystemExit(
            f"Проверка совместимости загрузчиков GA {loader}: уникальных версий={len(unique_versions[loader])}, ожидается={want}"
        )
if "1.7.10" not in unique_versions["forge"] or "1.12.2" not in unique_versions["forge"]:
    raise SystemExit(
        "Проверка совместимости загрузчиков GA должна включать устаревший Forge 1.7.10 и 1.12.2"
    )

print(
    "Проверка совместимости загрузчиков GA 0.18.0: OK (163 сочетания загрузчика и версии, контролируемых Runtime; 292 цели каталога, 280 обязательных, 12 NOT CERTIFIED, Fabric/Quilt/Forge/NeoForge и устаревшие версии)"
)
print('Loader Compatibility GA 0.18.0 gate: OK')
