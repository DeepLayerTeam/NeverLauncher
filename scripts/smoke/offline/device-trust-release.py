#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import json, subprocess, sys

ROOT = Path(__file__).resolve().parents[3]


def read(p):
    return (ROOT / p).read_text(encoding="utf-8")


def req(text, needles, label):
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


version = read("VERSION").strip()
core = version.split("-", 1)[0].split("+", 1)[0]
try:
    version_tuple = tuple(int(x) for x in core.split("."))
except ValueError:
    raise SystemExit(f"Некорректное значение VERSION: {version}")
if len(version_tuple) != 3 or version_tuple < (0, 13, 0):
    raise SystemExit(f"Device Trust Release: требуется версия не ниже 0.13.0, получено {version}")
api_migs = sorted((ROOT / "services/api/internal/dbmigrate/sql").glob("*.sql"))
cli_migs = migration_catalog(ROOT)
if [p.name for p in api_migs] != sorted(cli_migs):
    raise SystemExit("Каталоги миграций API/CLI отличаются")
if not any(p.name == "0018_device_trust_stabilization_01210.sql" for p in api_migs):
    raise SystemExit(
        "Версия 0.13+ должна сохранять запечатанную стабилизационную миграцию Device Trust 0018"
    )
for a in api_migs:
    if a.read_bytes() != cli_migs[a.name]:
        raise SystemExit(f"Миграция отличается: {a.name}")
release = read("cli/cmd/launcher/device_trust_release.go")
req(
    release,
    [
        "DEVICE_TRUST_TARGETS.json",
        "DEVICE_TRUST_MATRIX.json",
        "DEVICE_TRUST_CERTIFICATION.json",
        "deviceTrustCertificationRequired",
        "all-required-device-trust-targets-must-pass-exact-commit-evidence",
        "deviceTrustRelease0130",
    ],
    "Сертификация доверия к устройствам через CLI",
)
runtime = read("services/api/internal/httpapi/device_trust_release_0130.go")
req(
    runtime,
    [
        "0018_device_trust_stabilization_01210",
        "sessionDeviceBinding",
        "deviceBoundRefresh",
        "minecraftServerBridge",
        "not-remotely-verified",
        "exact-commit-public-device-trust-matrix",
    ],
    "Контракт выпуска Runtime",
)
e2e = read("e2e/scripts/run-device-trust-e2e.sh")
req(
    e2e,
    [
        "release-capabilities.json",
        "release-readiness.json",
        "deviceTrustRelease0130:true",
        "deviceTrustRelease:$version",
    ],
    "Результаты сквозных проверок протокола для выпуска",
)
targets = json.loads(read("device-trust/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit(
        f"Несовпадение версии целевых платформ доверия к устройствам: {targets.get('productVersion')} != {version}"
    )
for t in targets["targets"]:
    if "deviceTrustRelease0130" not in t.get("requiredChecks", []):
        raise SystemExit(f"Для цели {t.get('id')} отсутствует deviceTrustRelease0130")
build = read("scripts/release/build-release.sh")
req(
    build,
    [
        "LAUNCHER_DEVICE_TRUST_MATRIX_FILE",
        "--device-trust-matrix",
        "Publish-check Minecraft Compatibility + Device Trust Release",
    ],
    "release pipeline",
)
subprocess.run(["go", "test", "./cmd/launcher"], cwd=ROOT / "cli", check=True)
subprocess.run(
    ["go", "test", "-tags", "launcher_nopgx", "./internal/httpapi"],
    cwd=ROOT / "services/api",
    check=True,
)
subprocess.run(
    [
        sys.executable,
        str(ROOT / "scripts/device_trust/matrix.py"),
        "validate",
        "--targets",
        str(ROOT / "device-trust/targets.json"),
    ],
    check=True,
)
subprocess.run(
    [sys.executable, str(ROOT / "scripts/device_trust/test_matrix.py")], check=True
)
print(f"[Launcher] Проверка выпуска подсистемы доверия к устройствам пройдена: OK ({version})")
