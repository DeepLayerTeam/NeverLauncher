#!/usr/bin/env python3
"""Шлюз выпуска Launcher 0.21.2: честная валидация и границы доверия.

Это исполняемый контроль политики исходников для производственного поведения 0.21.2. Он сохраняет
замороженный upstream-реестр G01-G35/M01-M19 из 0.21.1 и проверяет, что текущие пути публикации,
свидетельств Runtime, доверия устройств и Host расширений не преувеличивают уровень доказательств.
"""

from __future__ import annotations

import argparse
import zipfile
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COVERAGE_0211 = ROOT / "compatibility/gravit/authorization-coverage.json"


def fail(message: str) -> None:
    raise SystemExit("honest-validation/trust 0.21.2: " + message)


def text(path: str) -> str:
    if path.startswith("cli/internal/dbmigrate/sql/"):
        with zipfile.ZipFile(ROOT / "cli/internal/dbmigrate/catalog.zip") as archive:
            return archive.read("sql/" + path.rsplit("/", 1)[-1]).decode("utf-8")
    p = ROOT / path
    if not p.is_file():
        fail(f"Отсутствует обязательный исходный файл: {path}")
    return p.read_text(encoding="utf-8")


def validate_frozen_coverage_registry() -> dict:
    doc = json.loads(COVERAGE_0211.read_text(encoding="utf-8"))
    if doc.get("productVersion") != "0.21.1":
        fail("Изменена версия исторического реестра зафиксированного покрытия")
    expected = [f"G{i:02d}" for i in range(1, 36)] + [f"M{i:02d}" for i in range(1, 20)]
    rows = doc.get("requirements") or []
    if [r.get("id") for r in rows] != expected:
        fail("Изменена структура или последовательность зафиксированного реестра G01-G35/M01-M19")
    for row in rows:
        if not row.get("owner") or not row.get("upstreamRefs"):
            fail(f"{row.get('id')} отсутствуют данные о владельце и исходном источнике")
        if row.get("status") in {"implemented", "partial"} and (
            not row.get("implementationRefs") or not row.get("testRefs")
        ):
            fail(f"{row.get('id')} отсутствуют свидетельства реализации и тестов")
    return doc


def validate_validation_pipeline() -> None:
    routes = text("services/api/internal/httpapi/routes_packages.go")
    validation = text("services/api/internal/httpapi/package_validation.go")
    product = text("services/api/internal/httpapi/package_product.go")
    admin = text("services/api/internal/httpapi/admin_handlers.go")
    install = text("services/api/internal/httpapi/install_handlers.go")
    model = text("services/api/internal/model/validation.go")
    repo = text("services/api/internal/repository/validation.go")
    config = text("services/api/internal/config/config.go")
    cli = text("cli/cmd/launcher/package_commands.go")

    for needle in [
        "POST /api/v1/packages/{packageId}/integrity-check",
        "POST /api/v1/packages/{packageId}/runtime-validations/evidence",
        "GET /api/v1/packages/{packageId}/validations",
        "PUT /api/v1/projects/{projectId}/validation-policy",
    ]:
        if needle not in routes:
            fail(f"Отсутствует канонический маршрут проверки: {needle}")

    for needle in [
        "func (s Server) packageSmoke",
        "s.packageIntegrityCheck0212(w, r)",
        '"runtimeExecuted": false',
        '"runtimeStatus": "not-checked"',
        "ed25519.Verify(pub, canonical, sig)",
        "integrity.ManifestDigest != manifestDigest",
        "integrity.ArtifactDigest != artifactDigest",
        "v.SignerKeyFingerprint != hex.EncodeToString(fingerprint[:])",
        'v.Result == "passed" && v.ManifestDigest == manifestDigest && v.ActualClient && v.ExitCode == 0',
    ]:
        if needle not in validation:
            fail(f"Отсутствует инвариант свидетельства проверки: {needle}")

    # Статус PASS среды запуска выводится из подписанных свидетельств, настоящего клиента и успешного завершения процесса.
    if (
        'resultState := "failed"' not in validation
        or "if e.ActualClient && e.ExitCode == 0 {" not in validation
        or 'resultState = "passed"' not in validation
    ):
        fail("Результат Runtime не основан на успешном свидетельстве работы реального клиента")
    if re.search(
        r"packageSmoke[\s\S]{0,1800}runtime[^\n]*passed",
        validation,
        flags=re.IGNORECASE,
    ):
        fail("Устаревшая экспресс-проверка может ошибочно пометить Runtime как проверенный")

    if "validatePublishEvidence0212(r, lookup)" not in product:
        fail("Каноническая публикация пакета обходит политику проверки")
    if admin.count("prepareAdminPublish0212(r,") < 2:
        fail("Маршруты публикации Admin не применяют общую каноническую проверку")
    if "PublishVersionWithManifest" in install or "publishSigned(" in install:
        fail("Установщик по-прежнему публикует первый релиз без проверки")
    if "func (s Server) publishSigned(" in text(
        "services/api/internal/httpapi/version_manifest.go"
    ):
        fail("Устаревший обход прямого вызова publishSigned по-прежнему существует")

    for needle in [
        "IntegrityCheckResult",
        "RuntimeValidationResult",
        "TrustAssessment",
        "ProjectValidationPolicy",
    ]:
        if needle not in model:
            fail(f"В канонической модели отсутствует {needle}")
    for needle in [
        "SaveIntegrityCheck",
        "SaveRuntimeValidation",
        "GetProjectValidationPolicy",
        "package_runtime_validations",
    ]:
        if needle not in repo:
            fail(f"В постоянном хранилище проверок отсутствует {needle}")
    if "LAUNCHER_RUNTIME_VALIDATION_KEYS_JSON" not in config:
        fail("Отсутствует конфигурация доверенных подписантов Runtime")
    for needle in [
        "runtime-sign",
        "runtime-submit",
        "integrity-check",
        "policy-set",
        "Проверка старого формата подтверждает только целостность",
    ]:
        if needle not in cli:
            fail(f"В сценарии достоверной проверки CLI отсутствует {needle}")


def validate_trust_boundaries() -> None:
    devices = text("services/api/internal/httpapi/device_trust.go")
    device_repo = text("services/api/internal/repository/devices.go")
    attestation = text("services/api/internal/httpapi/device_attestation.go")
    host = text("services/api/internal/extensionhost/host.go")
    host_api = text("services/api/internal/httpapi/extension_host.go")
    admin = text("apps/admin/src/main.tsx")

    for needle in [
        'RemoteHardwareProvenance: "not-verified"',
        'LocalHardwareBinding = "verified-local"',
        "remote-hardware-provenance-not-verified",
    ]:
        if needle not in devices:
            fail(f"Отсутствует граница оценки доверия устройству: {needle}")
    if "remote_hardware_provenance" not in device_repo:
        fail("Происхождение удалённого аппаратного обеспечения не сохраняется")
    if (
        "hardwareProvenance" not in attestation
        or "RemoteHardwareProvenance" not in attestation
    ):
        fail("Ответ аттестации не содержит канонические сведения о происхождении")

    for source, name in [(host, "extension host"), (host_api, "extension host API")]:
        for needle in ["trusted-process", "none"]:
            if needle not in source:
                fail(
                    f"{name} не указывает явно границу доверенного процесса без песочницы"
                )
    if "OS sandbox" not in admin or "trusted-process" not in admin:
        fail("Интерфейс Admin скрывает границу доверия при выполнении расширений")


def validate_migration_and_contract() -> None:
    api_m = text(
        "services/api/internal/dbmigrate/sql/0051_honest_validation_trust.sql"
    )
    cli_m = text("cli/internal/dbmigrate/sql/0051_honest_validation_trust.sql")
    if api_m != cli_m:
        fail("Миграции 0051 для API и CLI различаются")
    for needle in [
        "package_integrity_checks",
        "package_runtime_validations",
        "project_validation_policies",
        "signer_key_fingerprint",
        "status IN ('smoke-passed','smoke-failed')",
        "remote_hardware_provenance",
        "DEFAULT 'not-verified'",
    ]:
        if needle not in api_m:
            fail(f"В миграции 0051 отсутствует {needle}")
    spec = json.loads(text("schemas/openapi.yaml"))
    for path in [
        "/api/v1/packages/{packageId}/integrity-check",
        "/api/v1/packages/{packageId}/runtime-validations/evidence",
        "/api/v1/packages/{packageId}/validations",
        "/api/v1/projects/{projectId}/validation-policy",
    ]:
        if path not in spec.get("paths", {}):
            fail(f"В OpenAPI отсутствует {path}")
    smoke = spec["paths"]["/api/v1/packages/{packageId}/smoke-test"]["post"]
    if "never launches Minecraft" not in smoke.get("description", ""):
        fail("Маршрут экспресс-проверки совместимости OpenAPI преувеличивает подтверждённые свойства Runtime")


def validate(online: bool) -> None:
    version = text("VERSION").strip()
    try:
        parts = tuple(int(x) for x in version.split(".")[:3])
    except ValueError:
        fail("VERSION не соответствует семантическому версионированию")
    if parts < (0, 21, 2):
        fail("VERSION должна быть не ниже 0.21.2")
    doc = validate_frozen_coverage_registry()
    validate_validation_pipeline()
    validate_trust_boundaries()
    validate_migration_and_contract()
    if online:
        module_path = (
            ROOT / "scripts/compatibility/authorization_frozen_coverage.py"
        )
        spec = importlib.util.spec_from_file_location(
            "authorization_frozen_coverage_0211", module_path
        )
        if spec is None or spec.loader is None:
            fail("Не удалось загрузить проверку внешнего источника версии 0.21.1")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_upstream(doc)
    print("Проверка достоверности валидации и границ доверия 0.21.2 пройдена: OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    validate(args.online)


if __name__ == "__main__":
    main()
