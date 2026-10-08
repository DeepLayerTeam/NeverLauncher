#!/usr/bin/env python3
"""NeverLauncher 0.21.2 Честная проверка и Границы доверия контроль выпуска.

Этот является исполняемый исходник-политика контроль для рабочий 0.21.2 поведение. Это
сохраняет зафиксированный G01-G35/M01-M19 вышестоящий проект реестр из 0.21.1 пока
проверка тот текущий публикация, среда выполнения-свидетельство, устройство-доверие и расширение
хост пути не может overstate их свидетельство уровень.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COVERAGE_0211 = ROOT / "compatibility/gravit/authorization-coverage-0211.json"


def fail(message: str) -> None:
    raise SystemExit("honest-validation/trust 0.21.2: " + message)


def text(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        fail(f"обязательный исходник отсутствующий: {path}")
    return p.read_text(encoding="utf-8")


def validate_frozen_coverage_registry() -> dict:
    doc = json.loads(COVERAGE_0211.read_text(encoding="utf-8"))
    if doc.get("productVersion") != "0.21.1":
        fail("исторический зафиксированное покрытие реестр версия изменён")
    expected = [f"G{i:02d}" for i in range(1, 36)] + [f"M{i:02d}" for i in range(1, 20)]
    rows = doc.get("requirements") or []
    if [r.get("id") for r in rows] != expected:
        fail("зафиксированный G01-G35/M01-M19 реестр изменён shape/order")
    for row in rows:
        if not row.get("owner") or not row.get("upstreamRefs"):
            fail(f"{row.get('id')} потерянный owner/upstream исходник свидетельство")
        if row.get("status") in {"implemented", "partial"} and (not row.get("implementationRefs") or not row.get("testRefs")):
            fail(f"{row.get('id')} потерянный implementation/test свидетельство")
    return doc


def validate_validation_pipeline() -> None:
    routes = text("services/api/internal/httpapi/routes_packages.go")
    validation = text("services/api/internal/httpapi/package_validation_0212.go")
    product = text("services/api/internal/httpapi/package_product.go")
    admin = text("services/api/internal/httpapi/admin_handlers.go")
    install = text("services/api/internal/httpapi/install_handlers.go")
    model = text("services/api/internal/model/validation_0212.go")
    repo = text("services/api/internal/repository/validation_0212.go")
    config = text("services/api/internal/config/config.go")
    cli = text("cli/cmd/neverlauncher/package_commands.go")

    for needle in [
        'POST /api/v1/packages/{packageId}/integrity-check',
        'POST /api/v1/packages/{packageId}/runtime-validations/evidence',
        'GET /api/v1/packages/{packageId}/validations',
        'PUT /api/v1/projects/{projectId}/validation-policy',
    ]:
        if needle not in routes:
            fail(f"канонический валидация маршрут отсутствующий: {needle}")

    for needle in [
        'func (s Server) packageSmoke',
        's.packageIntegrityCheck0212(w, r)',
        '"runtimeExecuted": false',
        '"runtimeStatus": "not-checked"',
        'ed25519.Verify(pub, canonical, sig)',
        'integrity.ManifestDigest != manifestDigest',
        'integrity.ArtifactDigest != artifactDigest',
        'v.SignerKeyFingerprint != hex.EncodeToString(fingerprint[:])',
        'v.Result == "passed" && v.ManifestDigest == manifestDigest && v.ActualClient && v.ExitCode == 0',
    ]:
        if needle not in validation:
            fail(f"валидация свидетельство инвариант отсутствующий: {needle}")

    # Среда выполнения PASS является производный из подписанное свидетельство, реальный клиент и успешный процесс выход.
    if 'resultState := "failed"' not in validation or 'if e.ActualClient && e.ExitCode == 0 {' not in validation or 'resultState = "passed"' not in validation:
        fail("среда выполнения результат является не производный из успешный реальный клиент свидетельство")
    if re.search(r'packageSmoke[\s\S]{0,1800}runtime[^\n]*passed', validation, flags=re.IGNORECASE):
        fail("устаревший smoke маршрут appears able к захватывать среда выполнения пройден")

    if 'validatePublishEvidence0212(r, lookup)' not in product:
        fail("канонический пакет публикация обход валидация политика")
    if admin.count('prepareAdminPublish0212(r,') < 2:
        fail("Администратор публикация маршруты делать не share канонический валидация принудительное применение")
    if 'PublishVersionWithManifest' in install or 'publishSigned(' in install:
        fail("установщик по-прежнему публикует unvalidated первый релиз")
    if 'func (s Server) publishSigned(' in text("services/api/internal/httpapi/version_manifest.go"):
        fail("устаревший прямой publishSigned обход по-прежнему существует")

    for needle in ['IntegrityCheckResult', 'RuntimeValidationResult', 'TrustAssessment', 'ProjectValidationPolicy']:
        if needle not in model:
            fail(f"канонический модель отсутствующий {needle}")
    for needle in ['SaveIntegrityCheck', 'SaveRuntimeValidation', 'GetProjectValidationPolicy', 'package_runtime_validations']:
        if needle not in repo:
            fail(f"долговременный валидация репозиторий отсутствующий {needle}")
    if 'NEVERLAUNCHER_RUNTIME_VALIDATION_KEYS_JSON' not in config:
        fail("среда выполнения подписант доверие-задать конфигурация отсутствующий")
    for needle in ['runtime-sign', 'runtime-submit', 'integrity-check', 'policy-set', 'legacy smoke-test performs integrity validation only']:
        if needle not in cli:
            fail(f"CLI honest-валидация процесс отсутствующий {needle}")


def validate_trust_boundaries() -> None:
    devices = text("services/api/internal/httpapi/device_trust_0121.go")
    device_repo = text("services/api/internal/repository/devices_0121.go")
    attestation = text("services/api/internal/httpapi/device_attestation_0124.go")
    host = text("services/api/internal/extensionhost/host_0205.go")
    host_api = text("services/api/internal/httpapi/extension_host_0205.go")
    admin = text("apps/admin/src/main.tsx")

    for needle in [
        'RemoteHardwareProvenance: "not-verified"',
        'LocalHardwareBinding = "verified-local"',
        'remote-hardware-provenance-not-verified',
    ]:
        if needle not in devices:
            fail(f"доверие к устройству assessment граница отсутствующий: {needle}")
    if 'remote_hardware_provenance' not in device_repo:
        fail("удалённо подтверждённое происхождение оборудования является не сохранённый")
    if 'hardwareProvenance' not in attestation or 'RemoteHardwareProvenance' not in attestation:
        fail("аттестация ответ делает не предоставлять канонический происхождение")

    for source, name in [(host, "extension host"), (host_api, "extension host API")]:
        for needle in ['trusted-process', 'none']:
            if needle not in source:
                fail(f"{name} делает не состояние явный trusted-process/no-sandbox граница")
    if 'OS sandbox' not in admin or 'trusted-process' not in admin:
        fail("Панель администратора hides расширение выполнение доверие граница")


def validate_migration_and_contract() -> None:
    api_m = text("services/api/internal/dbmigrate/sql/0051_honest_validation_trust_0212.sql")
    cli_m = text("cli/internal/dbmigrate/sql/0051_honest_validation_trust_0212.sql")
    if api_m != cli_m:
        fail("API и CLI 0051 миграция differ")
    for needle in [
        'package_integrity_checks', 'package_runtime_validations', 'project_validation_policies', 'signer_key_fingerprint',
        "status IN ('smoke-passed','smoke-failed')", 'remote_hardware_provenance', "DEFAULT 'not-verified'",
    ]:
        if needle not in api_m:
            fail(f"0051 миграция отсутствующий {needle}")
    spec = json.loads(text("schemas/openapi.yaml"))
    for path in [
        '/api/v1/packages/{packageId}/integrity-check',
        '/api/v1/packages/{packageId}/runtime-validations/evidence',
        '/api/v1/packages/{packageId}/validations',
        '/api/v1/projects/{projectId}/validation-policy',
    ]:
        if path not in spec.get('paths', {}):
            fail(f"OpenAPI отсутствующий {path}")
    smoke = spec['paths']['/api/v1/packages/{packageId}/smoke-test']['post']
    if 'never launches Minecraft' not in smoke.get('description', ''):
        fail("OpenAPI smoke совместимость маршрут overstates среда выполнения семантика")


def validate(online: bool) -> None:
    version = text("VERSION").strip()
    try:
        parts = tuple(int(x) for x in version.split(".")[:3])
    except ValueError:
        fail("VERSION является не semantic версия")
    if parts < (0, 21, 2):
        fail("VERSION должен быть 0.21.2 или новый")
    doc = validate_frozen_coverage_registry()
    validate_validation_pipeline()
    validate_trust_boundaries()
    validate_migration_and_contract()
    if online:
        module_path = ROOT / "scripts/compatibility/authorization_frozen_coverage_0211.py"
        spec = importlib.util.spec_from_file_location("authorization_frozen_coverage_0211", module_path)
        if spec is None or spec.loader is None:
            fail("не может загрузка 0.21.1 вышестоящий проект проверка контроль")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_upstream(doc)
    print("Честная проверка и Границы доверия 0.21.2 контроль OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    validate(args.online)


if __name__ == "__main__":
    main()
