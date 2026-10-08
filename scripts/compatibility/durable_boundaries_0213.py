#!/usr/bin/env python3
"""NeverLauncher 0.21.3 Надёжные долговременные границы и Сертификация контроль выпуска.

Этот контроль проверяет конкретный 0.21.3 реализация является wired в 
рабочий публикация путь: долговременные задачи, идемпотентность, распределённый ограждение,
транзакционная исходящая очередь, одноразовый среда выполнения одноразовые значения, актуальная авторизация повторная проверка
и восстановление после перезапуска. Это намеренно отклоняет таблица-только реализация.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise SystemExit("долговременный-границы 0.21.3: " + message)


def text(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        fail(f"обязательный исходник отсутствующий: {path}")
    return p.read_text(encoding="utf-8")


def validate() -> None:
    version = text("VERSION").strip()
    try:
        parts = tuple(int(part) for part in version.split(".")[:3])
    except ValueError:
        fail("VERSION должна быть корректной SemVer-версией")
    if parts < (0, 21, 3):
        fail("для проверки 0.21.3 требуется VERSION не ниже 0.21.3")

    api_m = text("services/api/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    cli_m = text("cli/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    if api_m != cli_m:
        fail("API и CLI 0052 миграция differ")
    for table in ("durable_jobs", "durable_job_attempts", "durable_scope_leases", "event_outbox", "used_nonces", "idempotency_records"):
        if f"CREATE TABLE IF NOT EXISTS {table}" not in api_m:
            fail(f"0052 миграция отсутствующий {table}")

    repo = text("services/api/internal/repository/durable_0213.go")
    for needle in (
        "FOR UPDATE SKIP LOCKED",
        "func (r *SQLRepository) CommitDurablePublish",
        "fencing_token",
        "idempotency_records",
        "durableJobIdempotencyScope0213",
        "RenewDurableScopeLease",
        "event_outbox",
        "used_nonces",
        "package_integrity_checks",
        "status=$4 AND manifest=$3::jsonb",
    ):
        if needle not in repo:
            fail(f"рабочий долговременный репозиторий инвариант отсутствующий: {needle}")

    runtime_repo = text("services/api/internal/repository/validation_0212.go")
    if "runtime-validation-run" not in runtime_repo or "used_nonces" not in runtime_repo:
        fail("свидетельство реального запуска runId является не использованный через долговременный одноразовое значение хранилище")

    worker = text("services/api/internal/httpapi/durable_control_0213.go")
    for needle in (
        "StartDurableControlPlane0213",
        "LeaseDurableJobs",
        "AcquireDurableScopeLease",
        "CommitDurablePublish",
        "authorization-revoked-before-commit",
        "validatePublishEvidenceContext0213",
        "drainOutbox0213",
    ):
        if needle not in worker:
            fail(f"долговременный публикация обработчик инвариант отсутствующий: {needle}")
    if worker.count("authorizationService().Authorize") < 2:
        fail("публикация задача должен повторно проверять актуальная авторизация немедленно до фиксация")

    lock = text("services/api/internal/httpapi/package_mutation_lock.go")
    for needle in ("AcquireDurableScopeLease", "RenewDurableScopeLease", "lockPackageLookupMutation"):
        if needle not in lock:
            fail(f"изменение пакета граница отсутствующий: {needle}")

    main = text("services/api/cmd/neverlauncher-api/main.go")
    if "StartDurableControlPlane0213" not in main:
        fail("API запуск делает не запуск долговременный restart/outbox обработчик")

    # Нет рабочий HTTP маршрут может сохранять pre-0.21.3 прямой публикация API.
    http_root = ROOT / "services/api/internal/httpapi"
    forbidden = re.compile(r"\.(?:PublishVersionWithManifest|PublishVersion)\(")
    for path in http_root.glob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        if forbidden.search(path.read_text(encoding="utf-8")):
            fail(f"прямой публикация обход остаётся в {path.relative_to(ROOT)}")

    package_product = text("services/api/internal/httpapi/package_product.go")
    admin = text("services/api/internal/httpapi/admin_handlers.go")
    if package_product.count("publishDurably0213") < 2:
        fail("пакет publish/rollback являются не оба маршрут через долговременный публикация")
    if admin.count("publishDurably0213") < 2:
        fail("администратор публикация маршруты обход долговременный публикация")

    tests = text("services/api/internal/repository/durable_0213_test.go") + text("services/api/internal/repository/durable_0213_integration_test.go")
    for needle in (
        "TestDurableScopeLeaseFencing0213",
        "TestDurableJobIdempotencyRejectsDifferentPayload0213",
        "TestDurableJobIdempotencyIsActorScoped0213",
        "TestDurablePublishCommitAndOutbox0213",
        "TestDurablePublishCASRejectsStatusChange0213",
        "TestRuntimeValidationRunIDIsDurableNonce0213",
        "TestDurableJobLeaseRecoversAcrossReplicaRestart0213",
        "TestDurableScopeLeaseHasSingleDistributedOwner0213",
    ):
        if needle not in tests:
            fail(f"сертификация тест отсутствующий: {needle}")

    print("Надёжные долговременные границы и Сертификация 0.21.3 контроль OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.parse_args()
    validate()


if __name__ == "__main__":
    main()
