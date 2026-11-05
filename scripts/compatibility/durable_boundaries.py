#!/usr/bin/env python3
"""Шлюз выпуска Launcher 0.21.3: устойчивые границы и сертификация.

Проверяется подключение конкретной реализации 0.21.3 к промышленному пути публикации: устойчивые
задачи, идемпотентность, распределённые блокировки, транзакционный outbox, одноразовые nonce
Runtime, повторная проверка прав в реальном времени и восстановление после перезапуска. Реализация
только из таблиц намеренно отклоняется.
"""

from __future__ import annotations

import argparse
import zipfile
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise SystemExit("durable-boundaries 0.21.3: " + message)


def text(path: str) -> str:
    if path.startswith("cli/internal/dbmigrate/sql/"):
        with zipfile.ZipFile(ROOT / "cli/internal/dbmigrate/catalog.zip") as archive:
            return archive.read("sql/" + path.rsplit("/", 1)[-1]).decode("utf-8")
    p = ROOT / path
    if not p.is_file():
        fail(f"Отсутствует обязательный исходный файл: {path}")
    return p.read_text(encoding="utf-8")


def validate() -> None:
    try:
        version = tuple(int(x) for x in text("VERSION").strip().split(".")[:3])
    except ValueError:
        fail("VERSION не соответствует семантическому версионированию")
    if version < (0, 21, 3):
        fail("VERSION должна быть не ниже 0.21.3")

    api_m = text("services/api/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    cli_m = text("cli/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    if api_m != cli_m:
        fail("Миграции 0052 для API и CLI различаются")
    for table in (
        "durable_jobs",
        "durable_job_attempts",
        "durable_scope_leases",
        "event_outbox",
        "used_nonces",
        "idempotency_records",
    ):
        if f"CREATE TABLE IF NOT EXISTS {table}" not in api_m:
            fail(f"В миграции 0052 отсутствует {table}")

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
            fail(f"Отсутствует инвариант производственного постоянного хранилища: {needle}")

    runtime_repo = text("services/api/internal/repository/validation_0212.go")
    if (
        "runtime-validation-run" not in runtime_repo
        or "used_nonces" not in runtime_repo
    ):
        fail("runId свидетельства Runtime не расходуется через постоянное хранилище nonce")

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
            fail(f"Отсутствует инвариант постоянного обработчика публикации: {needle}")
    if worker.count("authorizationService().Authorize") < 2:
        fail("Задание публикации должно повторно проверять действующие полномочия непосредственно перед фиксацией")

    lock = text("services/api/internal/httpapi/package_mutation_lock.go")
    for needle in (
        "AcquireDurableScopeLease",
        "RenewDurableScopeLease",
        "lockPackageLookupMutation",
    ):
        if needle not in lock:
            fail(f"Отсутствует граница изменения пакета: {needle}")

    main = text("services/api/cmd/launcher-api/main.go")
    if "StartDurableControlPlane0213" not in main:
        fail("При запуске API не запускается постоянный обработчик перезапуска и исходящих событий")

    # Ни один производственный HTTP-маршрут не должен сохранять прежний прямой API публикации до 0.21.3.
    http_root = ROOT / "services/api/internal/httpapi"
    forbidden = re.compile(r"\.(?:PublishVersionWithManifest|PublishVersion)\(")
    for path in http_root.glob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        if forbidden.search(path.read_text(encoding="utf-8")):
            fail(f"В {path.relative_to(ROOT)} остался обход проверки прямой публикации")

    package_product = text("services/api/internal/httpapi/package_product.go")
    admin = text("services/api/internal/httpapi/admin_handlers.go")
    if package_product.count("publishDurably0213") < 2:
        fail("Публикация пакета и откат не оба выполняются через постоянный механизм публикации")
    if admin.count("publishDurably0213") < 2:
        fail("Маршруты публикации Admin обходят постоянный механизм публикации")

    tests = text("services/api/internal/repository/durable_0213_test.go") + text(
        "services/api/internal/repository/durable_0213_integration_test.go"
    )
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
            fail(f"Отсутствует сертификационный тест: {needle}")

    print("Durable Boundaries & Certification 0.21.3 gate OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.parse_args()
    validate()


if __name__ == "__main__":
    main()
