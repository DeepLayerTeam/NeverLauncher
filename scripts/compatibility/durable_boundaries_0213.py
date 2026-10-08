#!/usr/bin/env python3
"""NeverLauncher 0.21.3 Durable Boundaries & Certification release gate.

This gate verifies the concrete 0.21.3 implementation is wired into the
production publish path: durable jobs, idempotency, distributed fencing,
transactional outbox, single-use runtime nonces, live authorization rechecks
and restart recovery. It intentionally rejects a tables-only implementation.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise SystemExit("durable-boundaries 0.21.3: " + message)


def text(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        fail(f"required source missing: {path}")
    return p.read_text(encoding="utf-8")


def validate() -> None:
    try:
        version = tuple(int(x) for x in text("VERSION").strip().split('.')[:3])
    except ValueError:
        fail("VERSION is not semantic version")
    if version < (0, 21, 3):
        fail("VERSION must be 0.21.3 or newer")

    api_m = text("services/api/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    cli_m = text("cli/internal/dbmigrate/sql/0052_durable_boundaries_0213.sql")
    if api_m != cli_m:
        fail("API and CLI 0052 migrations differ")
    for table in ("durable_jobs", "durable_job_attempts", "durable_scope_leases", "event_outbox", "used_nonces", "idempotency_records"):
        if f"CREATE TABLE IF NOT EXISTS {table}" not in api_m:
            fail(f"0052 migration missing {table}")

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
            fail(f"production durable repository invariant missing: {needle}")

    runtime_repo = text("services/api/internal/repository/validation_0212.go")
    if "runtime-validation-run" not in runtime_repo or "used_nonces" not in runtime_repo:
        fail("runtime evidence runId is not consumed through durable nonce storage")

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
            fail(f"durable publish worker invariant missing: {needle}")
    if worker.count("authorizationService().Authorize") < 2:
        fail("publish job must re-check live authorization immediately before commit")

    lock = text("services/api/internal/httpapi/package_mutation_lock.go")
    for needle in ("AcquireDurableScopeLease", "RenewDurableScopeLease", "lockPackageLookupMutation"):
        if needle not in lock:
            fail(f"package mutation boundary missing: {needle}")

    main = text("services/api/cmd/neverlauncher-api/main.go")
    if "StartDurableControlPlane0213" not in main:
        fail("API startup does not start durable restart/outbox worker")

    # No production HTTP route may retain the pre-0.21.3 direct publication API.
    http_root = ROOT / "services/api/internal/httpapi"
    forbidden = re.compile(r"\.(?:PublishVersionWithManifest|PublishVersion)\(")
    for path in http_root.glob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        if forbidden.search(path.read_text(encoding="utf-8")):
            fail(f"direct publication bypass remains in {path.relative_to(ROOT)}")

    package_product = text("services/api/internal/httpapi/package_product.go")
    admin = text("services/api/internal/httpapi/admin_handlers.go")
    if package_product.count("publishDurably0213") < 2:
        fail("package publish/rollback are not both routed through durable publication")
    if admin.count("publishDurably0213") < 2:
        fail("admin publication routes bypass durable publication")

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
            fail(f"certification test missing: {needle}")

    print("Durable Boundaries & Certification 0.21.3 gate OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.parse_args()
    validate()


if __name__ == "__main__":
    main()
