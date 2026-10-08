#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
if core < (0, 17, 10):
    raise SystemExit(f"Загрузчик Усиление защиты требует VERSION>=0.17.10, получил {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствующий {missing}")

cache = read("cli/cmd/neverlauncher/loader_hardening.go")
require(cache, [
    "loaderPayloadCacheRecord", "loader-cache", "sha256", "storeLoaderPayloadCacheBytes",
    "loadLoaderPayloadCacheBytes", "fetchLoaderProfileWithCache", "restorePinnedInstallerFromCache",
    "downloadPinnedSHA256Artifact", "quarantine",
], "content-addressed loader cache")

processors = read("cli/cmd/neverlauncher/forge_processor_recovery.go")
require(processors, [
    "processor-journal.json", 'state == "running"', 'markProcessorJournal',
    "InstallerSHA256", "quarantineProcessorOutputs", "Recovered", "Attempts",
], "durable processor recovery journal")

loader_runtime = read("cli/cmd/neverlauncher/loader_runtime.go")
require(loader_runtime, ["--loader-cache-only", "PayloadCacheHit", "UpstreamRecoveryUsed", "fetchLoaderProfileWithCache"], "Fabric/Quilt cache recovery")
forge_runtime = read("cli/cmd/neverlauncher/forge_runtime.go")
require(forge_runtime, ["--loader-cache-only", "InstallerCacheHit", "ProcessorRecovered", "ProcessorJournalSHA256", "restorePinnedInstallerFromCache", "downloadPinnedSHA256Artifact"], "Forge/NeoForge installer recovery")

e2e = read("e2e/scripts/run-loader-hardening-probe.sh")
require(e2e, ["--loader-cache-only", "loader-hardening.json", "upstreamIndependentRecovery", "processorRecoveryVerified", "contentAddressedCache"], "loader hardening recovery probe")
compat = read("e2e/scripts/run-compatibility-case.sh")
require(compat, ["loader_hardening_target", "loaderCacheVerified", "loaderUpstreamRecovery", "loaderInstallerRecovery", "loaderProcessorRecovery", "loader-hardening.json"], "compatibility hardening evidence")
matrix = read("scripts/compatibility/matrix.py")
require(matrix, ["LOADER_HARDENING_01710", "loader_hardening_01710_required", "loaderCacheVerified", "loaderUpstreamRecovery", "loader-hardening.json"], "matrix hardening enforcement")
release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, ["LoaderHardeningTargets", "compatibilityLoaderHardening01710Required", "compatibilityLoaderHardeningTarget", "loaderCacheVerified", "loaderProcessorRecovery", "loader-hardening-0.17.10-content-addressed-cache-pinned-upstream-installer-processor-crash-recovery"], "release hardening certification")

tests = read("cli/cmd/neverlauncher/loader_runtime_test.go") + read("cli/cmd/neverlauncher/loader_hardening_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("scripts/compatibility/test_matrix.py")
require(tests, [
    "LoaderCacheOnly", "PayloadCacheHit", "UpstreamRecoveryUsed", "ProcessorRecovered", "TestLoaderPayloadCacheRejectsAndQuarantinesCorruptPayload",
    "TestCompatibilityCertificationLoaderHardening01710", "TestCompatibilityCertificationLoaderHardening01710RejectsTamperedCoverage",
    "test_01710_aggregate_rejects_missing_loader_cache_recovery", "test_01710_aggregate_rejects_missing_processor_recovery",
], "0.17.10 recovery regression tests")

workflow = read(".github/workflows/compatibility.yml")
require(workflow, ["e2e/runtime/loader-hardening.json", "e2e/runtime/loader-hardening-package.json"], "compatibility hardening artifacts")

print("Загрузчик Усиление защиты 0.17.10 контроль: OK (адресуемый по содержимому загрузчик кэш, закреплённый вышестоящий проект independence, установщик восстановление, долговременный обработчик восстановление после сбоя)")
