#!/usr/bin/env python3
"""Independent host-side V04/V06 attestor. Execute inside the worker.

An operator-controlled, non-root host invokes ONLY the pre-approved OCI image
by digest. The Ed25519 private key stays in this host process, in OCI,
CI, Docker environment, network or mounted volumes. Only verified on-disk
observations from this execution are signed, not uploaded JSON from callers.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import urllib.request
import urllib.parse
from official_chain_0347 import (
    issue_minecraft_credentials,
    ExternalOutage,
    AccountRejected,
)
from component_matrix_0348 import selected_components
from diagnostics_03412 import (
    retain as retain_redacted_diagnostics,
    redact as redact_diagnostics,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
)

SCHEMA = "launcher.validation-evidence.v4"
EVIDENCE_FIELDS = (
    "schemaVersion",
    "runNonce",
    "audience",
    "purpose",
    "targetId",
    "targetMatrixSha256",
    "signerKeyId",
    "packageVersion",
    "runId",
    "packageId",
    "manifestSha256",
    "artifactSha256",
    "resolvedPlanSha256",
    "sourceSha",
    "buildSha",
    "runnerImageSha256",
    "javaSha256",
    "javaVersion",
    "os",
    "arch",
    "loader",
    "installAdapterSha256",
    "guardMode",
    "guardPolicySha256",
    "serverBridgeSha256",
    "serverPluginVersion",
    "preset",
    "authenticationMode",
    "stages",
    "artifactHashes",
    "startedAt",
    "finishedAt",
    "issuedAt",
    "expiresAt",
)
DOMAIN = b"Launcher/validation-evidence/v4\x00"
REQUIRED = (
    "manifest-files",
    "materialization",
    "startup",
    "loader-readiness",
    "authentication",
    "server-readiness",
    "matching-server",
    "gameplay-smoke",
    "update-recovery",
)
FILES = (
    "staged-execution.json",
    "verified.json",
    "startup-readiness.json",
    "server-readiness.json",
    "gameplay-smoke.json",
    "authentication.json",
    "runtime-launch.json",
    "runtime-gameplay-launch.json",
    "execution-identity.json",
    "native-adoption.json",
    "update-recovery.json",
)
STAGE_ARTIFACT = {
    "materialization": "verified.json",
    "startup": "startup-readiness.json",
    "loader-readiness": "startup-readiness.json",
    "authentication": "authentication.json",
    "server-readiness": "server-readiness.json",
    "matching-server": "gameplay-smoke.json",
    "gameplay-smoke": "gameplay-smoke.json",
    "update-recovery": "update-recovery.json",
}
def needs_adversarial_gameplay(version):
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9.-]+)?", version)
    check(match is not None, "Некорректная версия для приёмки нативной игры")
    return tuple(map(int, match.groups())) >= (0, 43, 14)


def verify_adversarial_gameplay_04314(work, signed_manifest, snapshot, game):
    """Независимый узел: привяжите отрицательные проверки к подготовленным файлам и свидетельствам игрового запуска."""
    proof = read_json(work / "adversarial-gameplay-04314.json")
    assertion = game.get("adversarialGameplay04314")
    check(isinstance(assertion, dict) and assertion.get("status") == "passed"
          and assertion.get("evidenceSha256") == sha(work / "adversarial-gameplay-04314.json")
          and assertion.get("manifestTamperDenied") is True
          and assertion.get("installedFileTamperDeniedAndRestored") is True,
          "Для успешного игрового запуска 0.43.14 отсутствует связанное отрицательное наблюдение")
    manifest = proof.get("manifestTamper")
    installed = proof.get("installedFileTamper")
    check(proof.get("schemaVersion") == "launcher.adversarial-gameplay.04314.v1"
          and isinstance(manifest, dict) and isinstance(installed, dict)
          and manifest.get("status") == "denied"
          and manifest.get("baselineVerified") is True
          and HEX64.fullmatch(manifest.get("alteredManifestSha256", ""))
          and installed.get("status") == "denied-and-restored",
          "Не наблюдался отказ нативных Runtime/CLI версии 0.43.14")
    name = installed.get("filePath")
    required = {e["path"]: e for e in snapshot["files"] if e.get("required", True)}
    check(isinstance(name, str) and name in required and
          not name.startswith("/") and "\\" not in name and
          all(part not in ("", ".", "..") for part in name.split("/")),
          "Проверка повреждения не затронула обязательный файл пакета")
    expected = required[name]["sha256"].lower()
    path = work / "delivery-verified-client" / name
    restored = work / "adversarial-restored-04314.json"
    check(path.is_file() and not path.is_symlink()
          and not any((work / "delivery-verified-client" / "/".join(name.split("/")[:i])).is_symlink()
                      for i in range(1, len(name.split("/")) + 1))
          and sha(path) == expected
          and installed.get("baselineSha256") == expected
          and installed.get("restoredFileSha256") == expected
          and installed.get("restoredVerificationSha256") == sha(restored)
          and read_json(restored).get("status") == "valid",
          "Отрицательный тест не восстановил точную подписанную сборку или не перезапустил рабочую проверку")
    return sha(work / "adversarial-gameplay-04314.json")


HEX64 = re.compile(r"^[a-f0-9]{64}$")
TOKEN = re.compile(r"^[a-zA-Z0-9_.:/@+,\-]{1,160}$")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def read_json(p, limit=4 * 1024 * 1024):
    if not p.is_file() or p.is_symlink() or p.stat().st_size > limit:
        raise ValueError("Доказательства отсутствуют или превышают допустимый размер: " + p.name)
    return json.loads(p.read_text(encoding="utf-8"))


def check(expr, message):
    if not expr:
        raise ValueError(message)


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def verify_lifecycle_0349(work, current_pkg, signed_manifest, identity):
    """Independently check actual release bytes and native lifecycle diagnostics.

    Trust a worker-supplied list of PASS assertions on its own.
    """
    proof = read_json(work / "update-recovery.json")
    root = work / "lifecycle-validation"
    prior = read_json(root / "previous-source" / "staged-package-description.json")
    prior_signed = read_json(root / "previous-source" / "signed-release-manifest.json")
    check(
        proof["schemaVersion"] == "launcher.lifecycle-validation.v1"
        and proof["status"] == "passed",
        "V09 lifecycle incomplete",
    )
    check(
        proof["currentPackageId"] == current_pkg["packageId"]
        and proof["currentVersion"] == current_pkg["version"]
        and proof["previousPackageId"] == prior["packageId"]
        and proof["previousVersion"] == prior["version"]
        and prior["packageId"] != current_pkg["packageId"]
        and prior["version"] != current_pkg["version"],
        "V09: откат в пределах выпуска или между пакетами",
    )
    check(
        prior["projectId"] == current_pkg["projectId"]
        and prior["profileId"] == current_pkg["profileId"]
        and prior_signed["version"] == prior["version"]
        and prior_signed["signature"]["publicKey"]
        == signed_manifest["signature"]["publicKey"],
        "V09: предыдущий выпуск имеет другой идентификатор или не подписан закреплённым ключом",
    )
    check(
        HEX64.fullmatch(proof["previousArchiveSha256"])
        and HEX64.fullmatch(proof["javaOriginalSha256"])
        and HEX64.fullmatch(proof["javaReplacementSha256"])
        and proof["javaOriginalSha256"] != proof["javaReplacementSha256"]
        and identity["javaSha256"] == proof["javaOriginalSha256"],
        "V09: замена Java не выполнена независимым исполняемым файлом",
    )
    required = (
        "cleanPreviousInstall",
        "failedUpdateLeavesPrevious",
        "upgrade",
        "corruptCacheRejected",
        "repair",
        "javaReplacementLaunch",
        "managedJavaRepairAndLaunch",
        "rollbackAndLaunch",
    )
    check(
        all(proof["checks"].get(key) == "passed" for key in required),
        "V09: обязательная транзакция жизненного цикла не прошла проверку",
    )
    for phase in ("staging", "committing"):
        p = proof["checks"].get("interruptedTransaction-" + phase, {})
        check(
            p.get("phase") == phase
            and p.get("killedUpdater") is True
            and p.get("recovery") == "passed"
            and p.get("previousRestored") is True
            and p.get("retryVerified") is True
            and p.get("currentPackageId") == current_pkg["packageId"],
            "V09: не выполнено восстановление после сбоя обновления на этапе: " + phase,
        )
        case = root / ("interrupted-" + phase)
        check(
            read_json(case / "prior.json").get("status") == "applied-and-verified"
            and read_json(case / "retry.json").get("status") == "applied-and-verified",
            "V09: прерванное обновление не завершило повторную попытку через рабочий CLI",
        )
    download = proof["checks"].get("interruptedDownload", {})
    check(
        download.get("interruptedRejected") is True
        and download.get("partialRemoved") is True
        and download.get("retryVerified") is True,
        "V09: прерванная загрузка приняла повреждённые данные",
    )
    check(
        sha(root / "interrupted-download.bin") == download["artifactSha256"],
        "V09: после повторной загрузки данные не совпадают",
    )
    check(
        read_json(root / "prior-install.json")["status"] == "applied-and-verified"
        and read_json(root / "update.json")["status"] == "applied-and-verified"
        and read_json(root / "repaired.json")["status"] == "repaired-and-verified"
        and read_json(root / "rollback.json")["status"] == "rolled-back"
        and read_json(root / "rollback.json")["restoredSnapshot"]
        == proof["rollbackSnapshot"],
        "V09: транзакции рабочего CLI не подтверждены",
    )
    check(
        read_json(root / "java-replacement-launch.json")["status"] == "passed"
        and read_json(root / "rollback-launch.json")["status"] == "passed"
        and read_json(root / "java-replacement-launch.json")["javaSha256"]
        == proof["javaReplacementSha256"]
        and read_json(root / "rollback-launch.json")["javaSha256"]
        == proof.get("previousJavaSha256", proof["javaOriginalSha256"]),
        "V09: не подтверждён запуск после реальной замены или отката JVM",
    )
    manager = proof.get("managedJava", {})
    check(
        manager.get("reinstalled") is True
        and manager.get("majorVersion") in (8, 16, 17, 21, 25)
        and HEX64.fullmatch(manager.get("manifestSha256", ""))
        and HEX64.fullmatch(manager.get("archiveSha256", ""))
        and HEX64.fullmatch(manager.get("javaSha256", ""))
        and read_json(root / "managed-java-repair-launch.json").get("status")
        == "passed"
        and read_json(root / "managed-java-repair-launch.json").get("javaSha256")
        == manager["javaSha256"],
        "V09: отсутствует восстановление или замена закреплённой управляемой Java и реальный запуск",
    )
    for name in (
        "java-replacement-launch.json",
        "rollback-launch.json",
        "managed-java-repair-launch.json",
    ):
        samples = read_json(root / name).get("menuSamples", [])
        check(
            len(samples) == 2
            and samples[0]["sha256"] != samples[1]["sha256"]
            and all(len(x.get("menuControls", [])) >= 2 for x in samples),
            "V09: отсутствует наблюдение реального меню или окна: " + name,
        )
    signed_files = {f["path"]: f for f in prior_signed["files"]}
    check(
        len(signed_files) == len(prior["files"]) and bool(signed_files),
        "V09: не совпадает количество подписанных файлов предыдущего выпуска",
    )
    actual = {}
    for item in prior["files"]:
        rel = item["path"]
        check(
            isinstance(rel, str)
            and rel
            and not rel.startswith("/")
            and "\\" not in rel
            and all(bit not in ("", ".", "..") for bit in rel.split("/")),
            "V09: небезопасный путь к предыдущему выпуску",
        )
        check(
            rel in signed_files
            and signed_files[rel]["sha256"] == item["sha256"]
            and signed_files[rel]["size"] == item["size"],
            "V09: манифест предыдущего выпуска не совпадает",
        )
        for directory in (root / "previous-source", root / "installation"):
            f = directory / rel
            check(
                f.is_file()
                and not f.is_symlink()
                and f.stat().st_size == item["size"]
                and sha(f) == item["sha256"],
                "V09: откат не восстановил подписанные данные предыдущего выпуска: " + rel,
            )
        actual[rel] = item["sha256"]
    check(
        proof["files"] == actual
        and hashlib.sha256(
            json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == proof["filesSha256"],
        "V09: контрольные суммы файлов после отката не согласованы",
    )
    return {
        "lifecycle-report.json": sha(work / "update-recovery.json"),
        "previous-release-manifest.json": sha(
            root / "previous-source" / "signed-release-manifest.json"
        ),
        "rollback-launch.json": sha(root / "rollback-launch.json"),
        "java-replacement-launch.json": sha(root / "java-replacement-launch.json"),
        "managed-java-repair-launch.json": sha(
            root / "managed-java-repair-launch.json"
        ),
    }


def verify_local_artifacts(work, issued, image_sha, source_sha, build_sha, bridge_sha):
    """Запускайте только после успешного завершения доверенного контейнера OCI с закреплённым образом."""
    report = read_json(work / "staged-execution.json")
    check(
        report["schemaVersion"] == "launcher.staged-runtime-run.v1",
        "Некорректная схема отчёта о выполнении",
    )
    for k in ("runId", "packageId", "manifestSha256", "artifactSha256"):
        check(report[k] == issued[k], "Несовпадение подготовленного разрешения и отчёта: " + k)
    stages = report["stages"]
    check(
        set(stages) == set(REQUIRED),
        "Подготовленное выполнение не завершено или содержит неизвестные этапы",
    )
    for name in REQUIRED:
        check(stages[name]["status"] == "passed", "Не проверен этап Runtime: " + name)
    hashes = {name: sha(work / name) for name in FILES}
    for stage, name in STAGE_ARTIFACT.items():
        check(
            stages[stage].get("evidenceSha256") == hashes[name],
            "Свидетельство этапа не соответствует исходному артефакту: " + stage,
        )
    # The job's actual display, renderer and OS are part of the verified
    # observations. A headless/materialization-only job must be signed
    # as a positive Minecraft runtime run.
    host = read_json(work / "host-capabilities.json")
    check(
        host.get("schemaVersion") == "launcher.runner-capabilities.v1"
        and host.get("status") == "ready"
        and host.get("gui") is True
        and host.get("mode") == "gui"
        and host.get("os") == "linux"
        and host.get("arch") == "amd64"
        and isinstance(host.get("renderer"), dict)
        and bool(host["renderer"].get("renderer"))
        and bool(host["renderer"].get("version")),
        "V10: на доверенном исполнителе Linux/amd64 не подтверждена работоспособность графического OpenGL",
    )
    hashes["host-capabilities.json"] = sha(work / "host-capabilities.json")
    identity = read_json(work / "execution-identity.json")
    check(
        HEX64.fullmatch(identity["javaSha256"])
        and HEX64.fullmatch(identity["RuntimeSha256"])
        and HEX64.fullmatch(identity["cliSha256"]),
        "Контрольные суммы Java или исполняемых файлов не привязаны к проверке",
    )
    check(
        hashlib.sha256(
            (identity["cliSha256"] + identity["RuntimeSha256"]).encode()
        ).hexdigest()
        == identity["installAdapterSha256"],
        "Идентификатор исполняемого файла установочного адаптера не согласован",
    )
    check(
        HEX64.fullmatch(identity["resolvedPlanSha256"])
        and HEX64.fullmatch(identity["guardPolicySha256"]),
        "План Runtime или политика Guard не привязаны к проверке",
    )
    # Independently verify the exact staged downloads AND the actual installed
    # bytes. A report saying "valid" cannot compensate for a modified game jar.
    snapshot = read_json(work / "payload" / "staged-package-description.json")
    signed_manifest = read_json(work / "payload" / "signed-release-manifest.json")
    check(
        snapshot["packageId"] == issued["packageId"]
        and signed_manifest["projectId"] == snapshot["projectId"]
        and signed_manifest["version"] == snapshot["version"],
        "Не совпадает идентификатор подготовленного выпуска",
    )
    signed_files = {f["path"]: f for f in signed_manifest["files"]}
    check(
        len(signed_files) == len(snapshot["files"]) and bool(signed_files),
        "Подписанные подготовленные файлы отсутствуют или повторяются",
    )
    native_adoption = read_json(work / "native-adoption.json")
    check(
        native_adoption.get("status") == "ready"
        and native_adoption.get("networkDownloads") == 0
        and isinstance(native_adoption.get("importedFiles"), int)
        and native_adoption["importedFiles"] > 0
        and HEX64.fullmatch(native_adoption.get("planSha256", "")),
        "Нативная транзакция должна использовать точные подготовленные данные без сетевой загрузки",
    )
    catalog = signed_manifest.get("componentCatalog")
    if catalog:
        selection = read_json(work / "component-selection.json")
        check(
            selection["schemaVersion"] == "launcher.component-execution.v1"
            and selection["preset"] == identity["preset"]
            and selection["catalogDigest"] == catalog["digest"],
            "Выбранный каталог или набор компонентов не связан с запуском",
        )
        selected_ids, selected_paths = selected_components(
            signed_manifest, selection["preset"]
        )
        native = read_json(work / "component-verification.json")
        sync = read_json(work / "component-sync.json")
        check(
            native.get("status") == "ready"
            and sync == native_adoption
            and sync.get("status") == "ready",
            "Выбранная нативная установка не зафиксирована и не проверена",
        )
        check(
            selection["syncSha256"] == sha(work / "component-sync.json")
            and selection["nativeVerifySha256"]
            == sha(work / "component-verification.json"),
            "Артефакты нативной проверки компонентов были изменены",
        )
        observed = {
            f["path"] for f in native.get("files", []) if f.get("status") == "ok"
        }
        check(
            observed <= selected_paths and bool(observed),
            "Нативная проверка затронула файлы вне выбранного набора компонентов",
        )
        # For every optional JAR, presence must equal signed membership. A
        # default install leaving unselected mods in mods/ would be a FAIL.
        all_optional = {f for c in catalog["components"] for f in c["files"]}
        for name in all_optional:
            if name not in selected_paths:
                check(
                    not (work / "client" / name).exists()
                    and not (work / "client" / name).is_symlink(),
                    "Невыбранный дополнительный компонент остаётся установленным: "
                    + name,
                )
        listed = sorted(
            (f["path"], signed_files[f["path"]]["sha256"])
            for f in native["files"]
            if f["status"] == "ok"
        )
        calculated_component_digest = hashlib.sha256(
            json.dumps(
                {
                    "catalogDigest": catalog["digest"],
                    "preset": selection["preset"],
                    "selectedFiles": listed,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        check(
            selection["resolvedComponentPlanSha256"] == calculated_component_digest,
            "Подписанный план компонентов не соответствует путям, проверенным нативным кодом",
        )
        hashes["component-selection.json"] = sha(work / "component-selection.json")
        hashes["component-verification.json"] = sha(
            work / "component-verification.json"
        )
        hashes["component-sync.json"] = sha(work / "component-sync.json")
        extra = {
            "componentSelection": selection["preset"],
            "componentPlanSha256": selection["resolvedComponentPlanSha256"],
            "componentCatalogDigest": catalog["digest"],
        }
    else:
        check(identity["preset"] == "default", "Заявлен выбор компонентов без подписи")
        selected_paths = {f["path"] for f in signed_manifest["files"]}
        extra = {}
    for entry in snapshot["files"]:
        name = entry["path"]
        check(
            isinstance(name, str)
            and name
            and not name.startswith("/")
            and not any(bit in (".", "..", "") for bit in name.split("/"))
            and "\\" not in name,
            "Небезопасный путь подготовленного файла",
        )
        check(
            name in signed_files
            and entry["sha256"] == signed_files[name]["sha256"]
            and entry["size"] == signed_files[name]["size"],
            "Подготовленный файл не соответствует подписанному манифесту",
        )
        folders = (
            (work / "payload", work / "client")
            if name in selected_paths
            else (work / "payload",)
        )
        for folder in folders:
            full = folder / name
            check(
                full.is_file()
                and not full.is_symlink()
                and full.resolve().is_relative_to(folder.resolve())
                and full.stat().st_size == entry["size"]
                and sha(full) == entry["sha256"],
                "Загруженные или установленные данные клиента не совпадают с подписанными подготовленными данными: "
                + name,
            )
    recomputed = hashlib.sha256(
        json.dumps(
            dict(
                {
                    "minecraft": signed_manifest.get("minecraft"),
                    "runtime": signed_manifest.get("runtime"),
                    "fileHashes": sorted(
                        (f["path"], f["sha256"]) for f in snapshot["files"]
                    ),
                },
                **extra,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    check(
        identity["resolvedPlanSha256"] == recomputed,
        "Контрольная сумма плана Runtime не привязана к подписанному подготовленному содержимому",
    )
    guard = signed_manifest.get("runtime", {}).get("guard", {})
    actual_guard = hashlib.sha256(
        json.dumps(guard, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    check(
        identity["guardPolicySha256"] == actual_guard
        and identity["guardMode"] == str(guard.get("mode") or "disabled"),
        "Несовпадение политики Guard",
    )
    check(
        identity["loader"]
        == signed_manifest.get("minecraft", {}).get("loader", "vanilla").lower(),
        "Загрузчик не соответствует подписанному манифесту",
    )
    check(
        identity["preset"] == (selection["preset"] if catalog else "default"),
        "Фактический набор компонентов не соответствует подписанному выбору",
    )
    hashes.update(verify_lifecycle_0349(work, snapshot, signed_manifest, identity))
    install = read_json(work / "verified.json")
    check(install["status"] == "valid", "Проверка клиента не пройдена")
    startup = read_json(work / "startup-readiness.json")
    check(
        startup["schemaVersion"] == "launcher.startup-readiness.v1"
        and startup["windowPid"] is not None
        and not startup.get("failure")
        and not startup.get("blocked"),
        "Готовность графического интерфейса не подтверждена",
    )
    samples = startup.get("samples", [])
    check(
        len(samples) == 2 and samples[0]["sha256"] != samples[1]["sha256"],
        "Отсутствуют два различающихся отрисованных кадра меню",
    )
    for i, sample in enumerate(samples, 1):
        f = work / "startup-diagnostics" / f"menu-frame-{i}.png"
        check(
            f.is_file()
            and not f.is_symlink()
            and sha(f) == sample["sha256"]
            and len(sample["menuControls"]) >= 2
            and sample["pid"] == startup["windowPid"]
            and sample["width"] >= 640
            and sample["height"] >= 400,
            "Кадр меню не связан с окном Java",
        )
        hashes["menu-frame-" + str(i) + ".png"] = sha(f)
    authentication = read_json(work / "authentication.json")
    mode = authentication.get("mode")
    check(
        mode in ("official", "custom")
        and authentication.get("provider") == "live"
        and authentication.get("status") == "passed"
        and authentication.get("runId") == issued["runId"]
        and authentication.get("manifestSha256") == issued["manifestSha256"]
        and authentication.get("artifactSha256") == issued["artifactSha256"]
        and authentication.get("providerJoin") == "passed"
        and authentication.get("providerHasJoined") == "passed"
        and HEX64.fullmatch(authentication.get("profileSha256", "")),
        "Отсутствует аутентификация у реального провайдера либо имитация не допускается",
    )
    if mode == "custom":
        check(
            authentication.get("replayDenied") is True
            and authentication.get("revokedSessionDenied") is True
            and authentication.get("deviceTrust")
            == "positive-join-and-live-trust-denial"
            and authentication.get("guardPolicySha256")
            == identity["guardPolicySha256"],
            "Не проверены отзыв доступа, защита от повторов и политика устройств пользовательского Yggdrasil",
        )
        check(
            authentication.get("negativeDeviceTrustJoinDenied") is True,
            "Политика доверия к устройствам должна отклонять реальную тестовую сессию с недопустимой конфигурацией",
        )
        if identity["guardMode"] != "disabled":
            check(
                authentication.get("negativeGuardJoinDenied") is True,
                "Для Runtime с Guard требуется реальный отказ, связанный с политикой Guard",
            )
    else:
        check(
            authentication.get("serverOnlineModeRequired") is True
            and identity["guardMode"] == "disabled",
            "Официальный Minecraft требует online-mode и отключённый Guard до получения реального подтверждения политики Guard",
        )
    server = read_json(work / "server-readiness.json")
    game = read_json(work / "gameplay-smoke.json")
    props = work / "matching-server" / "server.properties"
    check(
        props.is_file() and not props.is_symlink(), "Отсутствуют свойства соответствующего сервера"
    )
    server_properties = dict(
        line.split("=", 1)
        for line in props.read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    expected_online = mode == "official"
    check(
        server.get("onlineMode") is expected_online
        and server_properties.get("online-mode") == str(expected_online).lower()
        and server_properties.get("server-ip") == "127.0.0.1",
        "Политика online-mode сервера Minecraft не соответствует реальному провайдеру",
    )
    hashes["server.properties"] = sha(props)
    check(
        server["runId"] == issued["runId"] and game["runId"] == issued["runId"],
        "Не совпадают идентификаторы игрового и серверного запусков",
    )
    check(
        server["startup"] == "passed"
        and server["minecraftVersion"] == game["minecraftVersion"]
        and server["loader"] == game["loader"]
        and server["loaderVersion"] == game["loaderVersion"],
        "Не совпадают версии сервера, плагина или Runtime",
    )
    if needs_adversarial_gameplay(signed_manifest["version"]):
        hashes["adversarial-gameplay-04314.json"] = verify_adversarial_gameplay_04314(
            work, signed_manifest, snapshot, game)
    check(
        game["status"] == "passed"
        and game["serverJoinAndOnline"] is True
        and game["clientConnectionLogObserved"] is True
        and game["clientInputSent"] is True
        and game["windowJavaProcessId"] is not None
        and not game["failure"],
        "Игровой процесс не подтверждён",
    )
    before, after = game["positionBefore"], game["positionAfter"]
    check(
        len(before) == 3
        and len(after) == 3
        and any(abs(float(a) - float(b)) > 0.001 for a, b in zip(before, after))
        and int(game["ticksAfter"]) > int(game["ticksBefore"]),
        "Сервер не подтвердил движение игрока или игровые тики",
    )
    check(
        game["frameBeforeSha256"] != game["frameAfterSha256"]
        and all(
            HEX64.fullmatch(game[k]) for k in ("frameBeforeSha256", "frameAfterSha256")
        ),
        "Отрисованные игровые кадры не изменились",
    )
    for filename, key in (
        ("world-before.png", "frameBeforeSha256"),
        ("world-after.png", "frameAfterSha256"),
    ):
        frame = work / "gameplay-diagnostics" / filename
        check(
            frame.is_file() and not frame.is_symlink() and sha(frame) == game[key],
            "Снимок игрового процесса отсутствует или его контрольная сумма неверна",
        )
        hashes[filename] = sha(frame)
    check(
        identity["loader"] == server["loader"]
        and TOKEN.fullmatch(identity["preset"])
        and TOKEN.fullmatch(identity["guardMode"]),
        "Не совпадают подписанные параметры загрузчика, набора компонентов или Guard",
    )
    check(
        HEX64.fullmatch(bridge_sha),
        "Контрольная сумма Bridge должна быть закреплена (нулевая сумма для Vanilla)",
    )
    if mode == "custom":
        check(
            server["bridgeRequired"],
            "Подходящий сервер пользовательского Yggdrasil должен запускать проверенный ServerBridge",
        )
    if server["bridgeRequired"]:
        check(
            bridge_sha != "0" * 64
            and server["bridgeRequired"]
            and game["serverBridgeVersion"],
            "ServerBridge обязателен, но не проверен",
        )
    else:
        check(
            bridge_sha == "0" * 64,
            "Для Vanilla без Bridge нельзя заявлять наличие исполняемого файла Bridge",
        )
    java_version = identity["javaVersionRaw"].splitlines()[0].strip()
    match = re.search(r'(?:version\s+)?["\']?([0-9]+(?:\.[0-9]+){0,3})', java_version)
    check(bool(match), "Версия Java не проверена")
    java_version = match.group(1)
    image_sha = image_sha.lower()
    check(
        HEX64.fullmatch(image_sha)
        and HEX64.fullmatch(build_sha)
        and bool(re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", source_sha)),
        "Недоверенное происхождение сборки на узле",
    )
    started = datetime.fromisoformat(report["startedAt"].replace("Z", "+00:00"))
    finished = datetime.fromisoformat(report["finishedAt"].replace("Z", "+00:00"))
    check(
        started <= finished
        and (finished - started).total_seconds() < 4 * 3600
        and finished <= datetime.now(timezone.utc),
        "Некорректные временные границы выполнения",
    )
    # IMPORTANT: order must match Go validationPayload0345 field order.
    evidence = {
        "schemaVersion": SCHEMA,
        "runNonce": issued["nonce"],
        "audience": "launcher-api/validation-evidence/0.34.7",
        "purpose": "staged-package-runtime-verification",
        "targetId": "",
        "targetMatrixSha256": issued["targetMatrixSha256"],
        "signerKeyId": "0" * 64,
        "packageVersion": signed_manifest["version"],
        "runId": report["runId"],
        "packageId": report["packageId"],
        "manifestSha256": report["manifestSha256"],
        "artifactSha256": report["artifactSha256"],
        "resolvedPlanSha256": identity["resolvedPlanSha256"],
        "sourceSha": source_sha,
        "buildSha": build_sha,
        "runnerImageSha256": image_sha,
        "javaSha256": identity["javaSha256"],
        "javaVersion": java_version,
        "os": "linux",
        "arch": "amd64",
        "loader": identity["loader"],
        "installAdapterSha256": identity["installAdapterSha256"],
        "guardMode": identity["guardMode"],
        "guardPolicySha256": identity["guardPolicySha256"],
        "serverBridgeSha256": bridge_sha,
        "serverPluginVersion": game["serverBridgeVersion"] or "none",
        "preset": identity["preset"],
        "authenticationMode": mode,
        "stages": {k: stages[k]["status"] for k in sorted(stages)},
        "artifactHashes": {k: hashes[k] for k in sorted(hashes)},
        "startedAt": report["startedAt"],
        "finishedAt": report["finishedAt"],
        "issuedAt": issued["issuedAt"],
        "expiresAt": (
            datetime.fromisoformat(issued["issuedAt"].replace("Z", "+00:00"))
            + __import__("datetime").timedelta(hours=24)
        )
        .isoformat()
        .replace("+00:00", "Z"),
    }
    # The target matrix is issued by the Backend, not selected by CI or the
    # worker. Require an EXACT identity match; no wildcard or fallback target.
    fields = (
        "packageVersion",
        "manifestSha256",
        "artifactSha256",
        "resolvedPlanSha256",
        "sourceSha",
        "buildSha",
        "javaSha256",
        "javaVersion",
        "os",
        "arch",
        "loader",
        "installAdapterSha256",
        "guardMode",
        "guardPolicySha256",
        "serverBridgeSha256",
        "serverPluginVersion",
        "preset",
        "authenticationMode",
    )
    applicable = [
        t
        for t in issued["requiredTargets"]
        if all(
            t.get("version" if k == "packageVersion" else k) == evidence.get(k)
            for k in fields
        )
    ]
    check(
        len(applicable) == 1,
        "Нет единственного настроенного целевого окружения, точно соответствующего Java, набору компонентов, серверу, сборке и Runtime",
    )
    evidence["targetId"] = applicable[0]["id"]
    check(
        HEX64.fullmatch(evidence["runNonce"])
        and HEX64.fullmatch(evidence["targetMatrixSha256"]),
        "Отсутствует выданное Backend одноразовое значение запуска или целевая матрица",
    )
    for val in (
        "runId",
        "packageId",
        "targetId",
        "packageVersion",
        "javaVersion",
        "os",
        "arch",
        "loader",
        "guardMode",
        "serverPluginVersion",
        "preset",
        "authenticationMode",
        "audience",
        "purpose",
    ):
        check(
            TOKEN.fullmatch(evidence[val]), "Небезопасное или неканоническое подписанное значение: " + val
        )
    return evidence


def request_json(base, path, token, body):
    u = base.rstrip("/") + path
    req = urllib.request.Request(
        u,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as res:
        check(res.status == 201, "Backend отклонил операцию проверки")
        return json.load(res)["data"]


def sign_evidence(payload, key_path):
    p = Path(key_path)
    check(p.stat().st_mode & 0o077 == 0, "Закрытый ключ аттестации должен быть доступен только владельцу")
    private = load_pem_private_key(p.read_bytes(), password=None)
    check(isinstance(private, Ed25519PrivateKey), "Требуется ключ аттестации Ed25519")
    payload = dict(payload)
    payload["signerKeyId"] = hashlib.sha256(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).hexdigest()
    payload = {key: payload[key] for key in EVIDENCE_FIELDS}
    # The byte order of the following dictionary is the Go struct field order.
    return {
        "evidence": payload,
        "signature": base64.urlsafe_b64encode(private.sign(DOMAIN + canonical(payload)))
        .decode()
        .rstrip("="),
    }


def execute_run(cfg, package_id, selection=None, issued_grant=None):
    check(
        re.fullmatch(r"[A-Za-z0-9_\-]{1,128}", package_id), "Некорректный идентификатор пакета"
    )
    check(
        platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"),
        "Этот закреплённый раннер предназначен только для Linux amd64; другим платформам требуется собственная сборка",
    )
    check(cfg.backend.startswith("https://"), "Для аттестации требуется Backend по HTTPS")
    check(
        "@sha256:" in cfg.image and HEX64.fullmatch(cfg.image.rsplit("@sha256:", 1)[1]),
        "Образ раннера должен быть закреплён контрольной суммой OCI",
    )
    image_sha = cfg.image.rsplit("@sha256:", 1)[1]
    check(
        re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", cfg.source_sha),
        "Коммит исходного кода должен быть закреплён",
    )
    check(HEX64.fullmatch(cfg.build_sha), "Контрольная сумма SHA-256 доверенной сборки должна быть закреплена")
    check(
        HEX64.fullmatch(cfg.manifest_key), "Ключ подписанного подготовленного манифеста должен быть закреплён"
    )
    # Pull/inspect the digest-identified image on the trusted host. Image labels
    # are immutable under the pinned digest, so arbitrary host-provided source
    # and build identifiers cannot be silently presented as observed provenance.
    subprocess.run(
        [cfg.engine, "pull", "--quiet", cfg.image],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=600,
    )
    inspected = subprocess.run(
        [cfg.engine, "image", "inspect", "--format", "{{json .Labels}}", cfg.image],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=True,
    )
    labels = json.loads(inspected.stdout)
    check(
        labels.get("org.opencontainers.image.revision") == cfg.source_sha
        and labels.get("io.launcher.validation.build-sha256") == cfg.build_sha,
        "Метки происхождения закреплённого образа не соответствуют выпуску, одобренному оператором",
    )
    # Do not accept a user-chosen executable, runtime, image, Docker flags or signing key.
    grant = (
        issued_grant
        if issued_grant is not None
        else request_json(
            cfg.backend,
            "/api/v1/packages/" + package_id + "/staged-runs",
            cfg.operator_token,
            {},
        )
    )
    check(
        grant["packageId"] == package_id and grant["attested"] is False,
        "Backend выдал неверный подготовленный снимок",
    )
    with tempfile.TemporaryDirectory(prefix="launcher-attestor-") as tmp:
        root = Path(tmp)
        inp = root / "input"
        out = root / "output"
        inp.mkdir(mode=0o700)
        out.mkdir(mode=0o700)
        grant_path = inp / "grant.json"
        grant_path.write_text(json.dumps(grant), encoding="utf-8")
        grant_path.chmod(0o600)
        official_credentials = inp / "official-credentials.json"
        if cfg.auth_mode == "official":
            check(
                cfg.official_client_id and cfg.official_refresh_token_file,
                "Официальный провайдер требует разрешённую тестовую учётную запись и токен обновления, доступный только узлу",
            )
            issue_minecraft_credentials(
                cfg.official_client_id,
                cfg.official_refresh_token_file,
                official_credentials,
            )
        if cfg.server_bundle_file:
            check(
                cfg.server_sha
                and HEX64.fullmatch(cfg.server_sha)
                and sha(cfg.server_bundle_file) == cfg.server_sha,
                "Контрольная сумма серверного пакета не соответствует закреплённой оператором",
            )
        job_network = "nlval-" + grant["runId"][:24]
        check(os.getuid() != 0, "Служба аттестации ОБЯЗАНА работать от непривилегированной учётной записи")
        subprocess.run(
            [cfg.engine, "network", "create", job_network],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        # Mount production data, Docker socket, runner source checkout,
        # admin token or signing key. Each job gets a fresh network namespace,
        # root filesystem readonly, all Linux capabilities dropped and bounded resources.
        name = "nl-validation-" + grant["runId"][:24]
        args = [
            cfg.engine,
            "run",
            "--rm",
            "--name",
            name,
            "--init",
            "--read-only",
            "--userns=keep-id",
            "--platform",
            "linux/amd64",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop=ALL",
            "--pids-limit=256",
            "--memory=6g",
            "--cpus=4",
            "--network",
            job_network,
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=2g",
            "--mount",
            f"type=bind,src={inp},dst=/run/staged,readonly",
            "--mount",
            f"type=bind,src={out},dst=/work",
            cfg.image,
            "--backend",
            cfg.backend,
            "--grant-file",
            "/run/staged/grant.json",
            "--package-id",
            package_id,
            "--output",
            "/work",
            "--cli",
            "/opt/launcher",
            "--runtime",
            "/opt/runtime",
            "--java",
            "auto",
            "--pinned-public-key",
            cfg.manifest_key,
            "--runtime-seconds",
            str(cfg.runtime_seconds),
        ]
        check(
            not Path(cfg.previous_bundle_file).is_symlink(),
            "Символьная ссылка на пакет предыдущего выпуска запрещена",
        )
        prior_bundle = Path(cfg.previous_bundle_file).resolve(strict=True)
        check(
            prior_bundle.is_file()
            and not prior_bundle.is_symlink()
            and HEX64.fullmatch(cfg.previous_sha)
            and sha(prior_bundle) == cfg.previous_sha,
            "Закреплённый на узле предыдущий выпуск отсутствует или изменён",
        )
        replacement_home = Path(cfg.replacement_java_home).resolve(strict=True)
        replacement_binary = replacement_home / "bin" / "java"
        check(
            replacement_binary.is_file() and replacement_binary.stat().st_mode & 0o111,
            "Отсутствует одобренная узлом замена Java",
        )
        args[args.index(cfg.image) : args.index(cfg.image)] = [
            "--mount",
            f"type=bind,src={prior_bundle},dst=/run/previous/release.zip,readonly",
            "--mount",
            f"type=bind,src={replacement_home},dst=/run/replacement-java,readonly",
        ]
        managed_manifest = Path(cfg.managed_java_manifest_file)
        check(
            not managed_manifest.is_symlink()
            and managed_manifest.is_file()
            and HEX64.fullmatch(cfg.managed_java_sha)
            and sha(managed_manifest) == cfg.managed_java_sha,
            "Манифест управляемой Java, одобренный узлом, отсутствует или не закреплён",
        )
        managed_dir = managed_manifest.resolve(strict=True).parent
        args[args.index(cfg.image) : args.index(cfg.image)] = [
            "--mount",
            f"type=bind,src={managed_dir},dst=/run/managed-java,readonly",
        ]
        args.extend(
            [
                "--previous-bundle",
                "/run/previous/release.zip",
                "--previous-sha256",
                cfg.previous_sha,
                "--replacement-java",
                "/run/replacement-java/bin/java",
                "--managed-java-manifest",
                "/run/managed-java/" + managed_manifest.name,
                "--managed-java-sha256",
                cfg.managed_java_sha,
            ]
        )
        if cfg.server_bundle_file:
            args[args.index(cfg.image) : args.index(cfg.image)] = [
                "--mount",
                f"type=bind,src={Path(cfg.server_bundle_file).resolve()},dst=/run/server/bundle.zip,readonly",
            ]
            args += [
                "--server-bundle",
                "/run/server/bundle.zip",
                "--server-sha256",
                cfg.server_sha,
                "--server-entry",
                cfg.server_entry,
                "--bridge-path",
                cfg.bridge_path,
                "--bridge-sha256",
                cfg.bridge_sha,
                "--bridge-version",
                cfg.bridge_version,
            ]
        check(
            cfg.auth_mode in ("official", "custom"),
            "Режим реального провайдера V07 должен быть указан явно",
        )

        def mount_identity(hostfile, inside, argument, required):
            if not hostfile:
                check(not required, "Недоступна обязательная реальная тестовая учётная запись")
                return
            supplied = Path(hostfile)
            check(not supplied.is_symlink(), "Символьная ссылка на файл учётных данных запрещена")
            path = supplied.resolve(strict=True)
            stat = path.stat()
            check(
                path.is_file()
                and not path.is_symlink()
                and stat.st_mode & 0o077 == 0
                and stat.st_size <= 16384,
                "Файл учётных данных тестовой записи должен быть обычным файлом с доступом только для владельца",
            )
            # Mounted directly, copied into generic work/output artifacts.
            args[args.index(cfg.image) : args.index(cfg.image)] = [
                "--mount",
                f"type=bind,src={path},dst={inside},readonly",
            ]
            args.extend([argument, inside])

        if selection is not None:
            check(
                selection["authenticationMode"] == cfg.auth_mode
                and selection["preset"]
                in {target["preset"] for target in grant["requiredTargets"]},
                "Целевое окружение не разрешено матрицей Runtime, выданной Backend",
            )
            args.extend(["--preset", selection["preset"]])
        args.extend(["--auth-mode", cfg.auth_mode])
        mount_identity(
            str(official_credentials)
            if cfg.auth_mode == "official"
            else cfg.credentials_file,
            "/run/auth/credentials.json",
            "--credentials-file",
            True,
        )
        mount_identity(
            cfg.negative_credentials_file,
            "/run/auth/negative.json",
            "--negative-credentials-file",
            cfg.auth_mode == "custom",
        )
        mount_identity(
            cfg.guard_denied_credentials_file,
            "/run/auth/guard-denied.json",
            "--guard-denied-credentials-file",
            cfg.auth_mode == "custom",
        )
        worker_log = root / "worker-redacted-pending.log"
        try:
            with open(worker_log, "wb") as log:
                proc = subprocess.run(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=7200,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            subprocess.run(
                [cfg.engine, "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
            )
            raise
        finally:
            subprocess.run(
                [cfg.engine, "network", "rm", job_network],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        # Retain only redacted, bounded host-only diagnostics with a digest and
        # expiry; make the raw stdout available to API, CI or operator UI.
        if cfg.diagnostics_dir:
            retain_redacted_diagnostics(
                worker_log,
                Path(cfg.diagnostics_dir),
                grant["runId"],
                cfg.diagnostics_ttl_hours,
            )
        check(proc.returncode == 0, "Закреплённый исполнитель завершился с ошибкой; доверенные свидетельства не получены")
        payload = verify_local_artifacts(
            out, grant, image_sha, cfg.source_sha, cfg.build_sha, cfg.bridge_sha
        )
        check(
            payload["authenticationMode"] == cfg.auth_mode,
            "Исполнитель вернул другого реального провайдера авторизации, чем выбранный узлом",
        )
        if selection is not None:
            check(
                payload["targetId"] == selection["id"]
                and payload["preset"] == selection["preset"],
                "Исполнитель запустил другое целевое окружение матрицы Runtime",
            )
        signed = sign_evidence(payload, cfg.signing_key)
        # No signature is ever exposed to an OCI container or a user-supplied
        # report. Only the backend receives signed evidence via scoped API.
        result = request_json(
            cfg.backend,
            "/api/v1/packages/" + package_id + "/validation-attestations",
            cfg.operator_token,
            signed,
        )
        return {
            "runId": grant["runId"],
            "attestationVerified": result["attestationVerified"],
            "stablePublishEligible": False,
        }


def execute_matrix(cfg, package_id):
    """Execute every required target on its OWN fresh staged grant and OCI job.

    A failed case remains failed. A passing default cannot be substituted for a
    missing preset. Unsupported OS/arch targets remain incomplete until a
    real matching worker executes them; no synthetic pass is emitted.
    """
    initial = request_json(
        cfg.backend,
        "/api/v1/packages/" + package_id + "/staged-runs",
        cfg.operator_token,
        {},
    )
    targets = initial.get("requiredTargets", [])
    check(
        bool(targets) and len(targets) <= 128,
        "Backend не предоставил обязательные целевые окружения Runtime",
    )
    outcomes = []
    seen = set()
    for index, target in enumerate(targets):
        ident = target["id"]
        check(ident not in seen, "Повторяющийся идентификатор обязательного целевого окружения")
        seen.add(ident)
        if target["os"] != "linux" or target["arch"] not in ("amd64", "x86_64"):
            outcomes.append(
                {
                    "targetId": ident,
                    "preset": target["preset"],
                    "status": "blocked",
                    "detail": "Для целевого окружения требуется независимый доверенный раннер с подходящими ОС и архитектурой",
                }
            )
            continue
        if target["authenticationMode"] != cfg.auth_mode:
            outcomes.append(
                {
                    "targetId": ident,
                    "preset": target["preset"],
                    "status": "blocked",
                    "detail": "Для целевого окружения требуется собственный раннер реального провайдера авторизации",
                }
            )
            continue
        try:
            # A separate grant/challenge/workdir prevents one successful run
            # from being replayed for two target IDs or two different presets.
            grant = (
                initial
                if index == 0
                else request_json(
                    cfg.backend,
                    "/api/v1/packages/" + package_id + "/staged-runs",
                    cfg.operator_token,
                    {},
                )
            )
            check(
                grant["targetMatrixSha256"] == initial["targetMatrixSha256"],
                "Обязательная матрица изменилась во время выполнения; перезапустите всю матрицу",
            )
            result = execute_run(cfg, package_id, target, grant)
            outcomes.append(
                {
                    "targetId": ident,
                    "preset": target["preset"],
                    "status": "passed",
                    "runId": result["runId"],
                }
            )
        except Exception as exc:
            outcomes.append(
                {
                    "targetId": ident,
                    "preset": target["preset"],
                    "status": "failed",
                    "detail": redact_diagnostics(str(exc))[:512],
                }
            )
    return {
        "packageId": package_id,
        "targetMatrixSha256": initial["targetMatrixSha256"],
        "allRequiredTargetsVerified": all(x["status"] == "passed" for x in outcomes),
        "targets": outcomes,
        "stablePublishEligible": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend", required=True)
    p.add_argument(
        "--operator-token-file",
        required=True,
        help="Файл учётных данных только для узла с правами 0600; передаётся воркеру",
    )
    p.add_argument(
        "--signing-key",
        required=True,
        help="Ключ Ed25519 PKCS8 PEM только для узла, права доступа 0600",
    )
    p.add_argument(
        "--image", required=True, help="Доверенный образ, полностью закреплённый по имени@sha256:..."
    )
    p.add_argument("--auth-mode", choices=("official", "custom"), required=True)
    p.add_argument(
        "--credentials-file", default="", help="Только JSON тестовой сессии пользовательского Yggdrasil"
    )
    p.add_argument(
        "--official-client-id",
        default="",
        help="Отдельный идентификатор публичного клиентского приложения Microsoft",
    )
    p.add_argument(
        "--official-refresh-token-file",
        default="",
        help="Токен обновления разрешённой тестовой учётной записи только для узла, права 0600",
    )
    p.add_argument(
        "--negative-credentials-file",
        default="",
        help="Отдельная действующая сессия для пользовательского отзыва доступа",
    )
    p.add_argument(
        "--guard-denied-credentials-file",
        default="",
        help="Реальная действующая сессия с запретом по политике",
    )
    p.add_argument(
        "--previous-bundle-file",
        required=True,
        help="Предыдущий подписанный ZIP выпуска, одобренный администратором узла",
    )
    p.add_argument(
        "--previous-sha", required=True, help="SHA-256 пакета предыдущего выпуска"
    )
    p.add_argument(
        "--replacement-java-home",
        required=True,
        help="Другой каталог JDK/JRE, одобренный администратором узла",
    )
    p.add_argument(
        "--managed-java-manifest-file",
        required=True,
        help="Манифест производственной поставки Temurin с зафиксированной версией; архив в том же каталоге",
    )
    p.add_argument(
        "--managed-java-sha",
        required=True,
        help="SHA-256 зафиксированного манифеста Managed JRE",
    )
    p.add_argument(
        "--server-bundle-file",
        default="",
        help="Полный соответствующий ZIP сервера, закреплённый администратором узла",
    )
    p.add_argument("--server-sha", default="")
    p.add_argument("--server-entry", default="")
    p.add_argument("--bridge-path", default="")
    p.add_argument("--bridge-version", default="")
    p.add_argument("--source-sha", required=True)
    p.add_argument("--build-sha", required=True)
    p.add_argument("--manifest-key", required=True)
    p.add_argument("--bridge-sha", default="0" * 64)
    p.add_argument("--runtime-seconds", type=int, default=180)
    p.add_argument(
        "--diagnostics-dir",
        required=True,
        help="Каталог диагностики воркера с удалёнными секретами, доступный только узлу (0700)",
    )
    p.add_argument("--diagnostics-ttl-hours", type=int, default=168)
    p.add_argument("--engine", choices=("podman",), default="podman")
    p.add_argument(
        "--package-id", help="Однократная аттестация; пропустить для службы mTLS"
    )
    p.add_argument("--listen", default="127.0.0.1:8845")
    p.add_argument("--tls-cert", default="")
    p.add_argument("--tls-key", default="")
    p.add_argument("--client-ca", default="")
    cfg = p.parse_args()
    token_path = Path(cfg.operator_token_file)
    check(
        token_path.stat().st_mode & 0o077 == 0,
        "Учётные данные оператора узла должны быть доступны только владельцу",
    )
    cfg.operator_token = token_path.read_text(encoding="utf-8").strip()
    check(bool(cfg.operator_token), "Отсутствуют учётные данные оператора узла")
    check(15 <= cfg.runtime_seconds <= 3600, "Некорректный крайний срок выполнения Runtime")
    check(1 <= cfg.diagnostics_ttl_hours <= 720, "Некорректный срок хранения диагностики (TTL)")
    # A rootful Docker daemon makes its client effectively root on the host,
    # including access to the signing key. Refuse it unconditionally.
    info = subprocess.run(
        ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    check(
        info.returncode == 0 and info.stdout.strip() == b"true",
        "Аттестатор на узле требует настроенный Podman без прав root",
    )
    if cfg.package_id:
        outcome = execute_matrix(cfg, cfg.package_id)
        print(json.dumps(outcome))
        if not outcome["allRequiredTargetsVerified"]:
            raise RuntimeError("Матрица Runtime заполнена не полностью")
        return
    check(
        cfg.tls_cert and cfg.tls_key and cfg.client_ca,
        "Службе требуются серверный и клиентский сертификаты mTLS",
    )
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if (
                self.path != "/v1/attest"
                or int(self.headers.get("Content-Length", "0")) > 512
            ):
                self.send_error(404)
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                check(set(body) == {"packageId"}, "Допускается только параметр packageId")
                if not lock.acquire(blocking=False):
                    self.send_error(429, "attestor busy")
                    return
                try:
                    result = execute_matrix(cfg, body["packageId"])
                finally:
                    lock.release()
                raw = json.dumps(result).encode()
                self.send_response(201 if result["allRequiredTargetsVerified"] else 409)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except ExternalOutage:
                self.send_error(
                    503, "Результат неопределён: внешний официальный провайдер недоступен"
                )
            except Exception as exc:
                self.send_error(409, redact_diagnostics(str(exc))[:160])

        def log_message(self, *args):
            pass

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cfg.client_ca)
    ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    host, port = cfg.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Ошибка аттестатора:", redact_diagnostics(str(e)), file=sys.stderr)
        sys.exit(1)
