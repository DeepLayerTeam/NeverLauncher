#!/usr/bin/env python3
"""Опубликовать уже подписанный GA-пакет Launcher в GitHub Releases.

При ошибке блокировать до записи, сначала создать черновик, повторно загрузить *каждый* ресурс
выпуска и лишь затем открыть проверенный черновик публично. Учётные данные публикации GitHub никогда
не используются на предыдущих этапах сборки/GA.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile, BadZipFile

from release_policy import policy, parsed

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ga"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from verified_targets import TARGETS, checks_for, approval_data, paths, Blocked, verify as verify_exact_ga
from security_capabilities_0431 import checks as security_checks, verify_all as verify_security
from package_security_0431 import evidence_files as security_evidence_files
from package_full_evidence_04315 import (ARCHIVE_NAME as FULL_GA_ARCHIVE,
                                         extract_verified as extract_full_ga)
from verified_support_0440 import check_file as verify_support_file, NAME as SUPPORT_REPORT_0440
from required_jobs_0363 import declared_jobs

PRODUCTION_WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github/workflows/production-release-candidate.yml"
)

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RECEIPT = "GA_VERIFIED_TARGETS.json"
REHEARSAL = "RELEASE_REHEARSAL_0365.json"
DRYRUN_SCHEMA = "launcher.release.publication-dry-run.v1"


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Blocked(why)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def json_object(path: Path) -> dict:
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= 4 * 1024 * 1024,
        "Свидетельство JSON отсутствует или небезопасно: " + str(path),
    )

    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "duplicate field: " + k)
            result[k] = v
        return result

    data = json.loads(path.read_bytes(), object_pairs_hook=unique)
    require(isinstance(data, dict), "Корень свидетельства должен быть объектом JSON")
    return data


def file_set(bundle: Path) -> dict[str, str]:
    require(
        bundle.is_dir() and not bundle.is_symlink(), "Отсутствует каталог финального выпуска"
    )
    manifest = json_object(bundle / "RELEASE_MANIFEST.json")
    version = manifest.get("version")
    require(
        isinstance(version, str) and policy(version).ga_mode == "signed-ga-v2",
        "Публиковать можно только текущие стабильные подписанные выпуски, прошедшие GA",
    )
    require(
        tuple(parsed(version)[0]) >= (0, 37, 0), "Для публикации требуется версия 0.37.0 или новее"
    )
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    expected = {}
    for row in sums.splitlines():
        require(bool(row), "empty line in SHA256SUMS")
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)", row)
        require(match is not None, "malformed or unsafe SHA256SUMS entry")
        digest, name = match.groups()
        require(
            name not in expected and name not in ("SHA256SUMS", "SHA256SUMS.sig"),
            "duplicate/self-reference in SHA256SUMS",
        )
        expected[name] = digest
    require(len(expected) >= 20, "В выпуске недостаточно подписанных артефактов")
    present = set()
    for p in bundle.iterdir():
        require(
            p.is_file() and not p.is_symlink(),
            "Выпуск содержит не обычный файл: " + p.name,
        )
        present.add(p.name)
    require(
        present == set(expected) | {"SHA256SUMS", "SHA256SUMS.sig"},
        "В выпуске отсутствует файл, обнаружен лишний или неподписанный артефакт",
    )
    for name, digest in expected.items():
        require(sha(bundle / name) == digest, "Контрольная сумма подписанного артефакта не совпадает: " + name)
    for extra in ("SHA256SUMS", "SHA256SUMS.sig"):
        require(
            (bundle / extra).stat().st_size > 0, "Отсутствуют подпись выпуска или контрольные суммы"
        )
    expected["SHA256SUMS"] = sha(bundle / "SHA256SUMS")
    expected["SHA256SUMS.sig"] = sha(bundle / "SHA256SUMS.sig")
    return expected


def verify_ci(report: dict, version: str, commit: str, run_id: int, attempt: int):
    require(
        report.get("schemaVersion") == 1
        and report.get("status") == "passed"
        and report.get("gateJob") == "required-production-ci"
        and report.get("productVersion") == version
        and report.get("sourceCommit") == commit
        and report.get("runId") == run_id
        and report.get("runAttempt") == attempt
        and report.get("missingJobs") == []
        and report.get("unexpectedJobs") == []
        and report.get("nonSuccessJobs") == {},
        "Отчёт рабочего CI устарел или неполон",
    )
    jobs = report.get("jobResults")
    expected = declared_jobs(str(PRODUCTION_WORKFLOW)) - {
        "required-production-ci",
        "publish-release",
    }
    require(
        isinstance(jobs, dict)
        and set(jobs) == expected
        and all(value == "success" for value in jobs.values())
        and "release-bundle" in jobs
        and "base-ci" in jobs,
        "Обязательные задания CI отсутствуют, неожиданны, пропущены или завершились ошибкой",
    )


def verify_security_archive(
    bundle: Path, approval: dict, run_id: int, attempt: int, *, now=None
) -> None:
    """Перед публикацией повторно проверять исходные наблюдения, защищённые SHA256SUMS."""
    archive_path = bundle / "SECURITY_CAPABILITY_EVIDENCE_0431.zip"
    require(
        archive_path.is_file() and not archive_path.is_symlink()
        and 0 < archive_path.stat().st_size <= 256 * 1024 * 1024,
        "Подписанный архив свидетельств безопасности отсутствует или небезопасен",
    )
    with tempfile.TemporaryDirectory(prefix="nl-security-publish-") as folder:
        extracted = Path(folder)
        with ZipFile(archive_path, "r") as archive:
            expected_names = set(security_evidence_files(approval["version"]))
            members = archive.infolist()
            require(
                len(members) == len(expected_names)
                and {item.filename for item in members} == expected_names
                and all(
                    not item.is_dir() and ((item.external_attr >> 16) & 0o170000) != 0o120000
                    and 0 < item.file_size <= 32 * 1024 * 1024
                    for item in members
                ),
                "Архив безопасности содержит отсутствующие, лишние, символьные или слишком большие свидетельства",
            )
            for member in members:
                # Имена файлов берутся только из фиксированного списка проверяющего; произвольные пути и archive.extract()
                # не используются.
                path = extracted / member.filename
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as stream:
                    data = stream.read(32 * 1024 * 1024 + 1)
                require(len(data) == member.file_size, "Неполные подтверждения безопасности")
                path.write_bytes(data)
        verify_security(
            extracted, approval, run_id=str(run_id), run_attempt=attempt, now=now
        )

def verify_ga(
    bundle: Path, public_key: Path, version: str, commit: str, run_id: int, attempt: int
) -> str:
    receipt = json_object(bundle / RECEIPT)
    rehearsal = json_object(bundle / REHEARSAL)
    require(
        receipt.get("schemaVersion") == policy(version).receipt_schema
        and receipt.get("status") == "approved-for-release-signing"
        and receipt.get("version") == version
        and receipt.get("commit") == commit,
        "Источник или версия квитанции GA не совпадают",
    )
    require(
        rehearsal.get("schemaVersion") == "launcher.release.rehearsal.v1"
        and rehearsal.get("status") == "package-and-ga-verified"
        and rehearsal.get("version") == version
        and rehearsal.get("commit") == commit
        and rehearsal.get("runId") == str(run_id)
        and rehearsal.get("runAttempt") == str(attempt),
        "rehearsal from another CI run/attempt",
    )
    with tempfile.TemporaryDirectory(prefix="nl-ga-publish-") as folder:
        evidence = Path(folder)
        shutil.copyfile(bundle / "GA_TARGET_APPROVAL.json", evidence / "approval.json")
        shutil.copyfile(bundle / "GA_TARGET_APPROVAL.sig", evidence / "approval.sig")
        approval, raw, key = approval_data(evidence, public_key, version, commit)
    require(
        sha(bundle / "GA_TARGET_APPROVAL.json")
        == receipt.get("approvalSha256")
        == rehearsal.get("gaApprovalSha256"),
        "Контрольная сумма подписанного одобрения GA не совпадает",
    )
    require(
        hashlib.sha256(bytes.fromhex(key.decode())).hexdigest()
        == receipt.get("operatorPublicKeySha256"),
        "Идентификатор оператора в квитанции GA не совпадает",
    )
    targets = approval.get("targets")
    require(
        isinstance(targets, list)
        and len(targets) == 6
        and all(isinstance(r, dict) for r in targets)
        and {r.get("target") for r in targets} == set(TARGETS),
        "Подпись GA не разрешает ровно шесть целевых платформ",
    )
    certified = receipt.get("targets")
    rehearsed = rehearsal.get("targets")
    require(
        isinstance(certified, list)
        and len(certified) == 6
        and all(isinstance(r, dict) for r in certified)
        and isinstance(rehearsed, list)
        and len(rehearsed) == 6
        and all(isinstance(r, dict) for r in rehearsed),
        "Отсутствуют результаты GA или пробного прогона для шести платформ",
    )
    require(
        {r.get("target") for r in rehearsed} == set(TARGETS)
        and {r.get("target") for r in certified} == set(TARGETS),
        "В квитанциях GA и пробного прогона платформа отсутствует или повторяется",
    )
    for target in TARGETS:
        signed_row = next(r for r in targets if r["target"] == target)
        certified_row = next(r for r in certified if r["target"] == target)
        rehearsed_row = next(r for r in rehearsed if r["target"] == target)
        binary, package = paths(version, target)
        require(
            signed_row.get("status") == "certified"
            and isinstance(signed_row.get("checks"), dict)
            and set(signed_row["checks"]) == set(checks_for(version))
            and certified_row.get("checksPassed") == len(checks_for(version))
            and (not security_checks(version)
                 or certified_row.get("securityCapabilitiesVerified") == list(security_checks(version)))
            and rehearsed_row.get("binary") == binary
            and rehearsed_row.get("package") == package,
            target + ": независимые проверки GA не завершены",
        )
        for field, file in [("binarySha256", binary), ("packageSha256", package)]:
            digest = sha(bundle / file)
            require(
                digest
                == signed_row.get(field)
                == certified_row.get(field)
                == rehearsed_row.get(field),
                target + ": публикуемый файл не получил независимого разрешения: " + file,
            )
    if security_checks(version):
        verify_security_archive(bundle, approval, run_id, attempt)
    # Начиная с 0.43.15: восстановите ПОЛНОЕ дерево доказательств из байтов финального выпуска, защищённого
    # SHA256SUMS, и независимо повторите первоначальную GA-приёмку на реальных исполняемых файлах и
    # установщиках. Ни неподписанной квитанции, ни рабочему каталогу исходного сборочного узла доверять
    # нельзя.
    if parsed(version)[0] >= (0, 43, 15):
        with tempfile.TemporaryDirectory(prefix="nl-full-ga-publish-") as folder:
            evidence = Path(folder)
            shutil.copyfile(bundle / "GA_TARGET_APPROVAL.json", evidence / "approval.json")
            shutil.copyfile(bundle / "GA_TARGET_APPROVAL.sig", evidence / "approval.sig")
            extract_full_ga(bundle / FULL_GA_ARCHIVE, evidence, version)
            actual = verify_exact_ga(
                bundle, evidence, public_key, version, commit,
                run_id=str(run_id), run_attempt=attempt,
            )
            require(actual == receipt, "Квитанция GA отличается от независимого полного повторения")
            if parsed(version)[0] >= (0, 44, 0):
                verify_support_file(bundle / SUPPORT_REPORT_0440, actual)
    return receipt["approvalSha256"]


def run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command, text=True, capture_output=True, cwd=cwd, check=False
    )
    require(
        result.returncode == 0,
        "Команда завершилась ошибкой: "
        + " ".join(command[:5])
        + " : "
        + (result.stderr or result.stdout)[-350:],
    )
    return result.stdout


def validate(
    *,
    bundle: Path,
    ci: Path,
    dryrun: Path,
    version: str,
    commit: str,
    run_id: int,
    attempt: int,
    ga_key: Path,
    release_key: Path,
    trust_policy: Path,
    cli: Path,
    trust_state: Path,
) -> dict:
    require(
        HEX40.fullmatch(commit) is not None and run_id > 0 and attempt > 0,
        "Некорректный идентификатор источника или запуска CI",
    )
    require(
        policy(version).ga_mode == "signed-ga-v2" and parsed(version)[0] >= (0, 37, 0),
        "Отсутствует текущая политика выпуска GA",
    )
    manifest = json_object(bundle / "RELEASE_MANIFEST.json")
    require(
        manifest.get("version") == version and manifest.get("sourceCommit") == commit,
        "Версия или коммит манифеста выпуска не совпадают",
    )
    files = file_set(bundle)
    if parsed(version)[0] >= (0, 46, 2):
        # До любых сетевых записей проверяйте не только контрольную сумму внешнего ZIP, но и формат бинарных
        # файлов и хеши вложенных пакетов.
        from delivery_verify_0462 import verify_bundle
        try:
            verify_bundle(bundle, True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise Blocked('Проверка исполняемых файлов поставки 0.46.2+ не пройдена') from exc
    if parsed(version)[0] >= (0, 46, 0):
        # Устаревший CLI до версии 0.46 не может разрешать публикацию. До ЛЮБОЙ записи на GitHub или создания
        # черновика проверяйте независимую эксплуатационную приёмку по доверенным ключам в текущем процессе
        # публикации.
        operator_key = os.environ.get('LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE', '')
        require(bool(operator_key), 'GA версии 0.46.0 ЗАБЛОКИРОВАНА: отсутствует открытый ключ независимого оператора')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'operations'))
        from operations_ga_0460 import verify_public
        try:
            verify_public(bundle, Path(operator_key), release_key)
        except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
            raise Blocked('GA 0.46.0 заблокирована: независимая проверка свидетельств эксплуатации не пройдена') from exc
    if version == '0.53.0':
        # Явно подтвердите допуск ещё до попытки публикации на GitHub. Защищённая среда выпуска предоставляет
        # одобренные исходные пакеты только для чтения и отдельный закреплённый ключ независимого проверяющего.
        from publication_ga_0530 import verify as verify_0530
        base = os.environ.get('NL_GA0530_INBOX','')
        key = os.environ.get('NL_GA0530_VERIFIER_KEY','')
        pin = os.environ.get('NL_GA0530_VERIFIER_PIN','')
        index_pin = os.environ.get('NL_GA0530_INDEX_SHA256','')
        project = os.environ.get('NL_GA0530_PROJECT','')
        require(all((base,key,pin,index_pin,project)),
                'Выпуск 0.53.0 ЗАБЛОКИРОВАН: отсутствуют независимые входные данные полной пользовательской приёмки GA')
        root=Path(base)
        require(root.is_absolute() and root.is_dir(), '0.53.0 GA inbox unavailable')
        try:
            verify_0530(root/'approval.json',root/'approval.sig',Path(key),pin,
                        root/'packages',root/'source-index.json',index_pin,
                        bundle.absolute(),commit,project)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise Blocked('Полная реальная пользовательская приёмка GA 0.53.0 заблокирована: '+str(exc)) from exc
    verify_ci(json_object(ci), version, commit, run_id, attempt)
    approval = verify_ga(bundle, ga_key, version, commit, run_id, attempt)
    dry = json_object(dryrun)
    require(
        dry.get("schemaVersion") == DRYRUN_SCHEMA
        and dry.get("status") == "passed"
        and dry.get("published") is False
        and dry.get("version") == version
        and dry.get("commit") == commit
        and dry.get("runId") == str(run_id)
        and dry.get("runAttempt") == str(attempt)
        and dry.get("filesCopied") == len(files)
        and dry.get("sha256sumsSha256") == files["SHA256SUMS"]
        and dry.get("gaApprovalSha256") == approval,
        "Подписанная пробная публикация отсутствует, устарела или неполна",
    )
    require(
        cli.is_file()
        and not cli.is_symlink()
        and cli.resolve().is_relative_to(bundle.resolve())
        and cli.name in files,
        "Требуется проверка с помощью CLI опубликованного выпуска",
    )
    cli.chmod(0o755)
    # Используйте изолированное состояние доверия: проверка кандидата не должна продвигать доверие
    # промышленного окружения.
    with tempfile.TemporaryDirectory(prefix="nl-0370-trust-") as tmp:
        state = Path(tmp) / "release-trust-state.json"
        if trust_state.is_file():
            shutil.copyfile(trust_state, state)
        run(
            [
                str(cli),
                "release",
                "publish-check",
                str(bundle),
                "--public-key",
                str(release_key),
                "--trust-policy",
                str(trust_policy),
                "--trust-state",
                str(state),
            ]
        )
    return {
        "schemaVersion": "launcher.release.publication.v1",
        "status": "verified",
        "version": version,
        "commit": commit,
        "runId": run_id,
        "runAttempt": attempt,
        "files": files,
        "gaApprovalSha256": approval,
    }


def github(repo: str, args: list[str]) -> str:
    return run(["gh", *args, "--repo", repo])


def publish(repo: str, verified: dict, bundle: Path) -> dict:
    require(REPOSITORY.fullmatch(repo) is not None, "Некорректный репозиторий GitHub")
    require(
        os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        "Токен публикации не настроен",
    )
    version = verified["version"]
    tag = "v" + version
    commit = verified["commit"]
    # При существующем публичном выпуске, черновике или теге завершайте операцию отказом без перезаписи.
    existing = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "tagName"],
        capture_output=True,
        text=True,
    )
    require(
        existing.returncode != 0
        and (
            "Релиз не найден" in existing.stderr.lower()
            or "http 404" in existing.stderr.lower()
            or "not found" in existing.stderr.lower()
        ),
        "Выпуск уже существует или невозможно проверить его отсутствие",
    )
    ref = subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/tags/{tag}"],
        capture_output=True,
        text=True,
    )
    require(
        ref.returncode != 0
        and ("http 404" in ref.stderr.lower() or "not found" in ref.stderr.lower()),
        "Тег уже существует или проверка тега не удалась",
    )
    files = verified["files"]
    # Опечатайте точные проверенные байты до любых сетевых операций. Изменённое после проверки дерево сборки
    # не должно попасть в GA.
    snapshot_context = tempfile.TemporaryDirectory(prefix="nl-publish-sealed-")
    snapshot = Path(snapshot_context.name)
    try:
        for name, digest in files.items():
            source = bundle / name
            require(source.is_file() and not source.is_symlink() and sha(source) == digest,
                    "После проверки GA файл выпуска изменился: " + name)
            shutil.copyfile(source, snapshot / name)
            require(sha(snapshot / name) == digest and sha(source) == digest,
                    "При окончательном подписании данные выпуска изменились: " + name)
    except Exception:
        snapshot_context.cleanup()
        raise
    args = [
        "gh",
        "release",
        "create",
        tag,
        "--repo",
        repo,
        "--target",
        commit,
        "--title",
        "Launcher " + version,
        "--draft",
        "--notes",
        "Проверенный выпуск для шести платформ. Включены побайтовые одобрения GA и подписанный манифест.",
    ]
    try:
        run(args)
        # Загружайте лишь опечатанный снимок с повторно проверенными хешами; неполный выпуск нельзя продвигать.
        for name in sorted(files):
            require(sha(snapshot / name) == files[name], "Опечатанный артефакт изменился: " + name)
            run(["gh", "release", "upload", tag, str(snapshot / name), "--repo", repo])
        with tempfile.TemporaryDirectory(prefix="nl-0370-roundtrip-") as tmp:
            remote = Path(tmp)
            run(
                ["gh", "release", "download", tag, "--repo", repo, "--dir", str(remote)]
            )
            require(
                {p.name for p in remote.iterdir()} == set(files),
                "В черновике публикации отсутствуют файлы или обнаружены неожиданные файлы",
            )
            for name, digest in files.items():
                require(
                    (remote / name).is_file()
                    and not (remote / name).is_symlink()
                    and sha(remote / name) == digest,
                    "Данные удалённого артефакта GitHub не совпадают: " + name,
                )
            if parsed(version)[0] >= (0, 46, 2):
                from delivery_verify_0462 import verify_bundle
                try:
                    verify_bundle(remote, True)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    raise Blocked('Проверка исполняемых файлов удалённого черновика выпуска 0.46.2+ не пройдена') from exc
        # Допуск к публикации требует второй полной проверки выпуска на серверной стороне.
        metadata = json.loads(
            github(
                repo,
                [
                    "release",
                    "view",
                    tag,
                    "--json",
                    "tagName,isDraft,targetCommitish,assets",
                ],
            )
        )
        require(
            metadata.get("tagName") == tag
            and metadata.get("isDraft") is True
            and metadata.get("targetCommitish") == commit
            and isinstance(metadata.get("assets"), list)
            and len(metadata["assets"]) == len(files)
            and {a.get("name") for a in metadata["assets"]} == set(files),
            "Идентификатор или артефакты черновика выпуска не совпадают",
        )
        run(["gh", "release", "edit", tag, "--repo", repo, "--draft=false"])
        final = json.loads(
            github(repo, ["release", "view", tag, "--json", "isDraft,tagName"])
        )
        require(
            final.get("isDraft") is False and final.get("tagName") == tag,
            "GitHub не опубликовал проверенный выпуск",
        )
    except Exception:
        # Намеренно сохраняйте черновик для расследования; не публикуйте неполные файлы.
        raise
    finally:
        snapshot_context.cleanup()
    return {
        "schemaVersion": "launcher.release.publication.v1",
        "status": "published",
        "repository": repo,
        "tag": tag,
        "version": version,
        "commit": commit,
        "runId": verified["runId"],
        "runAttempt": verified["runAttempt"],
        "assetCount": len(files),
        "sha256sumsSha256": files["SHA256SUMS"],
        "gaApprovalSha256": verified["gaApprovalSha256"],
        "verifiedRemoteBytes": True,
        "publishedAtUtc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("verify", "publish"))
    for name in (
        "bundle",
        "ci",
        "dryrun",
        "version",
        "commit",
        "run-id",
        "run-attempt",
        "ga-key",
        "release-key",
        "trust-policy",
        "cli",
        "trust-state",
    ):
        p.add_argument("--" + name, required=True)
    # Для 0.48.0 обязательна независимая приёмка РЕАЛЬНОЙ миграции, подписанная другой закреплённой
    # идентичностью оператора. Нет подписанных данных — нет публикации.
    p.add_argument("--ga0480-evidence-dir", default="")
    p.add_argument("--ga0480-approval", default="")
    p.add_argument("--ga0480-signature", default="")
    p.add_argument("--ga0480-trusted-key", default="")
    p.add_argument("--repository", default="")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    output = Path(a.output)
    output.unlink(missing_ok=True)
    try:
        verified = validate(
            bundle=Path(a.bundle),
            ci=Path(a.ci),
            dryrun=Path(a.dryrun),
            version=a.version,
            commit=a.commit,
            run_id=int(a.run_id),
            attempt=int(a.run_attempt),
            ga_key=Path(a.ga_key),
            release_key=Path(a.release_key),
            trust_policy=Path(a.trust_policy),
            cli=Path(a.cli),
            trust_state=Path(a.trust_state),
        )
        # Небольшие исправления исходников 0.48.x не наследуют промышленную сертификацию прежних исполняемых
        # байтов. Блокируйте публикацию до новой независимой GA-приёмки точных байтов; изменение VERSION не
        # заменяет доказательства миграции, игры, совместимости старых клиентов и подписания.
        if re.fullmatch(r"0\.48\.(?:[1-9][0-9]*)", a.version):
            raise Blocked("0.48.x patch release: требуется fresh, commit-bound independent migration, legacy, game and signed-delivery GA admission; existing 0.48.0 evidence cannot certify new executable bytes")
        if a.version == "0.48.0":
            require(all((a.ga0480_evidence_dir, a.ga0480_approval,
                         a.ga0480_signature, a.ga0480_trusted_key)),
                    "Для версии 0.48.x требуются независимые подписанные свидетельства реальной миграции, игровой проверки и приёмки устаревших версий GA")
            from ga_gate_0480 import gate as ga0480_gate
            evidence_root = Path(a.ga0480_evidence_dir)
            ga0480_gate(evidence_root, Path(a.ga0480_approval),
                        Path(a.ga0480_signature), Path(a.ga0480_trusted_key), a.commit)
            actual_bundle = Path(a.bundle)
            certified_bundle = evidence_root / 'signed'
            require(sha(actual_bundle / 'RELEASE_MANIFEST.json') ==
                    sha(certified_bundle / 'RELEASE_MANIFEST.json'),
                    'Фактический публикуемый пакет 0.48.0 не идентичен независимо одобренному финальному выпуску')
            # Сравнивайте каждый платформенный пакет поставки, а не только объявленную версию. Побайтовое совпадение
            # обязательно до первой записи в сеть.
            from delivery_verify_0462 import verify_bundle
            current = verify_bundle(actual_bundle, True)['targets']
            certified = verify_bundle(certified_bundle, True)['targets']
            require(current == certified, '0.48.0 actual package hashes differ from approved delivery')
        result = (
            publish(a.repository, verified, Path(a.bundle))
            if a.action == "publish"
            else verified
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print("Публикация релиза: " + result["status"])
        return 0
    except (
        Blocked,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        BadZipFile,
    ) as exc:
        print("ПУБЛИКАЦИЯ РЕЛИЗА ЗАБЛОКИРОВАНА: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
