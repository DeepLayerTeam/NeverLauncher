#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
CHECK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,95}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_OS = {"linux", "windows", "macos"}
ALLOWED_ARCH = {"x86_64", "universal"}
ARTIFACT_ROLES = ("package", "launcher", "guard", "manifest", "allowlist")
COMMON_CHECKS = {
    "rustFormat",
    "guardUnitTests",
    "guardIntegrationTest",
    "clippy",
    "releaseBuild",
    "packageManifestVerified",
    "artifactHashesVerified",
    "authenticatedIpcV4",
    "runtimePolicyEnforced",
    "releasePackageBuilt",
    "guardRelease0139",
    "GuardRelease0140",
}
OS_CHECK = {
    "linux": "linuxProductionGate",
    "windows": "windowsProductionGate",
    "macos": "macosProductionGate",
}
EXPECTED_PLATFORM = {
    "linux": "linux-amd64",
    "windows": "windows-amd64",
    "macos": "macos-universal",
}
GENERIC_LIMITATION = "ci-certifies-build-test-artifacts-not-vendor-signing-credentials"


def die(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"{path}: недопустимый JSON: {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        die(f"Отсутствует артефакт: {path}")
    size = path.stat().st_size
    if size <= 0:
        die(f"Артефакт пуст: {path}")
    return {"name": path.name, "size": size, "sha256": sha256_file(path)}


def load_targets(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion",
        "productVersion",
        "targets",
    }:
        die("Целевые данные Guard CI могут содержать только schemaVersion/productVersion/targets")
    if (
        payload.get("schemaVersion") != "1.0"
        or payload.get("productVersion") != PRODUCT_VERSION
    ):
        die(
            f"Целевые данные Guard CI должны использовать schemaVersion=1.0 и productVersion={PRODUCT_VERSION}"
        )
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows:
        die("Целевые данные Guard CI должны содержать непустой массив targets")
    allowed = {
        "id",
        "runner",
        "os",
        "arch",
        "required",
        "ciSigningMode",
        "requiredChecks",
    }
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    required_os: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            die(f"Целевая конфигурация №{index + 1} должна быть объектом")
        unknown = sorted(set(raw) - allowed)
        if unknown:
            die(f"Целевая конфигурация №{index + 1}: неизвестные поля: {', '.join(unknown)}")
        target_id = str(raw.get("id", "")).strip()
        os_name = str(raw.get("os", "")).strip().lower()
        arch = str(raw.get("arch", "")).strip().lower()
        runner = str(raw.get("runner", "")).strip()
        signing = str(raw.get("ciSigningMode", "")).strip()
        required = raw.get("required")
        checks = raw.get("requiredChecks")
        if not ID_RE.fullmatch(target_id) or target_id in seen:
            die(f"target #{index + 1}: недопустимый или повторяющийся идентификатор {target_id!r}")
        seen.add(target_id)
        if os_name not in ALLOWED_OS or arch not in ALLOWED_ARCH:
            die(f"{target_id}: неподдерживаемая ОС или архитектура {os_name}/{arch}")
        if os_name != "macos" and arch != "x86_64":
            die(f"{target_id}: {os_name} Сейчас для сертификации требуется x86_64")
        if os_name == "macos" and arch != "universal":
            die(f"{target_id}: сборка macOS для сертификации должна быть универсальной")
        if not runner or not signing or not isinstance(required, bool):
            die(f"{target_id}: обязательны runner/ciSigningMode/required")
        if (
            not isinstance(checks, list)
            or not checks
            or any(not isinstance(v, str) or not CHECK_RE.fullmatch(v) for v in checks)
        ):
            die(f"{target_id}: requiredChecks должен быть непустым массивом строк")
        if len(checks) != len(set(checks)):
            die(f"{target_id}: повторяющиеся requiredChecks")
        missing = sorted((COMMON_CHECKS | {OS_CHECK[os_name]}) - set(checks))
        if missing:
            die(f"{target_id}: ослаблена базовая защита Guard, отсутствует {', '.join(missing)}")
        if required:
            required_os.add(os_name)
        normalized.append(
            {
                "id": target_id,
                "runner": runner,
                "os": os_name,
                "arch": arch,
                "required": required,
                "ciSigningMode": signing,
                "requiredChecks": checks,
            }
        )
    if required_os != ALLOWED_OS:
        die(
            f"Обязательное покрытие Guard CI: linux/windows/macos; получено {sorted(required_os)}"
        )
    return {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "targets": normalized,
    }


def expected_artifact_names(os_name: str) -> dict[str, str]:
    if os_name == "linux":
        return {
            "package": f"launcher-desktop-{PRODUCT_VERSION}-linux-amd64.zip",
            "launcher": "launcher-desktop-linux-amd64",
            "guard": "guard-linux-amd64",
            "manifest": "LINUX_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_LINUX.json",
        }
    if os_name == "windows":
        return {
            "package": f"launcher-desktop-{PRODUCT_VERSION}-windows-amd64.zip",
            "launcher": "launcher-desktop-windows-amd64.exe",
            "guard": "guard-windows-amd64.exe",
            "manifest": "WINDOWS_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_WINDOWS.json",
        }
    if os_name == "macos":
        return {
            "package": f"launcher-desktop-{PRODUCT_VERSION}-macos-universal.zip",
            "launcher": "launcher-desktop-macos-universal",
            "guard": "guard-macos-universal",
            "manifest": "MACOS_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_MACOS.json",
        }
    die(f"Неподдерживаемая ОС Guard CI: {os_name}")


def manifest_hashes(os_name: str, manifest: dict[str, Any]) -> tuple[str, str, str]:
    expected_platform = EXPECTED_PLATFORM[os_name]
    if (
        manifest.get("schemaVersion") != "1.0"
        or manifest.get("productVersion") != PRODUCT_VERSION
    ):
        die("Обнаружено несоответствие версии или схемы манифеста пакета")
    if manifest.get("platform") != expected_platform:
        die(
            f"Платформа манифеста пакета не совпадает; ожидалась {expected_platform!r}, получено {manifest.get('platform')!r}"
        )
    if int(manifest.get("GuardProtocolVersion", 0)) != 4:
        die("Манифест пакета не требует протокол Guard v4")
    if os_name in {"linux", "windows"}:
        rows = manifest.get("artifacts")
        if not isinstance(rows, list) or len(rows) < 2:
            die("Отсутствуют package manifest artifacts")
        by_name = {
            str(row.get("name", "")): row for row in rows if isinstance(row, dict)
        }
        if os_name == "linux":
            desktop = by_name.get("launcher-desktop")
            guard = by_name.get("guard")
        else:
            guard = by_name.get("guard.exe")
            desktop = next(
                (
                    row
                    for name, row in by_name.items()
                    if name.startswith("launcher-desktop-") and name.endswith(".exe")
                ),
                None,
            )
        if not isinstance(desktop, dict) or not isinstance(guard, dict):
            die("В манифесте пакета отсутствуют записи Desktop/Guard")
        return (
            str(desktop.get("sha256", "")).lower(),
            str(guard.get("sha256", "")).lower(),
            expected_platform,
        )
    return (
        str(manifest.get("desktopSha256", "")).lower(),
        str(manifest.get("guardSha256", "")).lower(),
        expected_platform,
    )


def verify_package_metadata(
    target: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    manifest_path: Path,
    allowlist_path: Path,
) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        die("Манифест пакета должен быть объектом")
    desktop_hash, guard_hash, package_platform = manifest_hashes(target["os"], manifest)
    if (
        desktop_hash != artifacts["launcher"]["sha256"]
        or guard_hash != artifacts["guard"]["sha256"]
    ):
        die("package manifest SHA-256: не совпадает с emitted Desktop/Guard artifacts")
    allowlist = load_json(allowlist_path)
    expected_policy_platform = {
        "linux": "linux",
        "windows": "windows",
        "macos": "macos",
    }[target["os"]]
    signing_mode = ""
    if isinstance(allowlist, dict) and allowlist.get("schemaVersion") == "2.0":
        release = allowlist.get("releases", {}).get(PRODUCT_VERSION, {})
        if not isinstance(release, dict) or release.get("protocolVersion") != 4:
            die(
                "Политика выпуска Guard v2 не содержит актуальные productVersion/protocolVersion"
            )
        platform_policy = release.get("platforms", {}).get(expected_policy_platform, {})
        if not isinstance(platform_policy, dict):
            die("Политика выпуска Guard v2 не содержит ожидаемую платформу")
        signing_mode = str(platform_policy.get("signingMode", ""))
        pairs = platform_policy.get("artifacts", [])
        exact_pair = any(
            isinstance(row, dict)
            and str(row.get("guardSha256", "")).lower() == guard_hash
            and str(row.get("launcherSha256", "")).lower() == desktop_hash
            for row in pairs
        )
        if not exact_pair:
            die(
                "Политика выпуска Guard v2 не привязана к сформированной паре артефактов Desktop/Guard"
            )
    elif isinstance(allowlist, dict) and isinstance(
        allowlist.get(PRODUCT_VERSION), dict
    ):
        row = allowlist[PRODUCT_VERSION]
        guard_values = [str(v).lower() for v in row.get("guardSha256", [])]
        launcher_values = [str(v).lower() for v in row.get("launcherSha256", [])]
        if guard_hash not in guard_values or desktop_hash not in launcher_values:
            die("Список разрешённых выпусков Guard не привязан к хешам Desktop/Guard")
        signing_mode = "legacy"
    else:
        die("Список разрешённых выпусков Guard не содержит актуальную productVersion")
    for digest in (desktop_hash, guard_hash):
        if not SHA256_RE.fullmatch(digest):
            die("Некорректный SHA-256 в метаданных пакета")
    return {
        "packagePlatform": package_platform,
        "guardProtocolVersion": 4,
        "releasePolicySchema": "2.0"
        if allowlist.get("schemaVersion") == "2.0"
        else "1.0",
        "releaseSigningMode": signing_mode,
    }


def verify_result(
    target: dict[str, Any],
    result: dict[str, Any],
    *,
    commit: str,
    run_id: str,
    repository: str,
) -> list[str]:
    errors: list[str] = []
    expected = {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "targetId": target["id"],
        "runner": target["runner"],
        "os": target["os"],
        "arch": target["arch"],
        "commit": commit,
        "runId": run_id,
        "repository": repository,
    }
    for key, value in expected.items():
        if str(result.get(key, "")) != str(value):
            errors.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    if result.get("status") != "passed" or result.get("exitCode") != 0:
        errors.append("Значения status/exitCode должны быть passed/0")
    if not str(result.get("runtimeArch", "")).strip():
        errors.append("Отсутствует runtimeArch")
    checks = result.get("checks")
    if not isinstance(checks, dict):
        errors.append("Отсутствуют проверки")
    else:
        for check in target["requiredChecks"]:
            if checks.get(check) is not True:
                errors.append(f"обязательная проверка {check} не прошла")
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACT_ROLES):
        errors.append(
            "Артефакты должны содержать только package/launcher/guard/manifest/allowlist"
        )
    else:
        names: set[str] = set()
        for role in ARTIFACT_ROLES:
            item = artifacts.get(role)
            if not isinstance(item, dict):
                errors.append(f"артефакт {role} недействителен")
                continue
            name = str(item.get("name", ""))
            digest = str(item.get("sha256", "")).lower()
            size = item.get("size")
            if not name or Path(name).name != name or name in names:
                errors.append(f"Артефакт {role} имеет небезопасное или повторяющееся имя")
            names.add(name)
            if (
                not SHA256_RE.fullmatch(digest)
                or not isinstance(size, int)
                or size <= 0
            ):
                errors.append(f"Артефакт {role} имеет недопустимый хеш или размер")
    claims = result.get("claims")
    if not isinstance(claims, dict):
        errors.append("Отсутствуют утверждения проверки")
    else:
        if (
            claims.get("guardProtocolVersion") != 4
            or claims.get("releaseCertification") != PRODUCT_VERSION
            or claims.get("releasePolicySchema") != "2.0"
        ):
            errors.append("Утверждения о сертификации протокола или выпуска Guard не совпадают")
        if claims.get("packagePlatform") != EXPECTED_PLATFORM[target["os"]]:
            errors.append("Утверждение packagePlatform не совпадает")
        if claims.get("ciSigningMode") != target["ciSigningMode"]:
            errors.append("Утверждение ciSigningMode не совпадает")
        if claims.get("vendorSigningProvenance") != "not-certified-by-ci":
            errors.append("Нельзя указывать неподтверждённое происхождение подписи поставщика")
        if (
            claims.get("packageManifestBound") is not True
            or claims.get("artifactSetComplete") is not True
        ):
            errors.append("Утверждения о манифесте артефакта или пакета должны соответствовать действительности")
    limitations = result.get("limitations")
    if not isinstance(limitations, list) or GENERIC_LIMITATION not in limitations:
        errors.append("Не указано ограничение CI, связанное с учётными данными подписи поставщика")
    return errors


def command_validate(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(
        f"Целевые среды Guard CI проверены: {len(payload['targets'])} целевых сред для {PRODUCT_VERSION}"
    )
    return 0


def command_plan(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(json.dumps({"include": payload["targets"]}, separators=(",", ":")))
    return 0


def command_result(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)["targets"]
    target = next((row for row in targets if row["id"] == args.target_id), None)
    if target is None:
        die(f"Неизвестная цель Guard CI: {args.target_id}")
    if args.signing_mode != target["ciSigningMode"]:
        die(f"{args.target_id}: signing mode: обнаружено несоответствие")
    paths = {
        "package": args.package,
        "launcher": args.launcher,
        "guard": args.guard,
        "manifest": args.manifest,
        "allowlist": args.allowlist,
    }
    expected_names = expected_artifact_names(target["os"])
    for role, path in paths.items():
        if path.name != expected_names[role]:
            die(
                f"{target['id']}: неканоническое значение {role} имя артефакта: ожидалось {expected_names[role]!r}, получено {path.name!r}"
            )
    artifacts = {role: artifact_record(path) for role, path in paths.items()}
    meta = verify_package_metadata(target, artifacts, args.manifest, args.allowlist)
    checks = {name: True for name in target["requiredChecks"]}
    result = {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "targetId": target["id"],
        "runner": target["runner"],
        "os": target["os"],
        "arch": target["arch"],
        "runtimeArch": platform.machine().lower() or "unknown",
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "status": "passed",
        "exitCode": 0,
        "checks": checks,
        "artifacts": artifacts,
        "claims": {
            "guardProtocolVersion": meta["guardProtocolVersion"],
            "releaseCertification": PRODUCT_VERSION,
            "releasePolicySchema": meta["releasePolicySchema"],
            "releaseSigningMode": meta["releaseSigningMode"],
            "releaseIdentityAuthenticated": True,
            "packagePlatform": meta["packagePlatform"],
            "ciSigningMode": args.signing_mode,
            "vendorSigningProvenance": "not-certified-by-ci",
            "packageManifestBound": True,
            "artifactSetComplete": True,
        },
        "limitations": [GENERIC_LIMITATION],
    }
    errors = verify_result(
        target,
        result,
        commit=args.commit,
        run_id=args.run_id,
        repository=args.repository,
    )
    if errors:
        die("Сформированный результат Guard CI не прошёл самопроверку: " + "; ".join(errors))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Проверка Guard CI пройдена: {target['id']} -> {args.output}")
    return 0


def discover_results(
    root: Path,
) -> tuple[dict[str, tuple[Path, dict[str, Any]]], list[str]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    errors: list[str] = []
    if not root.exists():
        return found, [f"Корневой каталог результатов отсутствует: {root}"]
    for path in sorted(root.rglob("guard-ci-result.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: недопустимый JSON результата: {exc}")
            continue
        target_id = (
            str(payload.get("targetId", "")).strip()
            if isinstance(payload, dict)
            else ""
        )
        if not ID_RE.fullmatch(target_id):
            errors.append(f"{path}: недопустимый targetId")
            continue
        if target_id in found:
            errors.append(f"Повторяющийся результат Guard CI для {target_id}")
            continue
        found[target_id] = (path, payload)
    return found, errors


def render_markdown(
    targets: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    commit: str,
    run_id: str,
    repository: str,
) -> str:
    lines = [
        f"# Launcher {PRODUCT_VERSION} — сертификация Guard в CI",
        "",
        "| Цель | Исполнитель | Платформа | Архитектура Runtime | Статус | SHA-256 пакета |",
        "|---|---|---|---|---|---|",
    ]
    for target in targets:
        record = records[target["id"]]
        package = (
            record.get("artifacts", {}).get("package", {})
            if isinstance(record.get("artifacts"), dict)
            else {}
        )
        digest = str(package.get("sha256", "—"))
        lines.append(
            f"| `{target['id']}` | `{target['runner']}` | `{target['os']}/{target['arch']}` | `{record.get('runtimeArch', '—')}` | **{record.get('status', 'missing').upper()}** | `{digest}` |"
        )
    lines += [
        "",
        f"Коммит: `{commit}`  ",
        f"Запуск GitHub Actions: `{run_id}`  ",
        f"Репозиторий: `{repository}`",
        "",
        "Сертификация привязывает точные хеши собранного в CI пакета, Desktop, Guard, манифеста и разрешённого списка выпуска для Linux, Windows и macOS. Она намеренно не подтверждает наличие или происхождение производственных учётных данных Authenticode/Developer ID.",
        "",
    ]
    return "\n".join(lines)


def command_aggregate(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)["targets"]
    results, errors = discover_results(args.results_root)
    expected_ids = {row["id"] for row in targets}
    for extra in sorted(set(results) - expected_ids):
        errors.append(f"Неожиданный результат Guard CI: {extra}")
    records: dict[str, dict[str, Any]] = {}
    artifact_names: set[str] = set()
    for target in targets:
        found = results.get(target["id"])
        if found is None:
            if target["required"]:
                errors.append(f"Отсутствует обязательный результат Guard CI: {target['id']}")
            records[target["id"]] = {
                "targetId": target["id"],
                "status": "missing",
                "checks": {},
            }
            continue
        path, result = found
        result_errors = verify_result(
            target,
            result,
            commit=args.commit,
            run_id=args.run_id,
            repository=args.repository,
        )
        record = dict(result)
        record["evidenceSha256"] = sha256_file(path)
        if isinstance(result.get("artifacts"), dict):
            for role in ARTIFACT_ROLES:
                item = result["artifacts"].get(role, {})
                name = str(item.get("name", "")) if isinstance(item, dict) else ""
                if name in artifact_names:
                    result_errors.append(
                        f"Совпадают имена файлов артефактов разных платформ: {name}"
                    )
                artifact_names.add(name)
        if result_errors:
            record["status"] = "invalid"
            errors.extend(f"{target['id']}: {item}" for item in result_errors)
        records[target["id"]] = record
    required_pass = all(
        records[row["id"]].get("status") == "passed"
        for row in targets
        if row["required"]
    )
    status = "passed" if not errors and required_pass else "failed"
    matrix = {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "status": status,
        "targets": [records[row["id"]] for row in targets],
        "errors": errors,
        "generatorRuntime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "matrix.md").write_text(
        render_markdown(targets, records, args.commit, args.run_id, args.repository),
        encoding="utf-8",
    )
    if errors:
        for item in errors:
            print(f"Матрица Guard CI: {item}")
        return 1
    print(
        f"Матрица Guard CI PASS: {len(targets)} целей, коммит={args.commit}, запуск={args.run_id}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Кроссплатформенная CI-матрица сертификации Guard Launcher"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_validate)
    p = sub.add_parser("plan")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_plan)
    p = sub.add_parser("result")
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--launcher", type=Path, required=True)
    p.add_argument("--guard", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--allowlist", type=Path, required=True)
    p.add_argument("--signing-mode", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=command_result)
    p = sub.add_parser("aggregate")
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--results-root", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--repository", required=True)
    p.set_defaults(func=command_aggregate)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
