#!/usr/bin/env python3
"""Выполнять *подготовленные байты выпуска*, а не пересборку upstream/Client Factory.

Для запуска нужен изолированный CI-хост с настоящим GUI-рендерером. Отчёт скрипта — наблюдение и
никогда не принимается как стабильная сертификация.
"""

import argparse
import time
from staged_readiness_0343 import StartupObserver, log_health
from staged_matching_0344 import MatchingServer, GameplayObserver
from staged_auth_0347 import (
    run_probe,
    ProviderUnavailable,
    ProviderRejected,
    ProviderMisconfigured,
)
from staged_lifecycle_0349 import run_lifecycle
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "launcher.staged-runtime-run.v1"


def iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_path(value):
    if not value or "\\" in value or "\x00" in value:
        raise ValueError(f"Небезопасный путь в манифесте: {value!r}")
    components = PurePosixPath(value).parts
    if (
        PurePosixPath(value).is_absolute()
        or any(p in (".", "..", "") for p in components)
        or "/".join(components) != value
    ):
        raise ValueError(f"Небезопасный путь в манифесте: {value!r}")
    return value


def request_json(base, relative, bearer, body=None):
    url = base.rstrip("/") + relative
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": "Bearer " + bearer,
            "Content-Type": "application/json",
        },
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError("Неожиданный ответ API")
        return json.load(resp)


def download_exact(base, rel_url, bearer, target, size, expected):
    parsed = urllib.parse.urlsplit(rel_url)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not rel_url.startswith("/api/v1/staged-runs/")
    ):
        raise ValueError("Недоверенный URL загрузки подготовленного пакета")
    if size < 0 or size > (8 << 30) or len(expected) != 64:
        raise ValueError("Некорректные метаданные подготовленного объекта")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError("Целевой файл подготовленного объекта уже существует")
    url = base.rstrip("/") + rel_url
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + bearer}, method="GET"
    )
    temporary = target.with_name(target.name + ".partial")
    total = 0
    digest = hashlib.sha256()
    try:
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            open(temporary, "xb") as stream,
        ):
            if response.status != 200:
                raise ValueError("Ошибка загрузки подготовленного пакета")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise ValueError("Подготовленный объект превышает размер, указанный в подписи")
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if total != size or digest.hexdigest() != expected.lower():
            raise ValueError(
                "Загруженный файл отличается от подписанного снимка (размер / sha256)"
            )
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_checked(cmd, result_file, env):
    # Запрещены выполнение через shell и передача токена Backend клиенту/JVM.
    with open(result_file.with_suffix(".log"), "wb") as log:
        proc = subprocess.run(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=5400,
            check=False,
        )
    if proc.returncode:
        raise RuntimeError(
            f"Команда завершилась с ошибкой, код={proc.returncode}: {cmd[1]} (см. {result_file.with_suffix('.log').name})"
        )
    if not result_file.is_file():
        raise RuntimeError(f"Команда не записала доказательства в {result_file.name}")
    return json.loads(result_file.read_text(encoding="utf-8"))


def run_runtime_observed(cmd, result_file, env, deadline, observer):
    # Реальным жизненным циклом Java/Guard управляет Runtime. Не читайте JSON stdout по каналу во время
    # опроса: большой ограниченный хвост лога может заполнить канал и заблокировать Runtime до завершения.
    from process_group_03410 import group_flags, kill_tree

    stdout_path = result_file.with_suffix(".stdout")
    with (
        open(result_file.with_suffix(".log"), "wb") as diagnostic,
        open(stdout_path, "xb") as stdout_file,
    ):
        proc = subprocess.Popen(
            cmd, stdout=stdout_file, stderr=diagnostic, env=env, **group_flags()
        )
        observer.root_pid = proc.pid
        try:
            until = time.monotonic() + deadline
            while proc.poll() is None:
                if time.monotonic() >= until:
                    raise TimeoutError(
                        "Runtime завис и превысил срок принудительного завершения"
                    )
                observer.tick()
                time.sleep(0.5)
            proc.wait(timeout=10)
        except BaseException:
            # После неудачного запуска не оставляйте бесхозные процессы Minecraft/Guard.
            kill_tree(proc)
            proc.wait(timeout=10)
            raise
    if proc.returncode:
        raise RuntimeError(f"Runtime завершился с ошибкой, код={proc.returncode}")
    if stdout_path.stat().st_size > 4 * 1024 * 1024:
        raise RuntimeError("Структурированный вывод Runtime превысил допустимый объём")
    try:
        output = stdout_path.read_bytes()
        result = json.loads(output)
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("timed_out"), bool)
            or not isinstance(result.get("success"), bool)
        ):
            raise ValueError("Runtime не вернул корректный результат запуска")
        result_file.write_bytes(output)
    finally:
        stdout_path.unlink(missing_ok=True)
    return result


def native_json(cmd, destination, env):
    """Запускать закреплённый Runtime с ограниченным структурированным stdout; без оболочки."""
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=5400,
        check=False,
    )
    if len(completed.stdout) > 4 * 1024 * 1024:
        raise RuntimeError("Вывод нативной проверки компонентов превышает допустимый размер")
    if completed.returncode:
        raise RuntimeError(
            "Нативная проверка компонентов завершилась ошибкой (см. диагностику аттестатора)"
        )
    obj = json.loads(completed.stdout)
    if isinstance(obj, dict) and (obj.get("success") is False or obj.get("error")):
        raise RuntimeError("Нативная проверка компонентов отклонила выбранную предустановку")
    destination.write_text(json.dumps(obj, sort_keys=True, indent=2), encoding="utf-8")
    return obj


def execute(args):
    if not args.backend.startswith("https://") and not args.backend.startswith(
        ("http://127.0.0.1:", "http://localhost:")
    ):
        raise ValueError("Для подготовленного Runtime требуется HTTPS (HTTP на localhost допускается только в тестах)")
    if not args.package_id or "/" in args.package_id:
        raise ValueError("Недопустимый идентификатор пакета")
    if args.admin_token_file:
        token_file = Path(args.admin_token_file)
        if not token_file.is_file() or token_file.is_symlink():
            raise ValueError("Файл токена оператора недоступен")
        if os.name != "nt" and token_file.stat().st_mode & 0o077:
            raise ValueError("Файл токена оператора должен быть доступен только владельцу")
        args.admin_token = token_file.read_text(encoding="utf-8").strip()
    if args.grant_file:
        grant_data = json.loads(Path(args.grant_file).read_text(encoding="utf-8"))
        if grant_data.get("packageId") != args.package_id:
            raise ValueError("Предварительно выданное разрешение привязано к другому подготовленному пакету")
    else:
        if not args.admin_token:
            raise ValueError(
                "За пределами доверенного исполнителя аттестации необходим токен оператора"
            )
        grant_data = request_json(
            args.backend,
            "/api/v1/packages/" + urllib.parse.quote(args.package_id) + "/staged-runs",
            args.admin_token,
            {},
        )["data"]
    grant = grant_data["token"]
    run_id = grant_data["runId"]
    # Не печатайте и не записывайте в отчёты/логи: разрешение может позволить получить подготовленные байты.
    base_path = "/api/v1/staged-runs/" + urllib.parse.quote(args.package_id)
    report = {
        "schemaVersion": SCHEMA,
        "runId": run_id,
        "packageId": args.package_id,
        "manifestSha256": grant_data["manifestSha256"],
        "artifactSha256": grant_data["artifactSha256"],
        "startedAt": iso(),
        "stages": {},
    }
    work = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    from runtime_capabilities_03410 import evaluate, host_identity

    host_java = args.java if args.java != "auto" else (shutil.which("java") or "")
    host = evaluate("headless", host_java)
    (work / "host-capabilities.json").write_text(
        json.dumps(host, indent=2), encoding="utf-8"
    )
    if host["status"] != "ready":
        raise RuntimeError(
            "Заблокировано: возможности системы недоступны: " + "; ".join(host["blockers"])
        )
    stage = work / "payload"
    if stage.exists():
        raise ValueError("Для каждого запуска необходимо создавать новые выходные данные и полезную нагрузку")
    stage.mkdir(mode=0o700)
    client_dir = work / "client"
    delivery_client_dir = work / "delivery-verified-client"
    stage_name = ""
    error = None
    server = None
    subprocess_env = {
        k: v
        for k, v in os.environ.items()
        if not any(
            s in k.upper()
            for s in ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL")
        )
    }
    try:
        stage_name = "manifest-files"
        snapshot = request_json(args.backend, base_path + "/snapshot", grant)
        if any(
            snapshot[k] != report[k]
            for k in ("runId", "packageId", "manifestSha256", "artifactSha256")
        ):
            raise ValueError("Сервер вернул другой идентификатор запуска или снимка")
        pkg = snapshot["package"]
        signed = snapshot["signedManifest"]
        if args.expected_version and pkg.get("version") != args.expected_version:
            raise ValueError("Подготовленный пакет отличается от точной версии сборки исходников")
        # Обработчики выпуска обязаны явно проверять версию; прежние ручные диагностические пробы всё ещё могут
        # использовать этот скрипт для старых подготовленных пакетов.
        import re
        version_match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9.-]+)?", pkg.get("version", ""))
        if not version_match:
            raise ValueError("У подготовленного пакета недопустимая версия")
        requires_exact_version = tuple(map(int, version_match.groups())) >= (0, 43, 14)
        if requires_exact_version and not args.expected_version:
            raise ValueError("Для подготовленного пакета версии 0.43.14+ требуется точная ожидаемая версия исходников")
        if (
            pkg["packageId"] != args.package_id
            or pkg["projectId"] != signed["projectId"]
            or pkg["profileId"] != signed["profileId"]
            or pkg["channel"] != signed["channel"]
            or pkg["version"] != signed["version"]
        ):
            raise ValueError("Идентификатор релиза в подготовленном снимке не совпадает")
        if not pkg["files"]:
            raise ValueError("Подготовленный релиз не содержит файлов клиента для установки")
        manifest_files = {entry["path"]: entry for entry in signed["files"]}
        if len(manifest_files) != len(pkg["files"]):
            raise ValueError("Количество подготовленных файлов не совпадает")
        for item in pkg["files"]:
            name = checked_path(item["path"])
            if name not in manifest_files:
                raise ValueError("Файл отсутствует в подписанном манифесте")
            source = manifest_files[name]
            if (
                item["sha256"].lower() != source["sha256"].lower()
                or item["size"] != source["size"]
            ):
                raise ValueError("Метаданные подготовленного файла не соответствуют подписанному манифесту")
            download_exact(
                args.backend,
                item["url"],
                grant,
                stage / name,
                item["size"],
                item["sha256"],
            )
        package_path = stage / "staged-package-description.json"
        package_path.write_text(
            json.dumps(pkg, sort_keys=True, indent=2), encoding="utf-8"
        )
        signed_manifest_path = stage / "signed-release-manifest.json"
        signed_manifest_path.write_text(
            json.dumps(signed, sort_keys=True, indent=2), encoding="utf-8"
        )
        report["stages"][stage_name] = {
            "status": "passed",
            "detail": f"{len(pkg['files'])} staged files fetched and SHA-256 verified",
        }
        stage_name = "materialization"
        install = work / "install.json"
        cmd = [
            args.cli,
            "client",
            "install",
            "--package",
            str(package_path),
            "--client-dir",
            str(delivery_client_dir),
            "--storage-dir",
            str(work / "empty-storage"),
            "--output",
            str(install),
        ]
        installed = run_checked(cmd, install, subprocess_env)
        if (
            installed.get("status") != "applied-and-verified"
            or installed.get("packageId") != args.package_id
        ):
            raise ValueError("Обновляющий модуль не подтвердил точную версию пакета")
        verify_path = work / "verified.json"
        verified = run_checked(
            [
                args.cli,
                "client",
                "verify",
                "--package",
                str(package_path),
                "--client-dir",
                str(delivery_client_dir),
                "--output",
                str(verify_path),
            ],
            verify_path,
            subprocess_env,
        )
        if verified.get("status") != "valid" or verified.get("verify", {}).get(
            "checkedFiles"
        ) != len(pkg["files"]):
            raise ValueError(
                "Установленный пакет побайтово отличается от подготовленного манифеста"
            )
        # Независимо материализованные байты CLI становятся источником для долговременной транзакции выпуска
        # нативного Runtime. Файлы не загружаются повторно по URL манифеста; в фактическую директорию запуска
        # Minecraft попадают только выбранные проверенные байты.
        catalog = signed.get("componentCatalog")
        selection = args.preset or ""
        if catalog and not selection:
            raise RuntimeError(
                "Для целевой конфигурации матрицы компонентов необходимо выбрать явную подписанную предустановку"
            )
        if not catalog and selection and selection != "default":
            raise RuntimeError(
                "Для пакета без подписанного каталога указан выбор компонентов"
            )
        native_selection = (
            ""
            if catalog
            and selection == "default"
            and not any(p["id"] == "default" for p in catalog.get("presets", []))
            else selection
        )
        adopt = [
            args.runtime,
            "adopt-staged",
            "--manifest",
            str(signed_manifest_path),
            "--pinned-public-key",
            args.pinned_public_key,
            "--source",
            str(delivery_client_dir),
            "--root",
            str(client_dir),
        ]
        if catalog and native_selection:
            adopt.extend(["--preset", native_selection])
        adopted = native_json(adopt, work / "native-adoption.json", subprocess_env)
        if (
            adopted.get("status") != "ready"
            or adopted.get("networkDownloads") != 0
            or not isinstance(adopted.get("importedFiles"), int)
            or adopted["importedFiles"] < 1
        ):
            raise RuntimeError(
                "Принятие Runtime подготовленного пакета не подтверждено как автономная транзакция релиза"
            )
        report["stages"][stage_name] = {
            "status": "passed",
            "detail": "Установка и проверка через CLI, а также автономное транзакционное применение через Runtime прошли успешно",
            "evidenceSha256": sha_file(verify_path),
        }
        # V08: случай матрицы Runtime — реально установленный выбор, а не дополнительная метка запуска с пресетом
        # по умолчанию. Собственный резолвер Runtime фиксирует и проверяет выбранный план до запуска любого
        # процесса Java.
        component_digest = ""
        if catalog:
            verify_component = [
                args.runtime,
                "verify",
                "--manifest",
                str(signed_manifest_path),
                "--pinned-public-key",
                args.pinned_public_key,
                "--root",
                str(client_dir),
            ]
            if native_selection:
                verify_component.extend(["--preset", native_selection])
            checked = native_json(
                verify_component, work / "component-verification.json", subprocess_env
            )
            (work / "component-sync.json").write_bytes(
                (work / "native-adoption.json").read_bytes()
            )
            # CLI — штатный резолвер подписанного каталога для именованных пресетов. Пользовательские варианты +/-
            # обрабатывает подписанный нативный резолвер Runtime; Go CLI пока не поддерживает протокольный синтаксис
            # @custom.
            if not selection.startswith("@custom:v1:"):
                pinned_file = work / "manifest-public-key.hex"
                pinned_file.write_text(args.pinned_public_key, encoding="ascii")
                cmd = [
                    args.cli,
                    "components",
                    "resolve",
                    "--manifest",
                    str(signed_manifest_path),
                    "--public-key",
                    str(pinned_file),
                    "--output",
                    str(work / "component-plan.json"),
                    "--os",
                    host_identity()["os"],
                    "--arch",
                    "aarch64" if host_identity()["arch"] == "arm64" else "x86_64",
                    "--java-major",
                    str(
                        int(
                            signed.get("runtime", {})
                            .get("java", {})
                            .get("recommendedMajorVersion")
                            or signed.get("runtime", {})
                            .get("java", {})
                            .get("majorVersion")
                            or 0
                        )
                    ),
                    "--minecraft",
                    signed.get("minecraft", {}).get("version", ""),
                    "--loader",
                    signed.get("minecraft", {}).get("loader", ""),
                    "--loader-version",
                    signed.get("minecraft", {}).get("loaderVersion", ""),
                ]
                if native_selection:
                    cmd.extend(["--preset", native_selection])
                resolved = run_checked(
                    cmd, work / "component-plan.json", subprocess_env
                )
                if (
                    not resolved.get("signatureVerified")
                    or resolved["plan"]["catalogDigest"] != catalog["digest"]
                ):
                    raise RuntimeError(
                        "Средство разрешения компонентов не подтвердило подписанный каталог"
                    )
                # Сверяйте промышленный резолвер Go с нативным установщиком на фактических подписанных байтах; файлы
                # отдельных платформ могут быть намеренно исключены нативной проверкой.
                planned = {f["path"] for f in resolved["plan"]["files"]}
                native_paths = {f["path"] for f in checked.get("files", [])}
                if not native_paths <= planned:
                    raise RuntimeError(
                        "Нативное средство и Go-средство разрешения каталога расходятся в путях установки"
                    )
            if (
                checked.get("status") != "ready"
                or not checked.get("files")
                or any(f["status"] != "ok" for f in checked["files"])
            ):
                raise RuntimeError("Нативное средство разрешения не проверило все выбранные файлы")
            # Дайджест выбранного плана воспроизводится из неизменяемого манифеста и реально проверенных путей этой
            # целевой платформы.
            by_path = {f["path"]: f["sha256"] for f in signed["files"]}
            chosen_files = sorted(
                (f["path"], by_path[f["path"]]) for f in checked["files"]
            )
            component_digest = hashlib.sha256(
                json.dumps(
                    {
                        "catalogDigest": catalog["digest"],
                        "preset": selection,
                        "selectedFiles": chosen_files,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            selection_report = {
                "schemaVersion": "launcher.component-execution.v1",
                "preset": selection,
                "catalogDigest": catalog["digest"],
                "resolvedComponentPlanSha256": component_digest,
                "syncSha256": sha_file(work / "component-sync.json"),
                "nativeVerifySha256": sha_file(work / "component-verification.json"),
            }
            (work / "component-selection.json").write_text(
                json.dumps(selection_report, sort_keys=True, indent=2), encoding="utf-8"
            )
        elif selection and selection != "default":
            raise RuntimeError(
                "Для пакета без подписанного каталога указан выбор компонентов"
            )

        if args.execution_mode == "headless":
            report["stages"]["materialization"] = {
                "status": "passed",
                "detail": "Рабочая версия CLI установила и проверила каждый подготовленный файл по SHA-256",
                "evidenceSha256": sha_file(verify_path),
            }
            # Headless подтверждает ТОЛЬКО поставку и материализацию пакета. Не представляйте отсутствие графического
            # окружения как несовместимость клиента Minecraft.
            for name in (
                "startup",
                "loader-readiness",
                "authentication",
                "server-readiness",
                "matching-server",
                "gameplay-smoke",
                "update-recovery",
            ):
                report["stages"][name] = {
                    "status": "blocked",
                    "detail": "Целевая конфигурация GUI/Runtime не выполнялась обработчиком без графического интерфейса",
                }
            raise RuntimeError(
                "Заблокировано: тест без интерфейса проверил только манифест, файлы и подготовку данных"
            )
        stage_name = "startup"
        # Запускайте точно установленный выпуск обычным механизмом подписанного манифеста/запуска Runtime.
        # Специальная сертификационная проверка Client Factory отклонила бы дополнительные подготовленные моды и
        # НЕ является штатным игровым путём.
        if (
            len(args.pinned_public_key) != 64
            or signed.get("signature", {}).get("publicKey", "").lower()
            != args.pinned_public_key.lower()
        ):
            raise RuntimeError(
                "Ключ подписи подготовленного релиза не соответствует ключу, закреплённому оператором"
            )
        runtime_java = signed.get("runtime", {}).get("java", {})
        required_major = int(runtime_java.get("majorVersion", 0))
        if (
            signed.get("schemaVersion") in ("2.0", "3.0")
            and int(runtime_java.get("recommendedMajorVersion") or 0) > 0
        ):
            required_major = int(runtime_java["recommendedMajorVersion"])
        if required_major not in (8, 16, 17, 21, 25):
            raise RuntimeError(
                f"Закреплённая версия Java {required_major} для релиза не поддерживается"
            )
        if args.java == "auto":
            from runtime_capabilities_03410 import host_identity

            arch = host_identity()["arch"]
            envarch = "ARM64" if arch == "arm64" else "X64"
            home = os.environ.get(f"JAVA_HOME_{required_major}_{envarch}", "")
            if not home:
                raise RuntimeError(
                    f"В тестовом окружении не установлена Java {required_major}"
                )
            java_name = "java.exe" if sys.platform == "win32" else "java"
            selected_java = str((Path(home) / "bin" / java_name).resolve())
        else:
            selected_java = str(Path(args.java).resolve())
        if not Path(selected_java).is_file():
            raise RuntimeError("Выбранный исполняемый файл Java недоступен")
        if not Path(args.runtime).is_file():
            raise RuntimeError("Исполняемый файл Runtime недоступен")
        runtime_hash = sha_file(args.runtime)
        run_path = work / "runtime-launch.json"
        cmd = [
            args.runtime,
            "launch",
            "--manifest",
            str(signed_manifest_path),
            "--pinned-public-key",
            args.pinned_public_key,
            "--root",
            str(client_dir),
            "--java",
            selected_java,
            "--max-runtime-seconds",
            str(args.runtime_seconds),
        ]
        if catalog and native_selection:
            cmd.extend(["--preset", native_selection])
        loader = signed.get("minecraft", {}).get("loader", "vanilla").lower()
        gui_host = evaluate("gui", selected_java)
        (work / "host-capabilities.json").write_text(
            json.dumps(gui_host, indent=2), encoding="utf-8"
        )
        observer = StartupObserver(
            0,
            client_dir,
            work / "startup-diagnostics",
            loader,
            time.time(),
            selected_java,
        )
        if observer.blocked:
            # Отсутствие X11/OpenGL — ограничение инфраструктуры, а не доказательство несовместимости подготовленного
            # выпуска Minecraft.
            readiness_file = work / "startup-readiness.json"
            readiness_file.write_text(
                json.dumps(observer.evidence(), indent=2), encoding="utf-8"
            )
            report["stages"]["startup"] = {
                "status": "blocked",
                "detail": observer.blocked,
                "evidenceSha256": sha_file(readiness_file),
            }
            report["stages"]["loader-readiness"] = {
                "status": "blocked",
                "detail": "Среда выполнения GUI не запустилась",
            }
            raise RuntimeError("Проверка интерфейса подготовленного пакета заблокирована: " + observer.blocked)
        try:
            launched = run_runtime_observed(
                cmd, run_path, subprocess_env, args.runtime_seconds + 150, observer
            )
            status, detail = observer.conclude(launched)
        finally:
            readiness_file = work / "startup-readiness.json"
            readiness_file.write_text(
                json.dumps(observer.evidence(), indent=2), encoding="utf-8"
            )
        loader_ready, loader_detail = log_health(
            client_dir, observer.runtime_log, loader
        )
        report["stages"]["loader-readiness"] = {
            "status": "passed" if loader_ready else "failed",
            "detail": loader_detail[:2048],
            "evidenceSha256": sha_file(readiness_file),
        }
        report["stages"][stage_name] = {
            "status": status,
            "detail": (
                detail + "; runtime=" + runtime_hash + "; launch=" + sha_file(run_path)
            )[:2048],
            "evidenceSha256": sha_file(readiness_file),
        }
        if status == "failed":
            raise RuntimeError("Запуск Minecraft из подготовленного пакета завершился ошибкой: " + detail)
        if status == "blocked":
            raise RuntimeError("Запуск Minecraft из подготовленного пакета заблокирован: " + detail)
        if not loader_ready:
            raise RuntimeError("Проверка готовности загрузчика подготовленного пакета завершилась ошибкой: " + loader_detail)

        java_version_result = subprocess.run(
            [selected_java, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=subprocess_env,
            timeout=12,
            check=False,
        )
        if java_version_result.returncode or not java_version_result.stdout:
            raise RuntimeError("Не удалось проверить выбранную версию Java")
        java_version = java_version_result.stdout.decode(
            "utf-8", errors="replace"
        ).splitlines()[0]
        # Идентичность выполнения проверяется независимым аттестатором, а не подписывается самим обработчиком.
        runtime_identity = {
            "javaSha256": sha_file(selected_java),
            "javaVersionRaw": java_version,
            "cliSha256": sha_file(args.cli),
            "RuntimeSha256": runtime_hash,
            "installAdapterSha256": hashlib.sha256(
                (sha_file(args.cli) + runtime_hash).encode()
            ).hexdigest(),
            "resolvedPlanSha256": hashlib.sha256(
                json.dumps(
                    dict(
                        {
                            "minecraft": signed.get("minecraft"),
                            "runtime": signed.get("runtime"),
                            "fileHashes": sorted(
                                (f["path"], f["sha256"]) for f in pkg["files"]
                            ),
                        },
                        **(
                            {
                                "componentSelection": selection,
                                "componentPlanSha256": component_digest,
                                "componentCatalogDigest": catalog["digest"],
                            }
                            if catalog
                            else {}
                        ),
                    ),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "guardMode": str(
                signed.get("runtime", {}).get("guard", {}).get("mode") or "disabled"
            ),
            "guardPolicySha256": hashlib.sha256(
                json.dumps(
                    signed.get("runtime", {}).get("guard", {}),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "loader": loader,
            "preset": selection or "default",
        }
        (work / "execution-identity.json").write_text(
            json.dumps(runtime_identity, indent=2), encoding="utf-8"
        )

        # Второй штатный запуск Runtime автоматически подключается к настоящему подходящему серверу; первый
        # отдельно доказывает загрузку главного меню. Дистрибутив сервера закрепляется целиком и не подменяется
        # посторонним Vanilla-сервером, если подписанный клиент использует загрузчик модов.
        mc = signed.get("minecraft", {})
        minecraft = mc.get("version", "")
        loader_version = mc.get("loaderVersion", "")
        if (
            not minecraft
            or not loader
            or loader not in ("vanilla", "fabric", "quilt", "forge", "neoforge")
        ):
            raise ValueError("Неизвестная подписанная версия Minecraft или загрузчика")
        # Идентичность провайдера проверяется реальными учётными данными подписанного аккаунта, а не автономной
        # идентичностью или имитацией. Ошибка транспорта означает НЕОПРЕДЕЛЁННЫЙ результат.
        stage_name = "authentication"
        if not args.auth_mode or not args.credentials_file:
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "Не предоставлены учётные данные настоящего провайдера V07; автономный игровой процесс не подтверждает сертификацию авторизации",
            }
            raise RuntimeError(
                "Для сертификации подготовленного пакета требуется реальная авторизация через провайдера"
            )
        if args.auth_mode == "official" and runtime_identity["guardMode"] != "disabled":
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "official Guard-enabled target requires additional real Guard-policy proof",
            }
            raise RuntimeError(
                "Официальную цель Guard нельзя сертифицировать без независимого доказательства соблюдения политики"
            )
        if args.auth_mode == "custom" and not args.server_bundle:
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "custom authentication requires actual matching ServerBridge bundle",
            }
            raise RuntimeError(
                "Пользовательский провайдер не может использовать автономный сервер проверки vanilla"
            )
        if args.auth_mode == "custom" and not args.guard_denied_credentials_file:
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "custom auth requires live device/Guard trust-denied test identity",
            }
            raise RuntimeError(
                "Доверие устройства и Guard нельзя сертифицировать без отрицательного теста реальной сессии"
            )
        try:
            auth_result, live_credential = run_probe(
                args.auth_mode,
                args.credentials_file,
                args.negative_credentials_file,
                args.backend,
            )
            if args.auth_mode == "custom":
                from staged_auth_0347 import guard_denial_probe

                guard_result = guard_denial_probe(
                    live_credential, args.guard_denied_credentials_file
                )
                auth_result.update(guard_result)
            if args.auth_mode == "custom":
                auth_result["deviceTrust"] = "positive-join-and-live-trust-denial"
                auth_result["guardPolicySha256"] = runtime_identity["guardPolicySha256"]
            else:
                auth_result["deviceTrust"] = "not-applicable-official-provider"
                auth_result["guardPolicySha256"] = runtime_identity["guardPolicySha256"]
            auth_result.update(
                {
                    "runId": run_id,
                    "provider": "live",
                    "status": "passed",
                    "manifestSha256": report["manifestSha256"],
                    "artifactSha256": report["artifactSha256"],
                }
            )
            auth_path = work / "authentication.json"
            auth_path.write_text(
                json.dumps(auth_result, sort_keys=True, indent=2), encoding="utf-8"
            )
            report["stages"][stage_name] = {
                "status": "passed",
                "detail": "live provider join/hasJoined and policy checks verified",
                "evidenceSha256": sha_file(auth_path),
            }
        except ProviderUnavailable:
            report["stages"][stage_name] = {
                "status": "inconclusive",
                "detail": "external authentication provider unavailable (not a successful certification)",
            }
            raise RuntimeError("Результат проверки внешнего провайдера авторизации неоднозначен")
        except ProviderRejected:
            report["stages"][stage_name] = {
                "status": "failed",
                "detail": "real provider or trust policy rejected required authentication proof",
            }
            raise
        except ProviderMisconfigured:
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "live provider prerequisites or policy test account missing",
            }
            raise
        stage_name = "server-readiness"
        server = MatchingServer(
            work,
            selected_java,
            args.cli,
            minecraft,
            loader,
            loader_version,
            args.server_bundle,
            args.server_sha256,
            args.bridge_path,
            args.bridge_sha256,
            args.server_entry,
            args.bridge_version,
            online_mode=args.auth_mode == "official",
        )
        server.prepare()
        server.start(args.server_startup_seconds)
        server_report = work / "server-readiness.json"
        server_report.write_text(
            json.dumps(
                {
                    "runId": run_id,
                    "serverArtifactSha256": server.artifact_sha,
                    "minecraftVersion": minecraft,
                    "loader": loader,
                    "loaderVersion": loader_version,
                    "bridgeRequired": server.requires_bridge,
                    "onlineMode": server.online_mode,
                    "startup": "passed",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        report["stages"][stage_name] = {
            "status": "passed",
            "detail": "exact matching server/version, loader and required bridge booted; RCON world clock available",
            "evidenceSha256": sha_file(server_report),
        }
        stage_name = "matching-server"
        username = live_credential["username"]
        game = GameplayObserver(
            server,
            client_dir,
            selected_java,
            loader,
            username,
            work / "gameplay-diagnostics",
            run_id,
            time.time(),
        )
        joining = work / "runtime-gameplay-launch.json"
        join_cmd = [
            args.runtime,
            "launch",
            "--manifest",
            str(signed_manifest_path),
            "--pinned-public-key",
            args.pinned_public_key,
            "--root",
            str(client_dir),
            "--java",
            selected_java,
            "--username",
            username,
            "--credentials-file",
            args.credentials_file,
            "--matching-server-port",
            str(server.port),
            "--max-runtime-seconds",
            str(args.gameplay_seconds),
        ]
        if catalog and native_selection:
            join_cmd.extend(["--preset", native_selection])
        launch_error = None
        try:
            gameplay_launch = run_runtime_observed(
                join_cmd, joining, subprocess_env, args.gameplay_seconds + 150, game
            )
            if not gameplay_launch.get("timed_out") and not gameplay_launch.get(
                "success"
            ):
                raise RuntimeError(
                    "JVM Minecraft завершилась с ошибкой после запуска совместимого сервера"
                )
        except Exception as exc:
            launch_error = str(exc)
        game_proof = work / "gameplay-smoke.json"
        gameplay_evidence = game.evidence()
        # 0.43.14: наблюдаемая успешная игра необходима, но недостаточна. Проверьте реальные исполняемые файлы
        # выпуска с изменёнными подписанными метаданными и повреждёнными установленными байтами, затем
        # восстановите одноразовый клиент. Не формируйте PASS искусственно, если негативные сценарии нельзя
        # выполнить.
        if not launch_error and game.status == "passed":
            from staged_negative_04314 import execute as adversarial_probes
            negative = adversarial_probes(
                args.runtime, args.cli, signed_manifest_path,
                args.pinned_public_key, package_path, delivery_client_dir,
                pkg["files"], work, subprocess_env,
            )
            negative_path = work / "adversarial-gameplay-04314.json"
            negative_path.write_text(json.dumps(negative, sort_keys=True, indent=2), encoding="utf-8")
            gameplay_evidence["adversarialGameplay04314"] = {
                "status": "passed", "evidenceSha256": sha_file(negative_path),
                "manifestTamperDenied": negative["manifestTamper"]["status"] == "denied",
                "installedFileTamperDeniedAndRestored":
                    negative["installedFileTamper"]["status"] == "denied-and-restored",
            }
        game_proof.write_text(json.dumps(gameplay_evidence, indent=2), encoding="utf-8")
        proof_hash = sha_file(game_proof)
        from staged_matching_0344 import CRASH

        if (
            server.process.poll() is not None
            or game.failure
            or CRASH.search(server.log_text())
            or not log_health(client_dir, None, loader)[0]
        ):
            game.status = "failed"
            game.failure = (
                game.failure
                or "client/server crashed or loader readiness lost after join"
            )
        joined = (
            game.joined
            and game.client_log_seen
            and game.window_pid is not None
            and not game.failure
        )
        report["stages"]["matching-server"] = {
            "status": "blocked" if game.blocked else ("passed" if joined else "failed"),
            "detail": "matching server confirms login and player online; client log and PID-bound GUI observed"
            if joined
            else (
                "matching client/server join not established: "
                + (
                    launch_error
                    or game.failure
                    or getattr(game, "last_error", "no positive join evidence")
                )
            )[:2048],
            "evidenceSha256": proof_hash,
        }
        report["stages"]["gameplay-smoke"] = {
            "status": "blocked"
            if game.blocked
            else (
                "passed" if game.status == "passed" and not launch_error else "failed"
            ),
            "detail": "real GUI movement changed server-side position; world rendered and game ticks advanced"
            if game.status == "passed" and not launch_error
            else (
                "real gameplay state not confirmed: "
                + (
                    launch_error
                    or game.failure
                    or getattr(game, "last_error", "no positive gameplay proof")
                )
            )[:2048],
            "evidenceSha256": proof_hash,
        }
        if launch_error or game.status != "passed":
            raise RuntimeError(
                "Реальная игровая проверка подготовленного клиента завершилась ошибкой: "
                + (
                    launch_error
                    or game.failure
                    or getattr(game, "last_error", "missing required positive signals")
                )
            )
        stage_name = "update-recovery"
        if (
            not args.previous_bundle
            or not args.previous_sha256
            or not args.replacement_java
            or not args.managed_java_manifest
            or not args.managed_java_sha256
        ):
            report["stages"][stage_name] = {
                "status": "blocked",
                "detail": "Для V09 нужны закреплённый на узле предыдущий релиз, другая версия Java и восстановление подписанной Java, управляемой поставкой",
            }
            raise RuntimeError(
                "Отсутствует базовая версия V09 или замена Java; сертификация Runtime заблокирована"
            )
        lifecycle_path = run_lifecycle(
            args, work, pkg, signed, download_exact, selected_java, subprocess_env
        )
        report["stages"][stage_name] = {
            "status": "passed",
            "detail": "production install/update/repair/recover/rollback plus both real JVM menu launches verified",
            "evidenceSha256": sha_file(lifecycle_path),
        }
    except Exception as exc:
        error = str(exc)
        if stage_name not in report["stages"]:
            report["stages"][stage_name] = {
                "status": "failed"
                if stage_name
                in (
                    "manifest-files",
                    "materialization",
                    "startup",
                    "server-readiness",
                    "matching-server",
                    "gameplay-smoke",
                    "update-recovery",
                )
                else "blocked",
                "detail": error[:2048],
            }
    finally:
        if server is not None:
            server.close()
        # Подписи, созданные самим обработчиком, не считаются доверенными для стабильной публикации.
        report["finishedAt"] = iso()
        report_path = work / "staged-execution.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        try:
            request_json(args.backend, base_path + "/results", grant, report)
        except Exception as exc:
            print(f"Не удалось отправить отчёт: {exc}", file=sys.stderr)
            if error is None:
                error = "cannot persist execution report"
        for file in ("worker.key",):
            (work / file).unlink(missing_ok=True)
    if error:
        raise RuntimeError(error)
    print("Выполнение подготовленного окружения завершено:", report_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", required=True)
    parser.add_argument("--admin-token", default="")
    parser.add_argument(
        "--admin-token-file",
        default="",
        help="Файл токена оператора доступен только владельцу (не передавать секреты через argv)",
    )
    parser.add_argument(
        "--grant-file",
        default="",
        help="Ограниченный промежуточный допуск от доверенного хоста; не административные данные оператора",
    )
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--expected-version", default="",
                        help="Точная ожидаемая подписанная версия продукта для нативной проверки GA")
    parser.add_argument("--output", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--java", required=True)
    parser.add_argument("--execution-mode", choices=("headless", "gui"), default="gui")
    parser.add_argument("--pinned-public-key", required=True)
    parser.add_argument("--runtime-seconds", type=int, default=180)
    parser.add_argument(
        "--preset",
        default="",
        help="Обязательный именованный пресет Backend или подписанный выбор @custom",
    )
    parser.add_argument(
        "--auth-mode",
        choices=("official", "custom"),
        default="",
        help="Настоящий провайдер; не имитация и не автономная сертификация",
    )
    parser.add_argument(
        "--credentials-file",
        default="",
        help="Настоящий краткоживущий JSON учётных данных Minecraft, внедрённый хостом",
    )
    parser.add_argument(
        "--negative-credentials-file",
        default="",
        help="Отдельный отзывный тестовый сеанс Custom Auth",
    )
    parser.add_argument(
        "--guard-denied-credentials-file",
        default="",
        help="Отдельная живая тестовая идентичность с отказом по доверию",
    )
    parser.add_argument(
        "--previous-bundle",
        default="",
        help="Закреплённый хостом ZIP реального предыдущего подписанного выпуска с точными подготовленными файлами",
    )
    parser.add_argument(
        "--previous-sha256",
        default="",
        help="SHA-256 ZIP предыдущего выпуска, одобренного хостом",
    )
    parser.add_argument(
        "--replacement-java",
        default="",
        help="Другой настоящий бинарный Java той же требуемой основной версии для жизненного цикла",
    )
    parser.add_argument(
        "--managed-java-manifest",
        default="",
        help="Одобренный локальный закреплённый манифест Managed JRE и его архив",
    )
    parser.add_argument(
        "--managed-java-sha256",
        default="",
        help="SHA-256 закреплённого манифеста дистрибутива Managed JRE",
    )
    parser.add_argument(
        "--server-bundle",
        default="",
        help="Закреплённый ZIP сервера с подходящим Runtime загрузчика; Vanilla допускает официальную проверенную загрузку сервера",
    )
    parser.add_argument(
        "--server-sha256",
        default="",
        help="Закреплённый оператором SHA-256 полного дистрибутива сервера",
    )
    parser.add_argument(
        "--server-entry",
        default="",
        help="Запускатель в корне пакета: server.jar или run.sh",
    )
    parser.add_argument(
        "--bridge-path",
        default="",
        help="Обязательный путь мода/плагина ServerBridge внутри закреплённого пакета сервера",
    )
    parser.add_argument(
        "--bridge-sha256",
        default="",
        help="Закреплённый оператором SHA-256 настоящего мода/плагина Bridge",
    )
    parser.add_argument(
        "--bridge-version",
        default="",
        help="Версия ServerBridge, закреплённая оператором и наблюдавшаяся в реальном журнале сервера",
    )
    parser.add_argument("--server-startup-seconds", type=int, default=180)
    parser.add_argument("--gameplay-seconds", type=int, default=120)
    args = parser.parse_args()
    if not 15 <= args.runtime_seconds <= 3600:
        parser.error("Длительность работы среды выполнения должна составлять от 15 до 3600 секунд")
    if (
        not 30 <= args.gameplay_seconds <= 1200
        or not 30 <= args.server_startup_seconds <= 600
    ):
        parser.error("Игровой процесс должен длиться 30–1200 секунд, запуск сервера — 30–600 секунд")
    try:
        execute(args)
    except Exception as exc:
        print("Ошибка запуска подготовленного окружения:", str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
