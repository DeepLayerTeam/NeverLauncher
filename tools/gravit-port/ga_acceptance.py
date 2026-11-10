#!/usr/bin/env python3
"""Выполняет окончательную приёмку миграции Gravit с *реальными* внешними системами.

JAR Gravit не запускаются. Существующая Go-проверка Migration GA обязана проверить
подписанные свидетельства 36 проверок и повторно запросить Backend с PostgreSQL;
затем все 19 утверждённых проверок поведения модулей запускаются как реальные
исполняемые файлы с закреплёнными хешами. Утилита не может подделать сеансы
Minecraft, подписанные установщики или утверждение проверяющего.
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
import stat
import subprocess
import sys
import time

import rehearse_cohort_04910 as rehearsal

FORMAT = "never/gravit-acceptance-0500/v1"
MODULE_IDS = tuple(f"M{i:02}" for i in range(1, 20))
CLASSES = rehearsal.CLASSES
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_JSON = 8 << 20


class Blocked(Exception):
    pass


def require(value: bool, msg: str) -> None:
    if not value:
        raise Blocked(msg)


def regular(path: Path, limit: int = MAX_JSON, private: bool = False) -> bytes:
    require(path.is_absolute(), "Требуется абсолютный путь")
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
                "Файл отсутствует, является ссылкой, специальным файлом или слишком велик: " + str(path))
        if private:
            require(info.st_mode & 0o077 == 0, "Требуются закрытые права доступа к файлу: " + str(path))
        with path.open("rb") as f:
            data = f.read(limit + 1)
            require(len(data) == info.st_size, "Файл изменился во время чтения: " + str(path))
            require(os.fstat(f.fileno()).st_ino == info.st_ino, "Файл был заменён во время чтения")
        return data
    except OSError as exc:
        raise Blocked("не удаётся прочитать " + str(path)) from exc


def doc(path: Path, *, private: bool = False) -> dict:
    try:
        value = json.loads(regular(path, private=private))
    except (ValueError, UnicodeError) as exc:
        raise Blocked("Некорректное значение: JSON:" + str(path)) from exc
    require(type(value) is dict, "Требуется объект JSON: " + str(path))
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path, limit: int = 1 << 30) -> str:
    require(path.is_absolute(), "Требуется абсолютный путь проверяемого файла")
    try:
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
                "Небезопасный проверяемый файл " + str(path))
        h = hashlib.sha256()
        with path.open("rb") as f:
            require(os.fstat(f.fileno()).st_ino == st.st_ino, "Проверяемый файл был заменён")
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
            end = os.fstat(f.fileno())
            require(end.st_size == st.st_size and end.st_mtime_ns == st.st_mtime_ns,
                    "Проверяемый файл изменился во время чтения")
        return h.hexdigest()
    except OSError as exc:
        raise Blocked("не удаётся вычислить хеш " + str(path)) from exc


def pinned(path: str, expected: str, *, executable: bool = False) -> Path:
    require(isinstance(path, str) and path.startswith("/") and isinstance(expected, str)
            and HEX.fullmatch(expected) is not None, "Требуются абсолютный зафиксированный путь и SHA-256")
    result = Path(path)
    require(sha(result, 128 << 20 if executable else 1 << 30) == expected,
            "Несовпадение зафиксированного SHA-256 файла: " + path)
    if executable:
        require(result.lstat().st_mode & 0o111 != 0, "Проверка должна быть исполняемым файлом")
    return result


def execute(argv: list[str], *, timeout: int, env: dict[str, str], max_out: int = MAX_JSON) -> bytes:
    try:
        run = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout, env=env, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Ошибка команды проверки работающей системы: " + Path(argv[0]).name) from exc
    require(0 < len(run.stdout) <= max_out, "Вывод выполняемой команды отсутствует или превышает лимит")
    return run.stdout


def clean_env() -> dict[str, str]:
    # Проверки модулей не должны получать bearer-токен Backend, ключ подписи или DSN базы данных.
    forbidden = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE", "SIGNING", "DSN", "KEY", "CREDENTIAL", "AUTH")
    return {k: v for k, v in os.environ.items()
            if not any(x in k.upper() for x in forbidden) and k not in ("PYTHONPATH", "PYTHONHOME")}


def check_migration(cfg: dict, cohort: dict) -> tuple[dict, str, str]:
    cases = cohort.get("cases")
    require(cohort.get("format") == rehearsal.FORMAT and
            cohort.get("status") == "isolated-stage-pass-not-production-GA" and
            cohort.get("productionGA") is False and isinstance(cases, list) and len(cases) == 3,
            "Требуются три фактических подтверждения состояния проекта до и после обновления")
    root = Path(cfg["rehearsalRoot"])
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "Требуется каталог реального пробного запуска")
    refs = cfg.get("references")
    require(type(refs) is dict and set(refs) == set(CLASSES), "Требуются входные данные трёх эталонных сценариев миграции")
    require(set(x.get("referenceClass") for x in cases if type(x) is dict) == set(CLASSES),
            "Обнаружены повторяющиеся или отсутствующие классы репетиции")
    plans = {}
    commit = None
    target = None
    for item in cases:
        cls = item["referenceClass"]
        ref = refs[cls]
        require(type(ref) is dict and set(ref) == {"plan", "certificate", "evidenceDir"},
                "Требуются точные пути к доказательствам миграции на работающей системе")
        plan = doc(Path(ref["plan"]), private=True)
        cert = doc(Path(ref["certificate"]), private=True)
        require(plan.get("referenceClass") == cls and cert.get("referenceClass") == cls
                and plan.get("runId") == item.get("runId") == cert.get("runId")
                and plan.get("projectId") == item.get("projectId") == cert.get("projectId")
                and item.get("sourceSha256") == cert.get("sourceSha256"),
                "Подписанный сертификат GA не соответствует фактически перенесённому проекту: " + cls)
        require(isinstance(plan.get("sourceArchive"), str)
                and sha(Path(plan["sourceArchive"])) == item["sourceSha256"],
                "Исходные данные Gravit изменились: " + cls)
        if commit is None:
            commit, target = cert.get("commitSha"), cert.get("targetReleaseSha256")
        require(cert.get("commitSha") == commit and cert.get("targetReleaseSha256") == target,
                "Независимые проекты должны использовать одинаковые коммит и хеш финального релиза")
        require(isinstance(item.get("installedBeforeSha256"), str)
                and HEX.fullmatch(item["installedBeforeSha256"]) and
                isinstance(item.get("installedAfterSha256"), str)
                and HEX.fullmatch(item["installedAfterSha256"]) and
                item["installedBeforeSha256"] != item["installedAfterSha256"],
                "Клиент не был обновлён для " + cls)
        for step, field, expected in (("pre-update-live", "preUpdateWitnessSha256", "installedBeforeSha256"),
                                      ("post-update-live", "postUpdateWitnessSha256", "installedAfterSha256")):
            witness = root / cls / (step + ".json")
            require(sha(witness, MAX_JSON) == item.get(field), "Подтверждение игрового запуска изменилось: " + step)
            w = doc(witness)
            data = w.get("data", w)
            require(type(data) is dict and data.get("runId") == item["runId"],
                    "Проверочный запуск не соответствует сертифицированному проекту")
            live = data.get("liveSession")
            require(type(live) is dict and live.get("clientSha256") == item[expected]
                    and isinstance(live.get("joinedAt"), str) and bool(live["joinedAt"])
                    and bool(live.get("playerUuid")), "Отсутствует подтверждение реального игрового запуска клиента и UUID")
            probes = data.get("probes")
            require(type(probes) is list and len(probes) == len(rehearsal.PROBES)
                    and [p.get("name") for p in probes if type(p) is dict] == list(rehearsal.PROBES)
                    and all(p.get("passed") is True and type(p.get("evidenceSha256")) is str
                            and HEX.fullmatch(p["evidenceSha256"]) for p in probes),
                    "Игровые проверки отсутствуют либо не пройдены")
            if step == "pre-update-live":
                old_player = live["playerUuid"]
                require(data.get("ready") is True and data.get("blockers") == [],
                        "Backend не одобрил пробный запуск до обновления")
            else:
                require(live["playerUuid"] == old_player and data.get("ready") is False,
                        "После обновления UUID изменился либо локальное подтверждение ошибочно сообщает о готовности Backend")
        update = doc(root / cls / "signed-update.json")
        require(update.get("status") == "committed" and
                update.get("packageSha256") == item.get("updatePackageSha256"),
                "Обновление подписанного клиента не было зафиксировано")
        plans[cls] = ref
    require(isinstance(commit, str) and len(commit) in (40, 64)
            and isinstance(target, str) and HEX.fullmatch(target), "Некорректный идентификатор релиза")
    return plans, commit, target


def live_certificate_verification(cfg: dict, refs: dict) -> None:
    checker = pinned(cfg["checker"], cfg["checkerSha256"], executable=True)
    trusted = Path(cfg["trustedPublicKey"])
    require(trusted.is_absolute() and regular(trusted, 65536), "Требуется независимый доверенный открытый ключ")
    argv = [str(checker), "verify-cohort-live", "--public-key", str(trusted)]
    for cls in CLASSES:
        ref = refs[cls]
        e = Path(ref["evidenceDir"])
        require(e.is_absolute() and e.is_dir() and not e.is_symlink(),
                "Сохранённые закрытые подписанные доказательства недоступны")
        argv += ["--" + cls + "-plan", ref["plan"], "--" + cls, ref["certificate"],
                 "--" + cls + "-evidence", str(e)]
    require(bool(os.environ.get("LAUNCHER_MIGRATION_GA_TOKEN", "").strip()),
            "Для проверки работающего Backend необходим краткосрочный токен администратора")
    execute(argv, timeout=180, env=os.environ.copy(), max_out=65536)
    require(sha(checker, 128 << 20) == cfg["checkerSha256"],
            "Проверяющая программа Migration GA изменилась во время аттестации работающей системы")


def check_modules(cfg: dict, refs: dict, output: Path) -> list[dict]:
    modules = cfg.get("modules")
    require(type(modules) is dict and set(modules) == set(MODULE_IDS),
            "Требуются 19 реальных проверок функционального соответствия модулей Gravit, включая безопасную альтернативу небезопасной команде")
    result = []
    for module in MODULE_IDS:
        probe = modules[module]
        require(type(probe) is dict and set(probe) == {"referenceClass", "executable", "executableSha256", "args", "timeoutSeconds"},
                "Для модуля требуются закреплённый исполняемый файл с ограничениями и точная проверка")
        cls = probe["referenceClass"]
        require(cls in CLASSES and type(probe["args"]) is list and
                all(type(x) is str and len(x) <= 1024 for x in probe["args"]),
                "Некорректная ссылка на модуль или команда")
        seconds = probe["timeoutSeconds"]
        require(type(seconds) is int and 1 <= seconds <= 900, "Время ожидания проверки модуля выходит за допустимые пределы")
        exe = pinned(probe["executable"], probe["executableSha256"], executable=True)
        case = doc(Path(refs[cls]["certificate"]), private=True)
        started = time.time()
        stdout = execute([str(exe), *probe["args"]], timeout=seconds, env=clean_env())
        require(sha(exe, 128 << 20) == probe["executableSha256"],
                "Исполняемый файл проверки модуля изменился во время выполнения")
        try:
            observation = json.loads(stdout)
        except (ValueError, UnicodeError) as exc:
            raise Blocked("Некорректное значение: вывод модуля:" + module) from exc
        require(type(observation) is dict and observation.get("moduleId") == module
                and observation.get("runId") == case["runId"]
                and observation.get("projectId") == case["projectId"]
                and observation.get("sourceSha256") == case["sourceSha256"]
                and observation.get("passed") is True,
                "Модуль не прошёл реальную проверку сертифицированного проекта: " + module)
        events = observation.get("observations")
        require(type(events) is list and len(events) >= 2 and
                all(type(x) is str and 1 <= len(x) <= 256 for x in events),
                "Модуль не предоставил нескольких независимых наблюдений поведения: " + module)
        file = observation.get("evidenceFile")
        eh = observation.get("evidenceSha256")
        require(type(file) is str and file.startswith("/") and type(eh) is str and
                HEX.fullmatch(eh) and sha(Path(file), 128 << 20) == eh,
                "Доказательства работы реального модуля отсутствуют или изменились: " + module)
        evidence = Path(file)
        require(evidence.lstat().st_mtime >= started - 2,
                "Доказательства модуля не были созданы текущим запуском: " + module)
        result.append({"moduleId": module, "referenceClass": cls, "executableSha256": probe["executableSha256"],
                       "evidenceSha256": eh, "observationSha256": digest(stdout), "observations": events})
        # Сохраняйте исходные свидетельства конфиденциально, а не только их хеш. Перезапись запрещена.
        dest = output / (module + ".evidence")
        with evidence.open("rb") as source, dest.open("xb") as target:
            os.chmod(dest, 0o600)
            shutil.copyfileobj(source, target, 1 << 20)
            target.flush()
            os.fsync(target.fileno())
        require(sha(dest, 128 << 20) == eh, "Сохранённое подтверждение модуля не соответствует выполненной проверке")
    return result


def write_report(output: Path, report: dict) -> Path:
    target = output / "acceptance-0500.json"
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    with target.open("xb") as f:
        os.chmod(target, 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    d = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(d)
    finally:
        os.close(d)
    return target


def run(cfg: dict, output: Path) -> dict:
    require(cfg.get("format") == FORMAT and set(cfg) == {
        "format", "rehearsalRoot", "rehearsalReport", "references", "modules",
        "checker", "checkerSha256", "trustedPublicKey"}, "Некорректная конфигурация полной приёмки")
    require(output.is_absolute() and output.is_dir() and not output.is_symlink()
            and output.stat().st_mode & 0o077 == 0 and not list(output.iterdir()),
            "Выходной каталог доказательств должен быть новым, пустым и иметь права 0700")
    cohort = doc(Path(cfg["rehearsalReport"]), private=True)
    refs, commit, release = check_migration(cfg, cohort)
    # Go-проверка подключается к реальному TLS Backend и проверяет ВСЕ 36 подписанных E2E-тестов,
    # их исходные свидетельства, действующий маршрут PostgreSQL и разные проекты.
    live_certificate_verification(cfg, refs)
    tests = check_modules(cfg, refs, output)
    # После недоверенных проверок модулей повторно запросите Backend: отозванный
    # или откатанный релиз нельзя утвердить по прежним данным.
    live_certificate_verification(cfg, refs)
    report = {"format": FORMAT, "commitSha": commit, "targetReleaseSha256": release,
              "references": [{"referenceClass": item["referenceClass"],
                              "runId": item["runId"], "projectId": item["projectId"],
                              "sourceSha256": item["sourceSha256"],
                              "updatePackageSha256": item["updatePackageSha256"]}
                             for item in cohort["cases"]], "moduleChecks": tests,
              "migrationChecks": 36, "moduleCheckCount": 19,
              "status": "LIVE_CHECKS_PASSED_REVIEW_REQUIRED",
              "completedAt": datetime.now(timezone.utc).isoformat(),
              "productionGA": False}
    write_report(output, report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        result = run(doc(args.config, private=True), args.evidence_dir)
        print("ПРОВЕРКИ РАБОТАЮЩЕЙ СИСТЕМЫ ПРОЙДЕНЫ (это не одобрение GA):", result["migrationChecks"],
              "миграционных E2E-проверок и", result["moduleCheckCount"], "проверок модулей")
        return 0
    except (Blocked, OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        print("ЗАБЛОКИРОВАНО: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
