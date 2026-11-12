#!/usr/bin/env python3
"""Собрать настоящие установщики ОС из фирменного пакета, проверенного по Ed25519.

Артефакт платформы не объявляется промышленно подписанным без проверки платформенной подписи
(Authenticode, Apple Developer ID, отдельная GPG). Windows — один .exe со встроенным
скомпилированным проверенным пакетом; Linux собирает .deb; macOS — подписанное .app внутри
подписанного .pkg. Java не требуется.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = {"windows": "windows", "linux": "linux", "darwin": "macos"}
ARCH = {"amd64": "x64", "arm64": "arm64"}


def checked(*cmd, cwd=None, env=None):
    subprocess.run([str(a) for a in cmd], cwd=cwd, env=env, check=True)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def file_matches(path, art):
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size != art["size"]
        or digest(path) != art["sha256"]
    ):
        raise ValueError(f"Не совпадают SHA-256 или размер объекта: {path}")


def verify_config(path, key, policy_path=None):
    # Проверяйте точное подписанное содержимое. Делегированный подписант допускается только по политике
    # доверия, подписанной корнем, а не по произвольным открытым ключам из пакета.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import datetime

    env = json.loads(path.read_text("utf-8"))
    payload = base64.b64decode(env["payload"], validate=True)
    if env.get("schemaVersion") == "2.0":
        policy_path = policy_path or path.with_name("trust-policy.signed.json")
        if not policy_path.is_file() or policy_path.is_symlink():
            raise ValueError("Для делегированной конфигурации необходима локальная подписанная политика доверия")
        penv = json.loads(policy_path.read_text("utf-8"))
        if penv.get("schemaVersion") != "1.0":
            raise ValueError("Не поддерживается: конверт политики доверия")
        pp = base64.b64decode(penv["payload"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(penv["rootSignature"]), b"Launcher-Trust-Policy-v1\n" + pp
        )
        policy = json.loads(pp)
        if (
            policy.get("schemaVersion") != "1.0"
            or policy.get("domain") != "launcher.trust.v1"
            or policy.get("epoch") != env.get("trustEpoch")
        ):
            raise ValueError("Домен или эпоха политики доверия не совпадают")
        now = datetime.datetime.now(datetime.timezone.utc)

        def utc(t):
            return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc
            )

        if not utc(policy["issuedAt"]) <= now < utc(policy["expiresAt"]):
            raise ValueError("Устаревшая политика доверия")
        signer = next(
            (
                k
                for k in policy["keys"]
                if k["id"] == env.get("keyId")
                and k["role"] == "bootstrap"
                and k["status"] == "active"
            ),
            None,
        )
        if not signer or utc(signer["notBefore"]) > utc(env["signedAt"]):
            raise ValueError("Подписывающая сторона загрузчика не имеет делегированных полномочий")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer["publicKey"])).verify(
            bytes.fromhex(env["signature"]),
            (
                "Launcher-Bootstrap-v2\n"
                + env["keyId"]
                + "\n"
                + str(env["trustEpoch"])
                + "\n"
                + env["signedAt"]
                + "\n"
            ).encode()
            + payload,
        )
    elif env.get("schemaVersion") == "1.0" and set(env) == {
        "schemaVersion",
        "payload",
        "signature",
    }:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(env["signature"]), payload
        )
    else:
        raise ValueError("Некорректный подписанный контейнер конфигурации")
    config = json.loads(payload)
    if config["schemaVersion"] != "1.0":
        raise ValueError("Не поддерживается: конфигурация")
    if (
        env.get("schemaVersion") == "2.0"
        and config["profilePublicKey"].lower() != key.lower()
    ):
        raise ValueError("Корень доверия игры не совпадает со встроенным")
    return config


def check_binary_arch(path, osname, arch):
    with open(path, "rb") as f:
        head = f.read(4096)
        if osname == "linux":
            expect = 62 if arch == "amd64" else 183
            if (
                head[:5] != b"\x7fELF\x02"
                or struct.unpack_from("<H", head, 18)[0] != expect
            ):
                raise ValueError(f"{path}: неверная архитектура исполняемого файла Linux ELF")
        elif osname == "windows":
            if head[:2] != b"MZ":
                raise ValueError(f"{path}: файл не является исполняемым PE")
            peoff = struct.unpack_from("<I", head, 0x3C)[0]
            if peoff + 6 > len(head):
                f.seek(peoff)
                pe = f.read(6)
            else:
                pe = head[peoff : peoff + 6]
            expect = 0x8664 if arch == "amd64" else 0xAA64
            if pe[:4] != b"PE\0\0" or struct.unpack_from("<H", pe, 4)[0] != expect:
                raise ValueError(f"{path}: неверная архитектура исполняемого файла Windows PE")
        elif osname == "darwin":
            expect = 0x01000007 if arch == "amd64" else 0x0100000C
            if (
                head[:4] != b"\xcf\xfa\xed\xfe"
                or struct.unpack_from("<I", head, 4)[0] != expect
            ):
                raise ValueError(f"{path}: неверная архитектура исполняемого файла macOS Mach-O")


def collect_bundle(args, stage):
    key = pathlib.Path(args.root_key_file).read_text().strip().lower()
    if not re.fullmatch("[0-9a-f]{64}", key):
        raise ValueError("Необходим подготовленный 32-байтовый ключ Ed25519")
    cfg = verify_config(args.config, key, args.trust_policy)
    if args.platform not in TARGETS or args.arch not in ARCH:
        raise ValueError("Не поддерживается: цель")
    if not any(
        t["os"] == args.platform and t["arch"] == args.arch for t in cfg["targets"]
    ):
        raise ValueError("Платформа отсутствует в подписанной конфигурации релиза")
    match = [
        t
        for t in cfg.get("installerTargets", [])
        if t["os"] == args.platform and t["arch"] == args.arch
    ]
    if len(match) != 1:
        raise ValueError(
            "Подписанный installerTargets должен однозначно закреплять один Prestarter для платформы"
        )
    check_binary_arch(args.prestarter, args.platform, args.arch)
    file_matches(args.prestarter, match[0]["prestarter"])
    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.config, stage / "bootstrap.signed.json")
    if args.trust_policy:
        shutil.copy2(args.trust_policy, stage / "trust-policy.signed.json")
    suffix = ".exe" if args.platform == "windows" else ""
    shutil.copy2(args.prestarter, stage / ("prestarter" + suffix))
    if args.offline_source:
        # Сохраняйте лишь обычные исходные файлы: символические ссылки, устройства, вложенные junction и другие
        # попытки выхода за пределы каталога отклоняются без перехода по ним.
        for p in args.offline_source.rglob("*"):
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError(f"Небезопасная запись автономного источника: {p}")
            relative = p.relative_to(args.offline_source)
            target = stage / relative
            if p.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if target.exists():
                    raise ValueError(
                        "Автономный источник пытается заменить файлы подписанного установщика"
                    )
                if p.stat().st_size > 3 << 30:
                    raise ValueError("Автономный объект превышает допустимый размер")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
        target = next(
            t
            for t in cfg["targets"]
            if t["os"] == args.platform and t["arch"] == args.arch
        )
        for component in target["components"]:
            art = component
            file_matches(stage / "objects" / art["sha256"], art)
        file_matches(stage / "objects" / cfg["manifest"]["sha256"], cfg["manifest"])
        file_matches(stage / "managed-jre" / "manifest.json", cfg["javaManifest"])
    # Перед упаковкой подписанную конфигурацию должен одобрить тот же промышленный Go-проверяющий, что
    # использует Prestarter. Проверка контейнера подписи на Python необходима, но не заменяет проверки
    # контракта Runtime.
    if not shutil.which("go"):
        raise RuntimeError("Для доверенной проверки загрузчика необходим инструментальный комплект Go")
    validator = ["go", "run", "./cmd/verify-branding", "--config", str(stage / "bootstrap.signed.json"), "--root-key-file", str(args.root_key_file.resolve())]
    if args.trust_policy:
        validator.extend(["--trust-policy", str((stage / "trust-policy.signed.json").resolve())])
    checked(*validator, cwd=ROOT / "prestarter")
    return key, cfg


def apply_windows_brand_icon(executable, branding):
    """Записать PNG подписанного проекта как нативную иконку PE RT_GROUP_ICON.

    Делается до Authenticode-подписи через Windows Kernel API; изменение уже подписанного PE сделало
    бы Authenticode недействительной.
    """
    asset = branding.get("iconPng")
    if not asset:
        return
    if sys.platform != "win32":
        raise RuntimeError("Ресурсы значка Windows необходимо создавать на узле сборки под Windows")
    import ctypes
    from ctypes import wintypes

    png = base64.b64decode(asset, validate=True)
    if len(png) < 24 or png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Значок бренда подписанного установщика: требуется PNG")
    width, height = struct.unpack_from(">II", png, 16)
    if not (1 <= width <= 256 and 1 <= height <= 256):
        raise ValueError("Для нативного значка Windows требуется PNG не более 256×256 пикселей")
    group = struct.pack("<HHHBBBBHHIH", 0, 1, 1, width % 256, height % 256, 0, 0, 1, 32, len(png), 1)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    begin = kernel.BeginUpdateResourceW
    begin.argtypes = (wintypes.LPCWSTR, wintypes.BOOL)
    begin.restype = wintypes.HANDLE
    update = kernel.UpdateResourceW
    update.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.WORD, wintypes.LPVOID, wintypes.DWORD)
    update.restype = wintypes.BOOL
    end = kernel.EndUpdateResourceW
    end.argtypes = (wintypes.HANDLE, wintypes.BOOL)
    end.restype = wintypes.BOOL
    h = begin(str(executable), False)
    if not h:
        raise OSError(ctypes.get_last_error(), "Ошибка: BeginUpdateResourceW")
    committed = False
    try:
        for kind, resource in ((3, png), (14, group)):
            data = ctypes.create_string_buffer(resource)
            if not update(h, ctypes.cast(ctypes.c_void_p(kind), wintypes.LPCWSTR), ctypes.cast(ctypes.c_void_p(1), wintypes.LPCWSTR), 0, data, len(resource)):
                raise OSError(ctypes.get_last_error(), "Ошибка: UpdateResourceW")
        if not end(h, False):
            raise OSError(ctypes.get_last_error(), "Ошибка: EndUpdateResourceW")
        committed = True
    finally:
        if not committed:
            end(h, True)


def package_windows(args, stage, key, out, version):
    if not shutil.which("go"):
        raise RuntimeError("Требуется набор инструментов Go")
    # Используйте новую изолированную копию Go-модуля; дерево исходников не меняется ради идентичности
    # заказчика или его потенциально крупных автономных ресурсов.
    with tempfile.TemporaryDirectory() as tmp:
        module = pathlib.Path(tmp) / "prestarter"
        shutil.copytree(
            ROOT / "prestarter",
            module,
            ignore=shutil.ignore_patterns("*.exe", "*.test"),
        )
        embedded = module / "cmd" / "installer" / "embedded.bundle.zip"
        with zipfile.ZipFile(
            embedded, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as z:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    z.write(path, path.relative_to(stage).as_posix())
        result = (
            out
            / f"launcher-{version}-{args.project}-{TARGETS[args.platform]}-{ARCH[args.arch]}.exe"
        )
        env = dict(os.environ, GOOS=args.platform, GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            result,
            "./cmd/installer",
            cwd=module,
            env=env,
        )
    check_binary_arch(result, args.platform, args.arch)
    apply_windows_brand_icon(result, verify_config(stage / "bootstrap.signed.json", key).get("branding") or {})
    if not args.unsigned_test:
        thumb = os.environ.get("LAUNCHER_WINDOWS_CERT_THUMBPRINT", "")
        if not thumb or not shutil.which("signtool"):
            raise RuntimeError(
                "Для промышленной поставки необходимы сертификат Authenticode и signtool"
            )
        checked(
            "signtool",
            "sign",
            "/fd",
            "SHA256",
            "/sha1",
            thumb,
            "/tr",
            "http://timestamp.digicert.com",
            "/td",
            "SHA256",
            result,
        )
        checked("signtool", "verify", "/pa", "/v", result)
    # На нативном узле сборки повторно откройте КОНЕЧНЫЙ подписанный исполняемый файл: встроенный пакет должен
    # по-прежнему проходить закреплённый проверяющий Prestarter.
    if sys.platform == "win32":
        checked(result, "verify")
    return result


def package_linux(args, stage, key, out, version):
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("Требуется утилита dpkg-deb")
    with tempfile.TemporaryDirectory() as tmp:
        pkg = pathlib.Path(tmp) / "deb"
        bundled = pkg / "usr" / "lib" / "launcher" / "bundle"
        bundled.parent.mkdir(parents=True)
        shutil.copytree(stage, bundled)
        exe = bundled / "installer"
        env = dict(os.environ, GOOS="linux", GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            exe,
            "./cmd/installer",
            cwd=ROOT / "prestarter",
            env=env,
        )
        exe.chmod(0o755)
        launcher = pkg / "usr" / "bin" / "launcher"
        launcher.parent.mkdir(parents=True)
        launcher.write_text(
            '#!/bin/sh\nset -eu\nif [ "$#" -eq 0 ]; then set -- install; fi\nexec /usr/lib/launcher/bundle/installer "$@" --bundle /usr/lib/launcher/bundle\n'
        )
        launcher.chmod(0o755)
        desktop = pkg / "usr" / "share" / "applications" / "launcher.desktop"
        desktop.parent.mkdir(parents=True)
        cfg = verify_config(stage / "bootstrap.signed.json", key)
        branding = cfg.get("branding") or {}
        name = branding.get("displayName", "Launcher")
        # Для Desktop Entry действуют собственные правила экранирования. Подписанное отображаемое имя — данные, а
        # не произвольный синтаксис .desktop.
        safe = name.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
        icon_entry = ""
        if branding.get("iconPng"):
            icon = pkg / "usr" / "share" / "pixmaps" / f"launcher-{args.project}.png"
            icon.parent.mkdir(parents=True, exist_ok=True)
            icon.write_bytes(base64.b64decode(branding["iconPng"], validate=True))
            icon_entry = f"Icon=launcher-{args.project}\n"
        desktop.write_text(
            f"[Desktop Entry]\nType=Application\nName={safe}\nExec=/usr/bin/launcher\n{icon_entry}Terminal=false\nCategories=Game;\n",
            encoding="utf-8",
        )
        ctrl = pkg / "DEBIAN"
        ctrl.mkdir()
        debarch = "amd64" if args.arch == "amd64" else "arm64"
        ctrl.joinpath("control").write_text(
            f"Package: launcher-{args.project}\nVersion: {version}\nArchitecture: {debarch}\nMaintainer: Launcher Release Engineering\nSection: games\nPriority: optional\nDescription: Установщик лаунчера Minecraft с подписанной конфигурацией\n"
        )
        result = out / f"launcher-{version}-{args.project}-linux-{ARCH[args.arch]}.deb"
        checked("dpkg-deb", "--build", "--root-owner-group", pkg, result)
        checked("dpkg-deb", "--info", result)
        # Проверяйте встроенный установщик и доверенные байты конечного .deb, а не только каталог подготовки до
        # упаковки.
        with tempfile.TemporaryDirectory() as checkdir:
            checked("dpkg-deb", "--extract", result, checkdir)
            unpacked = pathlib.Path(checkdir) / "usr" / "lib" / "launcher" / "bundle"
            checked(unpacked / "installer", "verify", "--bundle", unpacked)
            file_matches(unpacked / "prestarter", next(
                t["prestarter"] for t in verify_config(unpacked / "bootstrap.signed.json", key)["installerTargets"]
                if t["os"] == args.platform and t["arch"] == args.arch
            ))
    if not args.unsigned_test:
        gpg = os.environ.get("LAUNCHER_GPG_SIGNING_KEY", "")
        if not gpg or not shutil.which("gpg"):
            raise RuntimeError("Для релиза Linux необходим ключ подписи GPG")
        checked(
            "gpg",
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            gpg,
            "--detach-sign",
            "--output",
            str(result) + ".asc",
            result,
        )
        checked("gpg", "--verify", str(result) + ".asc", result)
    return result


def package_macos(args, stage, key, out, version):
    if sys.platform != "darwin":
        raise RuntimeError("Для подписанного пакета macOS требуется узел сборки под macOS")
    with tempfile.TemporaryDirectory() as tmp:
        app = pathlib.Path(tmp) / "Launcher.app"
        macos = app / "Contents" / "MacOS"
        resources = app / "Contents" / "Resources" / "bundle"
        macos.mkdir(parents=True)
        shutil.copytree(stage, resources)
        binary = macos / "Launcher"
        env = dict(os.environ, GOOS="darwin", GOARCH=args.arch, CGO_ENABLED="0")
        checked(
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.embeddedRootPublicKey={key} -X main.version={version}",
            "-o",
            binary,
            "./cmd/installer",
            cwd=ROOT / "prestarter",
            env=env,
        )
        check_binary_arch(binary, "darwin", args.arch)
        binary.chmod(0o755)
        info = {
            "CFBundleExecutable": "Launcher",
            "CFBundleIdentifier": "org.launcher." + args.project,
            "CFBundleName": "Launcher",
            "CFBundleDisplayName": verify_config(stage / "bootstrap.signed.json", key)
            .get("branding", {})
            .get("displayName", "Launcher"),
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            "LSMinimumSystemVersion": "12.0",
        }
        branding = verify_config(stage / "bootstrap.signed.json", key).get("branding") or {}
        if branding.get("iconPng"):
            # iconutil создаёт фактическую иконку Finder/Dock; загрузка неподписанной иконки после установки как
            # запасной вариант не допускается.
            if not shutil.which("sips") or not shutil.which("iconutil"):
                raise RuntimeError("Для создания значка macOS необходимы sips и iconutil")
            source = pathlib.Path(tmp) / "brand-icon.png"
            source.write_bytes(base64.b64decode(branding["iconPng"], validate=True))
            iconset = pathlib.Path(tmp) / "Brand.iconset"
            iconset.mkdir()
            for size in (16, 32, 128, 256, 512):
                checked("sips", "-s", "format", "png", "-z", str(size), str(size), source, "--out", iconset / f"icon_{size}x{size}.png")
                checked("sips", "-s", "format", "png", "-z", str(size*2), str(size*2), source, "--out", iconset / f"icon_{size}x{size}@2x.png")
            checked("iconutil", "-c", "icns", iconset, "-o", app / "Contents" / "Resources" / "Brand.icns")
            info["CFBundleIconFile"] = "Brand.icns"
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
        result = out / f"launcher-{version}-{args.project}-macos-{ARCH[args.arch]}.pkg"
        signid = os.environ.get("LAUNCHER_MACOS_CODESIGN_ID", "")
        pkgid = os.environ.get("LAUNCHER_MACOS_INSTALLER_ID", "")
        if not args.unsigned_test and (not signid or not pkgid):
            raise RuntimeError(
                "Необходимы удостоверения Developer ID Application и Developer ID Installer"
            )
        if signid:
            # Закреплённый SHA-256 Prestarter вычисляется ДО подписания пакета. Prestarter уже ОБЯЗАН иметь подпись
            # Developer ID; подпись на этом этапе изменила бы байты и нарушила подписанный манифест начальной
            # загрузки.
            checked(
                "codesign",
                "--verify",
                "--strict",
                "--verbose=2",
                resources / "prestarter",
            )
            checked(
                "codesign",
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                signid,
                app,
            )
            checked("codesign", "--verify", "--deep", "--strict", "--verbose=2", app)
        cmd = [
            "pkgbuild",
            "--component",
            app,
            "--install-location",
            "/Applications",
            "--identifier",
            "org.launcher." + args.project,
            "--version",
            version,
        ]
        if not args.unsigned_test:
            cmd += ["--sign", pkgid]
        cmd += [result]
        checked(*cmd)
        if not args.unsigned_test:
            checked("pkgutil", "--check-signature", result)
            # Одной подписи pkg недостаточно для окончательного установщика, готового к Gatekeeper: нотариально
            # заверьте точный публикуемый пакет и прикрепите билет Apple до вычисления окончательного SHA-256 выпуска.
            profile = os.environ.get("LAUNCHER_MACOS_NOTARY_PROFILE", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile):
                raise RuntimeError("Требуется защищённый профиль Apple notarytool в связке ключей")
            notarized = subprocess.run(
                ["xcrun", "notarytool", "submit", str(result),
                 "--keychain-profile", profile, "--wait", "--output-format", "json"],
                capture_output=True, text=True, check=True, timeout=1800,
            )
            outcome = json.loads(notarized.stdout)
            if outcome.get("status") != "Accepted" or not outcome.get("id"):
                raise RuntimeError("Служба нотариального заверения Apple не приняла финальный установщик")
            checked("xcrun", "stapler", "staple", result)
            checked("xcrun", "stapler", "validate", result)
            checked("spctl", "--assess", "--type", "install", "--verbose=4", result)
            checked("pkgutil", "--check-signature", result)
        # Перед приёмкой .pkg выполните реальную проверку подписанной начальной загрузки в только что собранном
        # приложении.
        checked(binary, "verify", "--bundle", resources)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform", choices=TARGETS, required=True)
    p.add_argument("--arch", choices=ARCH, required=True)
    p.add_argument(
        "--project", required=True, help="Подписанное название проекта в ID пакетов"
    )
    p.add_argument("--version", required=True)
    p.add_argument("--config", type=pathlib.Path, required=True)
    p.add_argument(
        "--trust-policy",
        type=pathlib.Path,
        help="Локально предоставленная делегированная политика доверия для v2 config, подписанная корнем",
    )
    p.add_argument("--prestarter", type=pathlib.Path, required=True)
    p.add_argument("--root-key-file", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--offline-source", type=pathlib.Path)
    p.add_argument(
        "--unsigned-test",
        action="store_true",
        help="Только для пакетов CI/тестов; НИКОГДА не для производственного выпуска",
    )
    args = p.parse_args()
    if not re.fullmatch("[a-z0-9][a-z0-9-]{1,45}", args.project):
        p.error("Для проекта требуется безопасный идентификатор пакета")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        p.error("Некорректная версия SemVer")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = pathlib.Path(tmp) / "bundle"
        key, cfg = collect_bundle(args, stage)
        if cfg["projectId"].lower() != args.project:
            p.error("Параметр --project должен совпадать с подписанным projectId")
        if args.platform == "windows":
            result = package_windows(args, stage, key, args.output, args.version)
        elif args.platform == "linux":
            result = package_linux(args, stage, key, args.output, args.version)
        else:
            result = package_macos(args, stage, key, args.output, args.version)
    print(
        json.dumps(
            {
                "artifact": str(result),
                "sha256": digest(result),
                "size": result.stat().st_size,
                "productionSigned": not args.unsigned_test,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Ошибка сборки установщика:", e, file=sys.stderr)
        sys.exit(1)
