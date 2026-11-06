#!/usr/bin/env python3
"""Опубликовать материализованный клиентский пакет Never через канонический Admin API.

Скрипт намеренно ориентирован на E2E: каждый локальный файл повторно хешируется перед загрузкой;
хеш/размер каждого ответа Backend сравнивается с манифестом пакета. Выпуск публикуется только после
принятия всех артефактов и настроек Runtime через Backend API.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import mimetypes
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


class APIClient:
    def __init__(self, base_url: str, token: str) -> None:
        parsed = urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Параметр --api должен содержать абсолютный URL http(s)")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port
        self.base_path = parsed.path.rstrip("/")
        self.token = token
        self.conn: http.client.HTTPConnection | None = None
        # Бэкенд специально выдаёт короткие токены доступа на 15 минут. Публикация
        # настоящего клиента NeoForge с тысячами ресурсов может длиться дольше.
        # Обновляйте токен через уже существующий устойчивый к фишингу сеанс WebAuthn;
        # не увеличивайте TTL и не ослабляйте политику авторизации сервера.
        self.passkey_helper: Path | None = None
        self.passkey_state: Path | None = None
        self.passkey_sign_count = 0
        self.passkey_counter_file: Path | None = None
        self.passkey_refreshed_at = 0.0

    def use_passkey_counter_file(self, path: Path) -> None:
        """Сохранять тестовый счётчик WebAuthn signCount между настоящими запусками публикации.

        Учётные данные аутентификатора общие для последовательных выпусков E2E. Сброс до 1 при
        следующем процессе — повторное воспроизведение, а не новая повторная аутентификация.
        """
        if path.is_symlink():
            raise RuntimeError("Файл счётчика Passkey является символической ссылкой и отклонён")
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            count = payload.get("signCount") if isinstance(payload, dict) else None
            if type(count) is not int or not 0 <= count < 2**32:
                raise RuntimeError("Недопустимое сохранённое значение WebAuthn signCount")
            self.passkey_sign_count = count
        self.passkey_counter_file = path

    def persist_passkey_counter(self) -> None:
        if getattr(self, "passkey_counter_file", None) is None:
            return
        path = self.passkey_counter_file
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "x", encoding="utf-8") as f:
            json.dump({"signCount": self.passkey_sign_count}, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _connect(self) -> http.client.HTTPConnection:
        if self.conn is None:
            cls = (
                http.client.HTTPSConnection
                if self.scheme == "https"
                else http.client.HTTPConnection
            )
            self.conn = cls(self.host, self.port, timeout=120)
        return self.conn

    @staticmethod
    def _retry_after_seconds(response: http.client.HTTPResponse) -> int:
        values = [
            response.getheader("Retry-After", ""),
            response.getheader("X-RateLimit-Reset", ""),
        ]
        delays: list[int] = []
        for value in values:
            try:
                parsed = int(str(value).strip())
            except (TypeError, ValueError):
                continue
            if parsed > 0:
                delays.append(parsed)
        # API сообщает сброс фиксированного окна в секундах. Добавьте секунду,
        # чтобы повторный запрос не столкнулся с границей TTL Redis. Установите
        # верхнюю границу, чтобы сломанный прокси не останавливал выпуск бесконечно.
        return min(65, max(delays, default=1) + 1)

    def _request(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        request_path = self.base_path + path
        # SQL-репозиторий использует upsert по (version_id, path), поэтому
        # прерванную ЗАГРУЗКУ ФАЙЛА можно безопасно повторить с точно теми же
        # байтами и независимой проверкой SHA-256. Не применяйте длинный цикл
        # повторов POST к аутентификации, подписанию и публикации.
        upload_endpoint = (
            method == "POST"
            and path.startswith("/api/v1/admin/projects/")
            and path.endswith("/files")
        )
        max_transport_retries = 6 if upload_endpoint else 1
        transport_retries = 0
        rate_limit_retries = 0
        while True:
            conn = self._connect()
            merged = {
                "Authorization": f"Bearer {self.token}",
                "User-Agent": f"Launcher-E2E/{PRODUCT_VERSION}",
                **headers,
            }
            try:
                conn.request(method, request_path, body=body, headers=merged)
                response = conn.getresponse()
                payload = response.read()
                if response.getheader("Connection", "").lower() == "close":
                    conn.close()
                    self.conn = None
                if response.status == 429 and rate_limit_retries < 8:
                    delay = self._retry_after_seconds(response)
                    rate_limit_retries += 1
                    print(
                        f"[e2e-upload] ограничение частоты запросов {method} {path}; повтор {rate_limit_retries}/8 через {delay} с",
                        file=sys.stderr,
                        flush=True,
                    )
                    time.sleep(delay)
                    continue
                # Ошибки 502/503/504 возможны при перезапуске контейнера API.
                # Загрузку файла можно повторить; другие POST — нельзя.
                if (
                    upload_endpoint
                    and response.status in {502, 503, 504}
                    and transport_retries < max_transport_retries
                ):
                    transport_retries += 1
                    delay = min(10, 2 ** (transport_retries - 1))
                    print(
                        f"[e2e-upload] временная ошибка HTTP {response.status}; повтор {transport_retries}/{max_transport_retries} через {delay} с",
                        file=sys.stderr,
                        flush=True,
                    )
                    if self.conn is not None:
                        self.conn.close()
                        self.conn = None
                    time.sleep(delay)
                    continue
                return response.status, payload
            except (ConnectionError, OSError, http.client.HTTPException) as exc:
                try:
                    conn.close()
                except Exception:
                    pass
                self.conn = None
                if transport_retries >= max_transport_retries:
                    raise
                transport_retries += 1
                delay = min(10, 2 ** (transport_retries - 1))
                print(
                    f"[e2e-upload] ошибка транспорта {type(exc).__name__}; повтор {transport_retries}/{max_transport_retries} через {delay} с",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(delay)

    def json(self, method: str, path: str, payload: object | None = None) -> object:
        body = (
            None
            if payload is None
            else json.dumps(payload, separators=(",", ":")).encode()
        )
        status, raw = self._request(
            method, path, body, {"Content-Type": "application/json"}
        )
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"{method} {path} => HTTP {status}: {raw.decode(errors='replace')}"
            )
        return json.loads(raw or b"{}")

    def set_upload_passkey(self, helper: Path, state: Path) -> None:
        if not helper.is_file() or not state.is_file():
            raise RuntimeError("Учётные данные загрузки WebAuthn недоступны")
        self.passkey_helper, self.passkey_state = helper, state

    def refresh_upload_auth_if_due(self, *, force: bool = False) -> None:
        if self.passkey_helper is None or self.passkey_state is None:
            return
        # Первое обновление выполняйте до медленной многофайловой загрузки, затем не
        # чаще одного раза в восемь минут, то есть раньше истечения 15-минутного JWT.
        # Счётчик доказательств увеличивается только после успешного подтверждения.
        if (
            force
            or self.passkey_refreshed_at == 0.0
            or time.monotonic() - self.passkey_refreshed_at >= 8 * 60
        ):
            self.passkey_step_up(self.passkey_helper, self.passkey_state)

    def passkey_step_up(
        self, helper: Path, state: Path, sign_count: int | None = None
    ) -> None:
        if sign_count is None:
            sign_count = self.passkey_sign_count + 1
        if sign_count <= self.passkey_sign_count:
            raise RuntimeError("Счётчик подтверждений WebAuthn должен только увеличиваться")
        if not helper.is_file():
            raise RuntimeError(f"Вспомогательная утилита WebAuthn недоступна: {helper}")
        if not state.is_file():
            raise RuntimeError(f"Состояние WebAuthn недоступно: {state}")
        begin = self.json("POST", "/api/v1/auth/passkeys/step-up/begin", {})
        if not isinstance(begin, dict) or not isinstance(begin.get("data"), dict):
            raise RuntimeError(f"Некорректный ответ начала дополнительной проверки Passkey: {begin!r}")
        data = begin["data"]
        public_key = data.get("publicKey")
        if not isinstance(public_key, dict):
            raise RuntimeError("В ответе дополнительной проверки Passkey отсутствует publicKey")
        transaction = str(data.get("transactionToken", ""))
        challenge = str(public_key.get("challenge", ""))
        if not transaction or not challenge:
            raise RuntimeError(
                "В ответе дополнительной проверки Passkey отсутствуют транзакция или challenge"
            )
        proc = subprocess.run(
            [
                sys.executable,
                str(helper),
                "assert",
                f"--transaction-token={transaction}",
                f"--challenge={challenge}",
                f"--state={state}",
                f"--sign-count={sign_count}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Вспомогательная утилита подтверждения WebAuthn завершилась ошибкой: {proc.stderr.strip()}"
            )
        try:
            assertion = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Вспомогательная утилита подтверждения WebAuthn вернула некорректный JSON"
            ) from exc
        complete = self.json(
            "POST", "/api/v1/auth/passkeys/step-up/complete", assertion
        )
        if not isinstance(complete, dict) or not isinstance(complete.get("data"), dict):
            raise RuntimeError(
                f"Некорректный ответ завершения дополнительной проверки Passkey: {complete!r}"
            )
        step_data = complete["data"]
        token = str(step_data.get("accessToken", ""))
        session = step_data.get("session")
        if (
            not token
            or not isinstance(session, dict)
            or session.get("authStrength") != "phishing-resistant"
        ):
            raise RuntimeError(
                "Дополнительная проверка Passkey не выдала токен доступа, устойчивый к фишингу"
            )
        self.token = token
        self.passkey_sign_count = sign_count
        self.persist_passkey_counter()
        self.passkey_refreshed_at = time.monotonic()

    def upload(
        self,
        path: str,
        local_file: Path,
        expected_sha256: str,
        expected_size: int,
        executable: bool,
        target_os: list[str],
    ) -> object:
        boundary = "----launcher-e2e-" + secrets.token_hex(16)
        filename = local_file.name
        content = local_file.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual.lower() != expected_sha256.lower() or len(content) != expected_size:
            raise RuntimeError(f"Локальный файл пакета изменился перед загрузкой: {path}")
        parts: list[bytes] = []

        def field(name: str, value: str) -> None:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
            )

        field("path", path)
        field("executable", "true" if executable else "false")
        for os_name in target_os:
            field("targetOs", os_name)
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename.replace(chr(34), "")}"\r\nContent-Type: {mime}\r\n\r\n'.encode()
            + content
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        if not self.project_id or not self.package_id:
            raise RuntimeError("Цель загрузки не инициализирована")
        endpoint = f"/api/v1/admin/projects/{quote(self.project_id, safe='')}/versions/{quote(self.package_id, safe='')}/files"
        status, raw = self._request(
            "POST",
            endpoint,
            body,
            {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
            },
        )
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"upload {path} => HTTP {status}: {raw.decode(errors='replace')}"
            )
        parsed = json.loads(raw)
        file_info = parsed.get("data", {}).get("file", parsed)
        remote_sha = str(file_info.get("sha256", ""))
        remote_size = int(file_info.get("size", -1))
        if (
            remote_sha.lower() != expected_sha256.lower()
            or remote_size != expected_size
        ):
            raise RuntimeError(f"Контрольная сумма Backend после загрузки не совпадает: {path}")
        return parsed

    project_id = ""
    package_id = ""


def safe_local(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or not relative or "\\" in relative:
        raise RuntimeError(f"Небезопасный путь пакета: {relative!r}")
    resolved_root = root.resolve(strict=True)
    lexical = root
    for part in rel.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise RuntimeError(f"Путь пакета не может быть символической ссылкой: {relative!r}")
    candidate = (root / rel).resolve(strict=True)
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise RuntimeError(
            f"Путь пакета выходит за пределы корня клиента либо указывает на сам корень: {relative!r}"
        )
    if not candidate.is_file():
        raise RuntimeError(f"Путь пакета не указывает на обычный файл: {relative!r}")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--client-dir", required=True, type=Path)
    parser.add_argument("--quick-play", default="")
    parser.add_argument("--webauthn-helper", type=Path)
    parser.add_argument("--webauthn-state", type=Path)
    parser.add_argument("--passkey-counter-file", type=Path)
    parser.add_argument("--refreshed-token-output", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    wrapper = json.loads(args.package.read_text())
    manifest = wrapper.get("manifest")
    settings = wrapper.get("manifestSettings")
    if not isinstance(manifest, dict) or not isinstance(settings, dict):
        raise RuntimeError("Пакет клиента должен содержать manifest и manifestSettings")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("Пакет клиента не содержит файлов")
    if args.quick_play:
        minecraft = settings.setdefault("minecraft", {})
        game_args = list(minecraft.get("gameArgs") or [])
        game_args += ["--quickPlayMultiplayer", args.quick_play]
        minecraft["gameArgs"] = game_args
    runtime = settings.setdefault("runtime", {})
    runtime.setdefault(
        "memory", {"minimumMb": 512, "recommendedMb": 1024, "maximumMb": 1536}
    )

    project = str(manifest["projectId"])
    profile = str(manifest["profileId"])
    channel = str(manifest["channel"])
    version = str(manifest["version"])
    client = APIClient(args.api, args.token)
    if args.passkey_counter_file:
        client.use_passkey_counter_file(args.passkey_counter_file)

    created = client.json(
        "POST",
        f"/api/v1/admin/projects/{quote(project, safe='')}/versions",
        {
            "profileId": profile,
            "channel": channel,
            "version": version,
        },
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError(f"В ответе на создание версии отсутствует id: {created!r}")
    version_id = str(created["id"])
    client.project_id = project
    client.package_id = version_id

    client.json(
        "PUT",
        f"/api/v1/admin/projects/{quote(project, safe='')}/versions/{quote(version_id, safe='')}/manifest",
        settings,
    )

    if bool(args.webauthn_helper) != bool(args.webauthn_state):
        raise RuntimeError(
            "Параметры --webauthn-helper и --webauthn-state необходимо указывать вместе"
        )
    if args.webauthn_helper and args.webauthn_state:
        client.set_upload_passkey(args.webauthn_helper, args.webauthn_state)
        print(
            "[e2e-upload] обновите доступ перед длительной передачей файла",
            file=sys.stderr,
            flush=True,
        )
        client.refresh_upload_auth_if_due(force=True)

    total = len(files)
    total_bytes = 0
    for index, item in enumerate(files, 1):
        if not isinstance(item, dict):
            raise RuntimeError("Некорректная запись файла")
        relative = str(item["path"])
        expected_sha = str(item["sha256"])
        expected_size = int(item["size"])
        local_file = safe_local(args.client_dir, relative)
        if not local_file.is_file():
            raise RuntimeError(f"Файл пакета отсутствует: {relative}")
        client.refresh_upload_auth_if_due()
        client.upload(
            relative,
            local_file,
            expected_sha,
            expected_size,
            bool(item.get("executable", False)),
            list(item.get("targetOs") or []),
        )
        total_bytes += expected_size
        if index == 1 or index % 250 == 0 or index == total:
            print(
                f"[e2e-upload] {index}/{total} файлов, {total_bytes} байт",
                file=sys.stderr,
                flush=True,
            )

    if args.webauthn_helper and args.webauthn_state:
        print(
            "[e2e-upload] обновите дополнительную защиту от фишинга перед подписанием пакета",
            file=sys.stderr,
            flush=True,
        )
        client.passkey_step_up(args.webauthn_helper, args.webauthn_state)

    # Никогда не выводите сертификацию запуска или целостности из административного
    # запроса публикации. До окончательной фиксации пройдите тот же аудируемый
    # конвейер пакетов, что используется публичным API пакетов.
    package_path = f"/api/v1/packages/{quote(version_id, safe='')}"
    validated = client.json("POST", package_path + "/validate")
    if (
        not isinstance(validated, dict)
        or validated.get("data", {}).get("status") != "valid"
    ):
        raise RuntimeError(f"Проверка пакета не пройдена: {validated!r}")
    client.json("POST", package_path + "/sign")
    client.json("POST", package_path + "/stage")
    integrity = client.json("POST", package_path + "/integrity-check")
    if (
        not isinstance(integrity, dict)
        or integrity.get("data", {}).get("result", {}).get("result") != "passed"
    ):
        raise RuntimeError(f"Проверка целостности пакета не пройдена: {integrity!r}")

    if args.webauthn_helper and args.webauthn_state:
        print(
            "[e2e-upload] обновите дополнительную защиту от фишинга непосредственно перед публикацией",
            file=sys.stderr,
            flush=True,
        )
        client.passkey_step_up(args.webauthn_helper, args.webauthn_state)

    published = client.json(
        "POST",
        f"/api/v1/admin/projects/{quote(project, safe='')}/versions/{quote(version_id, safe='')}/publish",
    )
    manifest_url = f"{args.api.rstrip('/')}/api/v1/projects/{quote(project, safe='')}/profiles/{quote(profile, safe='')}/manifest?channel={quote(channel, safe='')}"
    result = {
        "status": "published",
        "projectId": project,
        "profileId": profile,
        "channel": channel,
        "version": version,
        "versionId": version_id,
        "files": total,
        "bytes": total_bytes,
        "manifestUrl": manifest_url,
        "release": published,
    }
    if args.refreshed_token_output:
        # Оркестратор E2E не должен повторно использовать токен, истёкший при загрузке
        # нескольких гигабайт. Обновлённый bearer нельзя помещать в сертификаты JSON.
        token_path = args.refreshed_token_output
        token_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(token_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as private:
            private.write(client.token + "\n")
            private.flush()
            os.fsync(private.fileno())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
