#!/usr/bin/env python3
"""Run the real Gravit identity/credential/trust migration against a live API.

Preconditions: an existing prepared migration run with persisted Gravit ZIP
inventory (and PostgreSQL). This tool never deserializes password verifiers,
accepts Gravit sessions, or imports a Gravit administrator role. Roles require
an individually approved mapping and a current passkey-authenticated admin token.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request

MAX_SOURCE = 512 << 20
MAX_RESPONSE = 4 << 20
UUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


class MigrationError(Exception):
    pass


def source_hash(path):
    size = os.stat(path).st_size
    if not 0 < size <= MAX_SOURCE:
        raise MigrationError("Исходный ZIP должен быть непустым и не превышать 512 МиБ")
    sha = hashlib.sha256()
    with open(path, "rb") as reader:
        for part in iter(lambda: reader.read(1 << 20), b""):
            sha.update(part)
    return size, sha.hexdigest()


def canonical_uuid(value):
    normalized = value.strip().lower().replace("-", "")
    if len(normalized) != 32 or any(c not in "0123456789abcdef" for c in normalized):
        raise MigrationError("Некорректное значение: UUID в утверждённой карте ролей")
    result = "-".join([normalized[:8], normalized[8:12], normalized[12:16], normalized[16:20], normalized[20:]])
    if not UUID.fullmatch(result) or normalized == "0" * 32:
        raise MigrationError("Некорректное значение: UUID карты ролей")
    return result


def role_plan(path, imported, users):
    """Require explicit per-UUID approval; never elevate matched Never users."""
    if not path:
        return []
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"projectId", "grants"}:
        raise MigrationError("Для карты ролей требуются projectId и grants")
    project = raw["projectId"]
    grants = raw["grants"]
    if not isinstance(project, str) or not project or project == "*" or not isinstance(grants, list) or len(grants) > 200000:
        raise MigrationError("Некорректное значение: сопоставление ролей проекта")
    allowed = {"viewer", "player", "developer", "operator", "owner"}
    rows = {canonical_uuid(r["uuid"]): r for r in imported if r.get("state") == "imported"}
    indexed = {u.get("id"): u for u in users}
    changes = []
    seen = set()
    for g in grants:
        if not isinstance(g, dict) or set(g) != {"uuid", "roleId"}:
            raise MigrationError("Некорректное значение: отдельное утверждение роли")
        u = canonical_uuid(g["uuid"])
        role = g["roleId"]
        if u in seen or u not in rows or not isinstance(role, str) or role not in allowed:
            raise MigrationError("Разрешение роли Gravit повторяется, не поддерживается или относится к неперенесённой роли")
        seen.add(u)
        row = rows[u]
        user_id = "gravit-" + row["provider"] + "-" + u.replace("-", "")
        user = indexed.get(user_id)
        if not user or user.get("status") != "active" or user.get("roleId") != "player":
            raise MigrationError("Целевая учётная запись для назначенной роли не является импортированным активным игроком")
        prior = user.get("projectRoles") or {}
        if not isinstance(prior, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in prior.items()):
            raise MigrationError("Некорректное значение: существующие роли проекта")
        desired = {**prior, project: role}
        changes.append((user_id, prior, desired))
    return changes


class NoRedirect(HTTPRedirectHandler):
    """A redirected Bearer request could otherwise disclose the operator token."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Backend:
    def __init__(self, url, token, timeout=40):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
            raise MigrationError("Для серверной части требуется HTTPS-адрес без учётных данных и пути")
        if not token or "\n" in token or "\r" in token:
            raise MigrationError("Укажите действительный токен оператора в переменных окружения")
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def request(self, method, path, source=None, headers=None, payload=None):
        req_headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        req_headers.update(headers or {})
        if source is not None and payload is not None:
            raise MigrationError("Нельзя одновременно загрузить ZIP и JSON")
        def call(body):
            req = Request(self.url + path, data=body, method=method, headers=req_headers)
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    if resp.status != 200:
                        raise MigrationError("Неожиданное значение: статус ответа серверной части")
                    raw = resp.read(MAX_RESPONSE + 1)
            except HTTPError as exc:
                # Do NOT echo a server error body (may contain secrets).
                raise MigrationError("Backend отклонил запрос %s %s (HTTP %d)" % (method, path, exc.code)) from None
            except (OSError, URLError) as exc:
                raise MigrationError("Ошибка передачи данных Backend: %s" % type(exc).__name__) from None
            if len(raw) > MAX_RESPONSE:
                raise MigrationError("Ответ Backend превышает 4 МиБ")
            try:
                obj = json.loads(raw)
            except (ValueError, UnicodeError):
                raise MigrationError("Ответ Backend не содержит корректный JSON") from None
            if not isinstance(obj, dict):
                raise MigrationError("Некорректный формат: ответ Backend")
            return obj.get("data", obj)
        if source is not None:
            size, before = source_hash(source)
            req_headers.update({"Content-Type": "application/zip", "Content-Length": str(size)})
            with open(source, "rb") as reader:
                response = call(reader)
            if source_hash(source) != (size, before):
                raise MigrationError("Исходный ZIP изменился во время загрузки")
            return response
        if payload is not None:
            req_headers["Content-Type"] = "application/json"
            return call(json.dumps(payload, separators=(",", ":")).encode())
        return call(None if method == "GET" else b"")


def verify_preview(inventory, identity, auth, run_id, digest):
    if inventory.get("sourceSha256") != digest or identity.get("sourceSha256") != digest or auth.get("sourceSha256") != digest:
        raise MigrationError("Хеш источника различается в перечне, учётных записях и учётных данных")
    if identity.get("runId") != run_id or auth.get("runId") != run_id:
        raise MigrationError("В ответе указан неверный запуск миграции")
    if identity.get("summary", {}).get("blocked") != 0:
        raise MigrationError("Сопоставление UUID заблокировано или содержит конфликты")
    rows = auth.get("rows")
    if not isinstance(rows, list) or len(rows) != len(identity.get("rows", [])) or not rows:
        raise MigrationError("Предпросмотр учётных данных охватывает не все сопоставленные учётные записи")
    counts = {"imported": 0, "manual_reset": 0, "existing_unchanged": 0}
    by_uuid = set()
    for row in rows:
        uuid = canonical_uuid(row.get("uuid", ""))
        if uuid in by_uuid or row.get("provider") not in ("sql", "fileauth") or row.get("state") not in counts:
            raise MigrationError("Обнаружен дубликат: либо неподдерживаемый результат проверки учётных данных")
        by_uuid.add(uuid)
        counts[row["state"]] += 1
    if any(auth.get({"imported": "imported", "manual_reset": "manualReset", "existing_unchanged": "existingUnchanged"}[key]) != n for key, n in counts.items()):
        raise MigrationError("Количество учётных данных не совпадает между источниками")
    return counts


def atomic_receipt(target, receipt):
    output = Path(target)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise MigrationError("Квитанция уже существует; выберите другой путь")
    fd, temporary = tempfile.mkstemp(prefix=".migration-users-", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(receipt, out, ensure_ascii=False, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.link(temporary, output)  # no overwrite when another operator races
        os.unlink(temporary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def migrate(api, run_id, source, mode, password_format, allow_resets=False, roles_file=None, texture_mapping_output=None):
    size, digest = source_hash(source)
    root = "/api/v1/admin/migration-runs/" + quote(run_id, safe="")
    inventory = api.request("GET", root + "/inventory")
    if inventory.get("sourceSha256") != digest or inventory.get("sourceBytes") != size:
        raise MigrationError("Исходный ZIP не совпадает с сохранённым каталогом Backend")
    mapped = api.request("POST", root + "/identities", source=source)
    verified = api.request("POST", root + "/identities/verify")
    if mapped.get("entriesSha256") != verified.get("entriesSha256") or mapped.get("summary") != verified.get("summary"):
        raise MigrationError("Во время проверки изменилось сопоставление учётных записей")
    h = {"X-Gravit-Password-Format": password_format}
    preview = api.request("POST", root + "/credentials/preview", source=source, headers=h)
    if preview.get("dryRun") is not True:
        raise MigrationError("Backend не выполнил предварительную проверку учётных данных")
    counts = verify_preview(inventory, verified, preview, run_id, digest)
    receipt = {"version": "0.49.4", "runId": run_id, "sourceSha256": digest, "sourceBytes": size, "identitySHA256": verified.get("entriesSha256"), "credentialCounts": counts, "mode": mode, "status": "prepared"}
    if mode == "prepare":
        return receipt
    if counts["manual_reset"] and not allow_resets:
        raise MigrationError("Требуется ручной сброс паролей; импорт приостановлен до явного подтверждения")
    if counts["imported"] == 0:
        raise MigrationError("Нет новых учётных записей для переноса; доверие существующих пользователей Never изменять нельзя")
    imported = api.request("POST", root + "/credentials/import", source=source, headers={**h, "X-Migration-Import-Confirm": run_id})
    if imported.get("dryRun") or verify_preview(inventory, verified, imported, run_id, digest) != counts:
        raise MigrationError("Импорт учётных данных не совпадает с подтверждённым предпросмотром")
    committed = api.request("GET", root + "/credentials")
    if committed.get("rows") != imported.get("rows") or committed.get("identitySha256") != imported.get("identitySha256"):
        raise MigrationError("Подтверждение сохранённых учётных данных отличается от ответа импорта")
    receipt["status"] = "accounts_imported"
    trust_preview = api.request("POST", root + "/security/preview")
    if trust_preview.get("importedAccounts") != counts["imported"] or trust_preview.get("appliedAt") is not None:
        raise MigrationError("предварительный просмотр сброса доверия не совпадает с импортированные пользователи")
    trust = api.request("POST", root + "/security/activate", headers={"X-Migration-Trust-Confirm": run_id, "X-Migration-Fresh-Keys-Confirmed": "true"})
    if trust.get("importedAccounts") != counts["imported"] or trust.get("appliedAt") is None:
        raise MigrationError("Сброс доверия не подтверждён в постоянном хранилище")
    durable = api.request("GET", root + "/security")
    if durable.get("importedAccounts") != counts["imported"] or not durable.get("verified"):
        raise MigrationError("Сохранённый отчёт о сбросе доверия не прошёл проверку")
    receipt["status"] = "trust_reset_verified"
    if texture_mapping_output:
        mapping = []
        seen = set()
        for row in committed["rows"]:
            if row["state"] not in ("imported", "existing_unchanged"):
                continue
            u = canonical_uuid(row["uuid"])
            if u in seen:
                raise MigrationError("Обнаружен дубликат: идентичность текстуры")
            seen.add(u)
            mapping.append({"source_uuid": u, "target_uuid": u})
        atomic_receipt(texture_mapping_output, mapping)
        receipt["textureMappingEntries"] = len(mapping)
    if roles_file:
        current = api.request("GET", "/api/v1/admin/users")
        changes = role_plan(roles_file, committed["rows"], current.get("items", []))
        done = 0
        for uid, prior, desired in changes:
            updated = api.request("PATCH", "/api/v1/admin/users/" + quote(uid, safe=""), payload={"projectRoles": desired, "expectedProjectRoles": prior})
            if updated.get("id") != uid or updated.get("projectRoles") != desired:
                raise MigrationError("Изменение роли в проекте не подтверждено")
            done += 1
        receipt["roleAssignments"] = done
        receipt["status"] = "roles_applied"
    return receipt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend", required=True, help="Базовый HTTPS-адрес работающего API NeverLauncher")
    p.add_argument("--run-id", required=True)
    p.add_argument("--source-zip", required=True)
    p.add_argument("--mode", choices=["prepare", "import"], default="prepare")
    p.add_argument("--password-format", default="", help="Явно указанный поддерживаемый формат проверки FileAuth")
    p.add_argument("--allow-manual-resets", action="store_true")
    p.add_argument("--fresh-keys-confirmed", action="store_true", help="Оператор подтверждает независимое создание ключей подписи Never и JWT")
    p.add_argument("--roles-file", help="Одобренные явные назначения ролей UUID → проект (только импорт, требуется недавняя MFA через passkey)")
    p.add_argument("--texture-mapping-output", help="Проверенная карта UUID для gravit-textures-import-02510 (только импорт)")
    p.add_argument("--receipt", required=True)
    args = p.parse_args(argv)
    if not RUN_ID.fullmatch(args.run_id):
        p.error("Некорректное значение: идентификатор запуска")
    if args.mode == "import" and not args.fresh_keys_confirmed:
        p.error("Импорт: требуется --fresh-keys-confirmed")
    if args.mode == "prepare" and (args.roles_file or args.allow_manual_resets or args.texture_mapping_output):
        p.error("Изменение ролей и подтверждение сброса требуют режима импорта")
    token = os.environ.get("NEVERLAUNCHER_MIGRATION_TOKEN", "")
    try:
        result = migrate(Backend(args.backend, token), args.run_id, args.source_zip, args.mode, args.password_format, args.allow_manual_resets, args.roles_file, args.texture_mapping_output)
        atomic_receipt(args.receipt, result)
    except (MigrationError, OSError, ValueError, KeyError) as exc:
        # Never print password hashes, tokens, response bodies or source paths.
        print("Миграция завершилась ошибкой (%s)" % type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
