#!/usr/bin/env python3
"""Получить матрицы сертификации Compatibility и Device Trust для точного коммита.

Помощник намеренно блокирует при неопределённости. Он принимает только успешные workflow-запуски для
запрошенного коммита и до сборки выпуска проверяет загруженную публичную матрицу. Возврата к
предыдущему успешному запуску нет.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import io
import json
from pathlib import Path
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from certification_run import required as fresh_required

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
USER_AGENT = f"Launcher-release-certification-fetch/{PRODUCT_VERSION}"
ARTIFACT_REDIRECT_SUFFIXES = (
    ".blob.core.windows.net",
    ".githubusercontent.com",
    ".github.com",
)


def _artifact_redirect_request(
    req: urllib.request.Request, newurl: str
) -> urllib.request.Request:
    parsed = urllib.parse.urlparse(newurl)
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RuntimeError(f"URL перенаправления артефакта не является безопасным HTTPS-адресом: {newurl}")
    if not any(
        host.endswith(suffix) or host == suffix[1:]
        for suffix in ARTIFACT_REDIRECT_SUFFIXES
    ):
        raise RuntimeError(f"Хост перенаправления артефакта не является доверенным: {host}")
    # Никогда не пересылайте токен GitHub Bearer на хосты перенаправлений
    # подписанных артефактов.
    # Никогда не передавайте bearer-токен GitHub на подписанный источник артефакта. URL
    # перенаправления уже содержит собственные краткосрочные параметры авторизации.
    return urllib.request.Request(
        newurl,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )


class ArtifactRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if code not in (301, 302, 303, 307, 308):
            return None
        return _artifact_redirect_request(req, newurl)


SPECS = (
    ("compatibility", "compatibility.yml", "launcher-compatibility-matrix-"),
    ("device-trust", "device-trust.yml", "launcher-device-trust-matrix-"),
)


class GitHubAPI:
    def __init__(self, token: str) -> None:
        token = token.strip()
        if not token:
            raise ValueError("Требуется: «GitHub token»")
        self.token = token

    def _request(self, url: str) -> bytes:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API HTTP {exc.code} for {url}: {body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Запрос API GitHub для {url} завершился ошибкой: {exc}") from exc

    def json(self, path_or_url: str) -> dict[str, Any]:
        url = (
            path_or_url
            if path_or_url.startswith("https://")
            else API_ROOT + path_or_url
        )
        raw = self._request(url)
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"API GitHub вернул некорректный JSON для {url}") from exc
        if not isinstance(doc, dict):
            raise RuntimeError(f"API GitHub вернул JSON, не являющийся объектом, для {url}")
        return doc

    def bytes(self, url: str) -> bytes:
        if not url.startswith(API_ROOT + "/"):
            raise RuntimeError(
                "Загрузка артефактов должна начинаться с исходного адреса GitHub API"
            )
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        opener = urllib.request.build_opener(ArtifactRedirectHandler())
        try:
            with opener.open(req, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub artifact HTTP {exc.code} for {url}: {body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Ошибка запроса артефакта GitHub по адресу {url}: {exc}"
            ) from exc


def select_exact_run(runs: list[dict[str, Any]], commit: str) -> dict[str, Any] | None:
    exact = [r for r in runs if str(r.get("head_sha", "")).lower() == commit.lower()]
    if not exact:
        return None
    # GitHub может хранить повторные запуски для одного SHA. Выбирайте новейший,
    # чтобы устаревшая неудачная попытка не скрывала свежий повтор точного коммита.
    exact.sort(
        key=lambda r: (str(r.get("created_at", "")), int(r.get("id", 0))), reverse=True
    )
    return exact[0]


def validate_matrix_document(
    doc: dict[str, Any],
    *,
    repository: str,
    commit: str,
    version: str,
    run_id: int,
    label: str,
) -> None:
    expected = {
        "repository": repository,
        "commit": commit,
        "productVersion": version,
        "status": "passed",
        "runId": str(run_id),
    }
    for key, value in expected.items():
        actual = doc.get(key)
        if key == "commit":
            if str(actual).lower() != str(value).lower():
                raise RuntimeError(
                    f"{label} matrix {key}: несоответствие — expected={value} actual={actual}"
                )
        elif str(actual) != str(value):
            raise RuntimeError(
                f"{label} matrix {key}: несоответствие — expected={value} actual={actual}"
            )
    targets = doc.get("targets")
    if not isinstance(targets, list) or not targets:
        raise RuntimeError(f"Матрица {label} не содержит сертифицированных целевых платформ")
    if doc.get("errors") not in ([], None):
        raise RuntimeError(f"Матрица {label} содержит ошибки: {doc.get('errors')!r}")


def matrix_from_zip(raw: bytes, *, label: str) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            candidates = [
                n
                for n in archive.namelist()
                if n == "matrix.json" or n.endswith("/matrix.json")
            ]
            if len(candidates) != 1:
                raise RuntimeError(
                    f"Артефакт {label} должен содержать ровно один matrix.json; найдено: {candidates}"
                )
            data = archive.read(candidates[0])
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Артефакт {label} не является корректным ZIP-архивом") from exc
    if len(data) > 4 * 1024 * 1024:
        raise RuntimeError(f"Файл matrix.json для {label} неожиданно велик")
    return data


def workflow_runs(
    api: GitHubAPI, repository: str, workflow: str, commit: str
) -> list[dict[str, Any]]:
    repo = urllib.parse.quote(repository, safe="/")
    wf = urllib.parse.quote(workflow, safe="")
    q = urllib.parse.urlencode({"head_sha": commit, "event": "push", "per_page": 20})
    doc = api.json(f"/repos/{repo}/actions/workflows/{wf}/runs?{q}")
    runs = doc.get("workflow_runs")
    if not isinstance(runs, list):
        raise RuntimeError(f"Некорректный ответ о выполнении рабочего процесса {workflow}")
    return [r for r in runs if isinstance(r, dict)]


def fetch_matrix(
    api: GitHubAPI,
    *,
    repository: str,
    commit: str,
    version: str,
    label: str,
    workflow: str,
    artifact_prefix: str,
    output: Path,
) -> bool:
    run = select_exact_run(workflow_runs(api, repository, workflow, commit), commit)
    if run is None:
        print(
            f"[release-certification] {label}: Запуск процесса CI для точного коммита пока не обнаружен",
            flush=True,
        )
        return False
    status = str(run.get("status", ""))
    conclusion = run.get("conclusion")
    run_id = int(run.get("id", 0))
    if run_id <= 0:
        raise RuntimeError(f"У запуска рабочего процесса {label} для точного коммита некорректный ID")
    if status != "completed":
        print(
            f"[Сертификация релиза] {label}: запуск {run_id}, состояние={status}; ожидание",
            flush=True,
        )
        return False
    if conclusion != "success":
        raise RuntimeError(
            f"Рабочий процесс точного коммита {label} с запуском {run_id} завершился со статусом {conclusion!r}; резервная публикация запрещена"
        )
    if fresh_required(version):
        # Одного точного SHA недостаточно для актуальности: самый новый завершённый
        # прогон мог состояться недели назад. Использовать можно только недавно
        # выполненный прогон.
        started = str(run.get("run_started_at", ""))
        try:
            stamp = datetime.fromisoformat(started.replace("Z", "+00:00"))
            attempt = run.get("run_attempt")
            if not started.endswith("Z") or type(attempt) is not int or attempt < 1:
                raise ValueError("Отсутствует: «run attempt or UTC start time»")
        except (ValueError, TypeError) as exc:
            raise RuntimeError(f"У запуска {label} отсутствуют актуальные сведения о происхождении выполнения") from exc
        delta = datetime.now(timezone.utc) - stamp
        if not timedelta(0) <= delta <= timedelta(hours=24):
            raise RuntimeError(
                f"Запуск рабочего процесса для точного коммита {label} устарел; повторите проверку этого релиза"
            )

    repo = urllib.parse.quote(repository, safe="/")
    artifacts_doc = api.json(
        f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    artifacts = artifacts_doc.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError(f"Некорректный ответ об артефакте {label}")
    expected_name = artifact_prefix + str(run_id)
    matches = [
        a
        for a in artifacts
        if isinstance(a, dict)
        and a.get("name") == expected_name
        and not a.get("expired", False)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Запуск {run_id} для точного коммита {label} должен предоставить ровно один артефакт {expected_name!r}"
        )
    archive_url = str(matches[0].get("archive_download_url", "")).strip()
    if not archive_url.startswith("https://api.github.com/"):
        raise RuntimeError(f"Некорректный URL загрузки артефакта {label}")
    matrix_raw = matrix_from_zip(api.bytes(archive_url), label=label)
    try:
        matrix = json.loads(matrix_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Файл matrix.json для {label} содержит некорректный JSON") from exc
    if not isinstance(matrix, dict):
        raise RuntimeError(f"Файл matrix.json для {label} должен содержать объект")
    validate_matrix_document(
        matrix,
        repository=repository,
        commit=commit,
        version=version,
        run_id=run_id,
        label=label,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(matrix_raw)
    print(
        f"[release-certification] {label}: Принят точный коммит {commit} from run {run_id}",
        flush=True,
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--poll-seconds", type=int, default=15)
    args = parser.parse_args()

    if not args.repository or "/" not in args.repository:
        raise SystemExit("Некорректный параметр --repository")
    if len(args.commit) not in (40, 64) or any(
        ch not in "0123456789abcdefABCDEF" for ch in args.commit
    ):
        raise SystemExit("Параметр --commit должен содержать точный хеш коммита исходников из 40 или 64 шестнадцатеричных символов")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise SystemExit("Параметр --timeout-seconds должен иметь значение от 1 до 3600")
    if args.poll_seconds < 1 or args.poll_seconds > 60:
        raise SystemExit("Параметр --poll-seconds должен иметь значение от 1 до 60")

    api = GitHubAPI(args.token)
    outputs = {
        "compatibility": args.output_dir / "compatibility" / "matrix.json",
        "device-trust": args.output_dir / "device-trust" / "matrix.json",
    }
    for path in outputs.values():
        if path.exists():
            path.unlink()

    deadline = time.monotonic() + args.timeout_seconds
    pending = {label: (workflow, prefix) for label, workflow, prefix in SPECS}
    while pending:
        for label in list(pending):
            workflow, prefix = pending[label]
            if fetch_matrix(
                api,
                repository=args.repository,
                commit=args.commit,
                version=args.version,
                label=label,
                workflow=workflow,
                artifact_prefix=prefix,
                output=outputs[label],
            ):
                del pending[label]
        if not pending:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Превышено время ожидания сертификаций для точного коммита: {', '.join(sorted(pending))}"
            )
        time.sleep(args.poll_seconds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
