#!/usr/bin/env python3
"""Fetch exact-commit Compatibility and Device Trust certification matrices.

This helper is intentionally fail-closed. It only accepts successful workflow
runs for the requested commit and validates the downloaded public matrix before
release assembly. It never falls back to a previous successful run.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import zipfile

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"

SPECS = (
    ("compatibility", "compatibility.yml", "neverlauncher-compatibility-matrix-"),
    ("device-trust", "device-trust.yml", "neverlauncher-device-trust-matrix-"),
)


class GitHubAPI:
    def __init__(self, token: str) -> None:
        token = token.strip()
        if not token:
            raise ValueError("GitHub token is required")
        self.token = token

    def _request(self, url: str) -> bytes:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "NeverLauncher-release-certification-fetch/0.16.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API HTTP {exc.code} for {url}: {body[:500]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API request failed for {url}: {exc}") from exc

    def json(self, path_or_url: str) -> dict[str, Any]:
        url = path_or_url if path_or_url.startswith("https://") else API_ROOT + path_or_url
        raw = self._request(url)
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"GitHub API returned invalid JSON for {url}") from exc
        if not isinstance(doc, dict):
            raise RuntimeError(f"GitHub API returned non-object JSON for {url}")
        return doc

    def bytes(self, url: str) -> bytes:
        return self._request(url)


def select_exact_run(runs: list[dict[str, Any]], commit: str) -> dict[str, Any] | None:
    exact = [r for r in runs if str(r.get("head_sha", "")).lower() == commit.lower()]
    if not exact:
        return None
    # GitHub may expose re-runs for the same SHA. Prefer the newest run so a
    # stale failed attempt can never mask a newer exact-commit retry.
    exact.sort(key=lambda r: (str(r.get("created_at", "")), int(r.get("id", 0))), reverse=True)
    return exact[0]


def validate_matrix_document(doc: dict[str, Any], *, repository: str, commit: str, version: str, run_id: int, label: str) -> None:
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
                raise RuntimeError(f"{label} matrix {key} mismatch: expected={value} actual={actual}")
        elif str(actual) != str(value):
            raise RuntimeError(f"{label} matrix {key} mismatch: expected={value} actual={actual}")
    targets = doc.get("targets")
    if not isinstance(targets, list) or not targets:
        raise RuntimeError(f"{label} matrix contains no certified targets")
    if doc.get("errors") not in ([], None):
        raise RuntimeError(f"{label} matrix contains errors: {doc.get('errors')!r}")


def matrix_from_zip(raw: bytes, *, label: str) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            candidates = [n for n in archive.namelist() if n == "matrix.json" or n.endswith("/matrix.json")]
            if len(candidates) != 1:
                raise RuntimeError(f"{label} artifact must contain exactly one matrix.json, found {candidates}")
            data = archive.read(candidates[0])
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"{label} artifact is not a valid ZIP") from exc
    if len(data) > 4 * 1024 * 1024:
        raise RuntimeError(f"{label} matrix.json is unexpectedly large")
    return data


def workflow_runs(api: GitHubAPI, repository: str, workflow: str, commit: str) -> list[dict[str, Any]]:
    repo = urllib.parse.quote(repository, safe="/")
    wf = urllib.parse.quote(workflow, safe="")
    q = urllib.parse.urlencode({"head_sha": commit, "event": "push", "per_page": 20})
    doc = api.json(f"/repos/{repo}/actions/workflows/{wf}/runs?{q}")
    runs = doc.get("workflow_runs")
    if not isinstance(runs, list):
        raise RuntimeError(f"workflow run response for {workflow} is malformed")
    return [r for r in runs if isinstance(r, dict)]


def fetch_matrix(api: GitHubAPI, *, repository: str, commit: str, version: str, label: str, workflow: str, artifact_prefix: str, output: Path) -> bool:
    run = select_exact_run(workflow_runs(api, repository, workflow, commit), commit)
    if run is None:
        print(f"[release-certification] {label}: exact-commit workflow run not visible yet", flush=True)
        return False
    status = str(run.get("status", ""))
    conclusion = run.get("conclusion")
    run_id = int(run.get("id", 0))
    if run_id <= 0:
        raise RuntimeError(f"{label} exact-commit workflow run has invalid id")
    if status != "completed":
        print(f"[release-certification] {label}: run {run_id} status={status}; waiting", flush=True)
        return False
    if conclusion != "success":
        raise RuntimeError(f"{label} exact-commit workflow run {run_id} concluded {conclusion!r}, refusing release fallback")

    repo = urllib.parse.quote(repository, safe="/")
    artifacts_doc = api.json(f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = artifacts_doc.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError(f"{label} artifact response is malformed")
    expected_name = artifact_prefix + str(run_id)
    matches = [a for a in artifacts if isinstance(a, dict) and a.get("name") == expected_name and not a.get("expired", False)]
    if len(matches) != 1:
        raise RuntimeError(f"{label} exact-commit run {run_id} must expose exactly one {expected_name!r} artifact")
    archive_url = str(matches[0].get("archive_download_url", "")).strip()
    if not archive_url.startswith("https://api.github.com/"):
        raise RuntimeError(f"{label} artifact download URL is invalid")
    matrix_raw = matrix_from_zip(api.bytes(archive_url), label=label)
    try:
        matrix = json.loads(matrix_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} matrix.json is invalid JSON") from exc
    if not isinstance(matrix, dict):
        raise RuntimeError(f"{label} matrix.json must be an object")
    validate_matrix_document(matrix, repository=repository, commit=commit, version=version, run_id=run_id, label=label)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(matrix_raw)
    print(f"[release-certification] {label}: accepted exact commit {commit} from run {run_id}", flush=True)
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
        raise SystemExit("invalid --repository")
    if len(args.commit) not in (40, 64) or any(ch not in "0123456789abcdefABCDEF" for ch in args.commit):
        raise SystemExit("--commit must be an exact 40/64-hex source commit")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise SystemExit("--timeout-seconds must be between 1 and 3600")
    if args.poll_seconds < 1 or args.poll_seconds > 60:
        raise SystemExit("--poll-seconds must be between 1 and 60")

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
            raise RuntimeError(f"timed out waiting for exact-commit certifications: {', '.join(sorted(pending))}")
        time.sleep(args.poll_seconds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
