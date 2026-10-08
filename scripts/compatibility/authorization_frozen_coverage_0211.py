#!/usr/bin/env python3
"""NeverLauncher 0.21.1 authorization/frozen-coverage release gate.

This gate is intentionally executable rather than documentation-only. It seals the
security-sensitive source files, checks the G01-G35/M01-M19 evidence registry,
asserts authorization invariants in the shipping router/repository code, and can
verify the pinned Gravit v5.7.12 -> v5.7.13 upstream delta directly against GitHub.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "compatibility/gravit/authorization-coverage-0211.json"
ALLOWED_LEVELS = {
    "source-reviewed",
    "contract-tested",
    "unit-tested",
    "integration-tested",
    "runtime-tested",
    "cross-platform-certified",
}
ALLOWED_STATUSES = {"implemented", "partial", "gap", "not-applicable"}


def load() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(message: str) -> None:
    raise SystemExit("authorization/frozen-coverage 0.21.1: " + message)


def check_exists(ref: str, field: str, req_id: str) -> None:
    path = ROOT / ref
    if not path.is_file():
        fail(f"{req_id} {field} does not exist: {ref}")


def validate_registry(doc: dict) -> None:
    if doc.get("schemaVersion") != "1.0" or doc.get("productVersion") != "0.21.1":
        fail("lock schema/product version mismatch")
    try:
        version = tuple(int(x) for x in (ROOT / "VERSION").read_text(encoding="utf-8").strip().split('.')[:3])
    except ValueError:
        fail("VERSION is not semantic version")
    if version < (0, 21, 1):
        fail("VERSION must be 0.21.1 or newer")

    expected = [f"G{i:02d}" for i in range(1, 36)] + [f"M{i:02d}" for i in range(1, 20)]
    rows = doc.get("requirements") or []
    ids = [row.get("id") for row in rows]
    if ids != expected:
        fail("requirement registry must contain ordered G01-G35 and M01-M19 exactly once")

    for row in rows:
        req_id = row["id"]
        if not str(row.get("name", "")).strip() or not str(row.get("owner", "")).strip():
            fail(f"{req_id} is missing name/owner")
        level = row.get("verificationLevel")
        if level not in ALLOWED_LEVELS:
            fail(f"{req_id} has invalid verificationLevel {level!r}")
        status = row.get("status")
        if status not in ALLOWED_STATUSES:
            fail(f"{req_id} has invalid status {status!r}")
        component = str(row.get("upstreamComponent", "")).strip()
        components = doc.get("upstream", {}).get("components", {})
        if component not in components:
            fail(f"{req_id} references unknown upstreamComponent {component!r}")
        impl = row.get("implementationRefs") or []
        tests = row.get("testRefs") or []
        upstream = row.get("upstreamRefs") or []
        if not upstream:
            fail(f"{req_id} must have upstream source evidence")
        if status in {"implemented", "partial"} and (not impl or not tests):
            fail(f"{req_id} {status} coverage requires implementation and test evidence")
        if status in {"partial", "gap", "not-applicable"} and not str(row.get("gapReason", "")).strip():
            fail(f"{req_id} {status} coverage requires an explicit gapReason")
        if status in {"gap", "not-applicable"} and level != "source-reviewed":
            fail(f"{req_id} {status} coverage may only claim source-reviewed verification")
        for ref in impl:
            check_exists(ref, "implementationRef", req_id)
        for ref in tests:
            check_exists(ref, "testRef", req_id)


def validate_authorization_invariants() -> None:
    auth = (ROOT / "services/api/internal/httpapi/auth.go").read_text(encoding="utf-8")
    all_http = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "services/api/internal/httpapi").glob("*.go"))
    routes_projects = (ROOT / "services/api/internal/httpapi/routes_projects.go").read_text(encoding="utf-8")
    routes_packages = (ROOT / "services/api/internal/httpapi/routes_packages.go").read_text(encoding="utf-8")
    routes_auth = (ROOT / "services/api/internal/httpapi/routes_auth.go").read_text(encoding="utf-8")
    repo = (ROOT / "services/api/internal/repository/postgres.go").read_text(encoding="utf-8")
    migration = (ROOT / "services/api/internal/dbmigrate/sql/0050_authorization_scopes_identity_0211.sql").read_text(encoding="utf-8")
    cli_migration = (ROOT / "cli/internal/dbmigrate/sql/0050_authorization_scopes_identity_0211.sql").read_text(encoding="utf-8")
    minecraft = (ROOT / "services/api/internal/httpapi/minecraft_auth_119.go").read_text(encoding="utf-8")
    installer = (ROOT / "services/api/internal/httpapi/installation.go").read_text(encoding="utf-8")

    # JWT permissions may remain as compatibility output only; request authorization
    # must never call authClaims.HasPermission directly.
    matches = re.findall(r"\.HasPermission\(", all_http)
    if matches:
        fail("HTTP handlers still authorize from JWT claims.HasPermission")
    if "authorizationService().Authorize" not in auth or "requireProjectPermission" not in auth or "requirePackagePermission" not in auth:
        fail("live AuthorizationService middleware is not wired")

    required_project_routes = [
        'PATCH /api/v1/admin/projects/{projectId}", s.requireProjectPermission("project:write"',
        'POST /api/v1/admin/projects/{projectId}/profiles", s.requireProjectPermission("project:write"',
        'PATCH /api/v1/admin/projects/{projectId}/profiles/{profileId}", s.requireProjectPermission("project:write"',
        'POST /api/v1/admin/projects/{projectId}/channels", s.requireProjectPermission("project:write"',
    ]
    for needle in required_project_routes:
        if needle not in routes_projects:
            fail(f"project router lost scoped authorization: {needle}")

    required_package_routes = [
        'GET /api/v1/packages/{packageId}", s.requirePackagePermission("project:read"',
        'POST /api/v1/packages/{packageId}/files", s.requirePackagePermission("file:write"',
        'POST /api/v1/packages/{packageId}/validate", s.requirePackagePermission("release:prepare"',
        'POST /api/v1/packages/{packageId}/publish", s.requirePackageFreshAuth117("release:publish"',
        'POST /api/v1/admin/projects/import", s.requireAuthenticated',
    ]
    for needle in required_package_routes:
        if needle not in routes_packages:
            fail(f"package router lost scoped/payload authorization: {needle}")

    if 'requirePermission("project:read", s.authPasskey' in routes_auth or 'requirePermission("project:read", s.v1Auth' in routes_auth:
        fail("identity self-service is incorrectly coupled to global project permission")

    for needle in [
        "SELECT project_id, role_id FROM project_user_roles WHERE user_id=$1",
        "DELETE FROM project_user_roles WHERE user_id=$1",
        "INSERT INTO project_user_roles(project_id,user_id,role_id,created_at,updated_at)",
    ]:
        if needle not in repo:
            fail(f"repository no longer uses authoritative project_user_roles: {needle}")

    for needle in [
        "users_global_role_fk",
        "project_user_roles_project_fk",
        "project_user_roles_user_fk",
        "project_user_roles_role_fk",
        "project_user_roles_project_not_wildcard",
        "nl_sync_user_project_roles_0211",
    ]:
        if needle not in migration or needle not in cli_migration:
            fail(f"API/CLI migration missing authorization invariant {needle}")
    if migration != cli_migration:
        fail("API and CLI 0050 migrations differ")

    if 'map[string]string{"*": "owner"}' in installer:
        fail("installer still creates wildcard project authority")
    if "minecraftUUID119(userID" in minecraft or "newMinecraftProfileUUID119" not in minecraft or 'IdentityVersion: "independent-v1"' not in minecraft:
        fail("new GameProfile identities are not independent from internal user IDs")


def validate_hashes(doc: dict) -> None:
    sealed = doc.get("sealedFiles") or {}
    if not sealed:
        fail("sealedFiles is empty")
    for rel, expected in sorted(sealed.items()):
        path = ROOT / rel
        if not path.is_file():
            fail(f"sealed file missing: {rel}")
        actual = sha256_file(path)
        if actual != expected:
            fail(f"sealed source drift: {rel}: lock={expected} actual={actual}; run seal only after review")


def github_json(url: str) -> object:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "NeverLauncher-0.21.1-coverage-gate"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except Exception as exc:  # noqa: BLE001 - gate should report remote failure exactly
        fail(f"upstream verification failed for {url}: {exc}")


def validate_upstream(doc: dict) -> None:
    component_locks = doc.get("upstream", {}).get("components", {})
    if not component_locks:
        fail("upstream component source locks are missing")
    trees: dict[str, set[str]] = {}
    for component, lock in component_locks.items():
        repo = str(lock.get("repository", "")).strip()
        commit = str(lock.get("commit", "")).strip()
        if not repo or not re.fullmatch(r"[0-9a-f]{40}", commit):
            fail(f"invalid source lock for {component}")
        commit_doc = github_json(f"https://api.github.com/repos/{repo}/commits/{commit}")
        if commit_doc.get("sha") != commit:
            fail(f"upstream component commit mismatch for {component}")
        tree_sha = ((commit_doc.get("commit") or {}).get("tree") or {}).get("sha")
        if not tree_sha:
            fail(f"upstream component tree missing for {component}")
        tree_doc = github_json(f"https://api.github.com/repos/{repo}/git/trees/{tree_sha}?recursive=1")
        if tree_doc.get("truncated"):
            fail(f"upstream component tree is truncated for {component}")
        trees[component] = {str(item.get("path", "")) for item in (tree_doc.get("tree") or [])}

    for row in doc.get("requirements") or []:
        component = row["upstreamComponent"]
        paths = trees[component]
        for ref in row.get("upstreamRefs") or []:
            if ref not in paths:
                fail(f"{row['id']} upstream source ref is absent from locked {component}: {ref}")

    upstream = doc.get("upstream", {}).get("gravitLauncher", {})
    repo = upstream.get("repository")
    base = upstream.get("base") or {}
    target = upstream.get("target") or {}
    delta = upstream.get("delta") or {}
    if repo != "GravitLauncher/Launcher":
        fail("unexpected Gravit repository")
    for label, ref in (("base", base), ("target", target)):
        tag, expected_sha = ref.get("tag"), ref.get("commit")
        data = github_json(f"https://api.github.com/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
        actual = ((data or {}).get("object") or {}).get("sha")
        if actual != expected_sha:
            fail(f"Gravit {label} tag moved: {tag} lock={expected_sha} remote={actual}")

    compare = github_json(f"https://api.github.com/repos/{repo}/compare/{base['tag']}...{target['tag']}")
    checks = {
        "aheadBy": compare.get("ahead_by"),
        "totalCommits": compare.get("total_commits"),
        "fileCount": len(compare.get("files") or []),
        "additions": sum(int(f.get("additions") or 0) for f in compare.get("files") or []),
        "deletions": sum(int(f.get("deletions") or 0) for f in compare.get("files") or []),
    }
    for key, actual in checks.items():
        if actual != delta.get(key):
            fail(f"Gravit delta drift for {key}: lock={delta.get(key)} remote={actual}")

    for anchor in upstream.get("anchors") or []:
        path = anchor["path"]
        url = "https://api.github.com/repos/%s/contents/%s?ref=%s" % (
            repo,
            urllib.parse.quote(path, safe="/"),
            urllib.parse.quote(target["tag"], safe=""),
        )
        data = github_json(url)
        if data.get("sha") != anchor.get("blobSha"):
            fail(f"Gravit anchor drift: {path}")


def seal(doc: dict) -> None:
    files = doc.get("sealPaths") or []
    if not files:
        fail("sealPaths is empty")
    hashes = {}
    for rel in files:
        path = ROOT / rel
        if not path.is_file():
            fail(f"cannot seal missing file {rel}")
        hashes[rel] = sha256_file(path)
    doc["sealedFiles"] = hashes
    LOCK.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"sealed {len(hashes)} security-sensitive files")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p_validate = sub.add_parser("validate")
    p_validate.add_argument("--online", action="store_true", help="also verify immutable Gravit refs/delta against GitHub")
    sub.add_parser("seal")
    args = parser.parse_args()

    doc = load()
    validate_registry(doc)
    validate_authorization_invariants()
    if args.command == "seal":
        seal(doc)
        doc = load()
    validate_hashes(doc)
    if args.command == "validate" and args.online:
        validate_upstream(doc)
    print("NeverLauncher 0.21.1 authorization/frozen coverage: PASS")


if __name__ == "__main__":
    main()
