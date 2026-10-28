#!/usr/bin/env python3
"""Fail-closed GA release preflight using live Backend's trusted evaluator.

This is NOT a certificate or a substitute for the atomic PostgreSQL head gate.
Nothing on this CI worker can sign ValidationEvidence or grant publication.
"""
import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9_.:@+-]{1,160}$")
STAGES = frozenset(("manifest-files", "materialization", "startup", "loader-readiness",
                   "authentication", "server-readiness", "matching-server", "gameplay-smoke", "update-recovery"))


class Blocked(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def timestamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        raise Blocked("invalid expiry time") from None


def assess(package, validations, report, package_id, version, source_sha, now=None):
    """Checks independent API views. Fail closed on missing, stale or synthetic coverage."""
    now = now or datetime.now(timezone.utc)
    require(isinstance(package, dict) and package.get("packageId") == package_id, "wrong package ID")
    require(package.get("version") == version, "wrong release version")
    require(package.get("channel") == "stable", "not a stable release")
    require(package.get("status") == "integrity-passed", "release not staged with current integrity PASS")
    require(isinstance(validations, dict), "missing validation payload")
    integrity = validations.get("integrity")
    require(isinstance(integrity, dict) and integrity.get("result") == "passed", "integrity verification failed")
    policy = validations.get("effectivePolicy")
    require(isinstance(policy, dict) and policy.get("source") == "production-runtime-gate-0.34.11" and
            policy.get("requiredLevel") == "trusted-runtime", "not using trusted runtime evaluator")
    require(policy.get("sourceSha") == source_sha, "source commit differs from GA release")
    require(policy.get("publishEligible") is True, "Backend stable policy denies publication")
    require(isinstance(report, dict) and report.get("packageId") == package_id and
            report.get("manualCertificationAllowed") is False, "invalid audit report or manual certification")
    coverage = report.get("coverage")
    require(isinstance(coverage, dict) and coverage.get("stablePublishEligible") is True, "live audit gate ineligible")
    require(coverage.get("sourceSha") == source_sha, "audit source commit mismatch")
    matrix = policy.get("matrixSha256")
    require(isinstance(matrix, str) and SHA256.fullmatch(matrix) and coverage.get("matrixSha256") == matrix,
            "required target matrix changed or missing")
    count = policy.get("requiredTargets")
    require(type(count) is int and 0 < count <= 128 and policy.get("verifiedTargets") == count,
            "incomplete mandatory target count")
    require(coverage.get("required") == count and coverage.get("verified") == count,
            "live target counts differ")
    covered = policy.get("targetCoverage")
    require(isinstance(covered, dict) and len(covered) == count and
            all(ID.fullmatch(k) and v is True for k, v in covered.items()), "missing or failed target")
    require(coverage.get("targetCoverage") == covered, "report and validation target coverage differs")
    require(policy.get("targetBlockers") == {} and coverage.get("targetBlockers") == {}, "blocked targets remain")
    evidence = report.get("evidence")
    require(isinstance(evidence, list), "missing trusted evidence history")
    accepted = {}
    run_ids = set()
    for item in evidence:
        if not isinstance(item, dict) or item.get("status") != "signature-and-execution-verified":
            continue
        target_id = item.get("targetId")
        if target_id not in covered:
            continue
        run_id = item.get("runId")
        require(isinstance(run_id, str) and ID.fullmatch(run_id), "invalid trusted run ID")
        require(timestamp(item.get("expiresAt")) > now + timedelta(minutes=15), "evidence expires during GA release")
        require(run_id not in run_ids, "reused runtime attestation")
        run_ids.add(run_id)
        accepted.setdefault(target_id, []).append(run_id)
    require(set(accepted) == set(covered), "no fresh signed execution for every target")
    runs = report.get("runs")
    require(isinstance(runs, list), "no recorded runtime execution history")
    by_run = {r.get("runId"): r for r in runs if isinstance(r, dict)}
    for target, ids in accepted.items():
        require(any(all(isinstance(by_run.get(run), dict) and
                        isinstance(by_run[run].get("stages"), dict) and
                        stage in by_run[run]["stages"] and
                        by_run[run]["stages"][stage].get("status") == "passed"
                        for stage in STAGES) for run in ids),
                "runtime stages missing for " + target)
    return {"schemaVersion": "neverlauncher.ga-runtime-preflight.v1", "status": "backend-eligible-not-published",
            "packageId": package_id, "productVersion": version, "sourceSha": source_sha,
            "matrixSha256": matrix, "verifiedTargets": count,
            "note": "This read-only snapshot does not authorize publishing; PostgreSQL rechecks at commit."}


def get_json(backend, endpoint, bearer):
    req = Request(backend.rstrip("/") + endpoint,
                  headers={"Authorization": "Bearer " + bearer, "Accept": "application/json",
                           "Cache-Control": "no-cache"}, method="GET")
    class RejectRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise Blocked("Backend redirect rejected; access token cannot leave pinned origin")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), RejectRedirect())
    with opener.open(req, timeout=30) as response:
        require(response.status == 200, "Backend returned non-200")
        raw = response.read((16 << 20) + 1)
    require(len(raw) <= (16 << 20), "Backend report too large")
    data = json.loads(raw)
    require(isinstance(data, dict) and isinstance(data.get("data"), dict), "missing Backend data")
    return data["data"]


def supported_runtime_release(version: str) -> bool:
    """The trusted runtime gate is mandatory for ALL releases after 0.35.0.

    Historical fixtures remain valid for 0.35.0, while the current protected
    evaluator must recheck the *actual* staged version and commit every time.
    """
    matched = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version)
    return matched is not None and tuple(map(int, matched.groups())) >= (0, 35, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        require(ID.fullmatch(args.package_id), "invalid package ID")
        require(SOURCE.fullmatch(args.source_sha), "invalid source SHA")
        require(supported_runtime_release(args.version), "release predates the protected runtime gate or has invalid version")
        url = urlsplit(args.backend)
        require(url.scheme == "https" and bool(url.hostname) and not url.username and not url.password and
                not url.query and not url.fragment and not url.path.rstrip("/"), "Backend must use a HTTPS origin")
        token = os.environ.get("NL_GA_OPERATOR_TOKEN", "").strip()
        require(bool(token) and "\n" not in token and "\r" not in token, "missing protected read token")
        base = "/api/v1/packages/" + quote(args.package_id, safe="")
        pkg = get_json(args.backend, base, token)
        validations = get_json(args.backend, base + "/validations", token)
        report = get_json(args.backend, base + "/validation-report", token)
        decision = assess(pkg, validations, report, args.package_id, args.version, args.source_sha)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("GA runtime preflight: eligible for atomic Backend validation (not certified by CI)")
        return 0
    except (Blocked, OSError, ValueError, json.JSONDecodeError) as ex:
        print("GA runtime preflight BLOCKED: " + str(ex), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
