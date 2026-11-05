#!/usr/bin/env python3
"""Execute the final Gravit migration acceptance against *live* external systems.

Never executes Gravit JARs. The existing Go Migration GA verifier must validate
signed 36-check evidence and re-query PostgreSQL-backed Backend; then all 19
approved module behavior probes run as real, hash-pinned executables. This tool
cannot manufacture Minecraft sessions, signed installers or reviewer approval.
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
    require(path.is_absolute(), "absolute path required")
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
                "missing, linked, special or oversized file: " + str(path))
        if private:
            require(info.st_mode & 0o077 == 0, "private file permissions required: " + str(path))
        with path.open("rb") as f:
            data = f.read(limit + 1)
            require(len(data) == info.st_size, "file changed during reading: " + str(path))
            require(os.fstat(f.fileno()).st_ino == info.st_ino, "file replaced during reading")
        return data
    except OSError as exc:
        raise Blocked("cannot read " + str(path)) from exc


def doc(path: Path, *, private: bool = False) -> dict:
    try:
        value = json.loads(regular(path, private=private))
    except (ValueError, UnicodeError) as exc:
        raise Blocked("Некорректное значение: «JSON:»" + str(path)) from exc
    require(type(value) is dict, "JSON object required: " + str(path))
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path, limit: int = 1 << 30) -> str:
    require(path.is_absolute(), "absolute checked path required")
    try:
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
                "unsafe checked file " + str(path))
        h = hashlib.sha256()
        with path.open("rb") as f:
            require(os.fstat(f.fileno()).st_ino == st.st_ino, "checked file replaced")
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
            end = os.fstat(f.fileno())
            require(end.st_size == st.st_size and end.st_mtime_ns == st.st_mtime_ns,
                    "checked file changed during read")
        return h.hexdigest()
    except OSError as exc:
        raise Blocked("cannot hash " + str(path)) from exc


def pinned(path: str, expected: str, *, executable: bool = False) -> Path:
    require(isinstance(path, str) and path.startswith("/") and isinstance(expected, str)
            and HEX.fullmatch(expected) is not None, "absolute pinned path and SHA-256 required")
    result = Path(path)
    require(sha(result, 128 << 20 if executable else 1 << 30) == expected,
            "pinned file SHA-256 mismatch: " + path)
    if executable:
        require(result.lstat().st_mode & 0o111 != 0, "probe must be executable")
    return result


def execute(argv: list[str], *, timeout: int, env: dict[str, str], max_out: int = MAX_JSON) -> bytes:
    try:
        run = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout, env=env, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise Blocked("live command failed: " + Path(argv[0]).name) from exc
    require(0 < len(run.stdout) <= max_out, "missing or unbounded live command output")
    return run.stdout


def clean_env() -> dict[str, str]:
    # Module probes must receive no Backend bearer, signing key or database DSN.
    forbidden = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE", "SIGNING", "DSN", "KEY", "CREDENTIAL", "AUTH")
    return {k: v for k, v in os.environ.items()
            if not any(x in k.upper() for x in forbidden) and k not in ("PYTHONPATH", "PYTHONHOME")}


def check_migration(cfg: dict, cohort: dict) -> tuple[dict, str, str]:
    cases = cohort.get("cases")
    require(cohort.get("format") == rehearsal.FORMAT and
            cohort.get("status") == "isolated-stage-pass-not-production-GA" and
            cohort.get("productionGA") is False and isinstance(cases, list) and len(cases) == 3,
            "three actual pre/post update project witnesses required")
    root = Path(cfg["rehearsalRoot"])
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "real rehearsal directory required")
    refs = cfg.get("references")
    require(type(refs) is dict and set(refs) == set(CLASSES), "three migration reference inputs required")
    require(set(x.get("referenceClass") for x in cases if type(x) is dict) == set(CLASSES),
            "duplicate or missing rehearsal classes")
    plans = {}
    commit = None
    target = None
    for item in cases:
        cls = item["referenceClass"]
        ref = refs[cls]
        require(type(ref) is dict and set(ref) == {"plan", "certificate", "evidenceDir"},
                "exact live migration evidence locations required")
        plan = doc(Path(ref["plan"]), private=True)
        cert = doc(Path(ref["certificate"]), private=True)
        require(plan.get("referenceClass") == cls and cert.get("referenceClass") == cls
                and plan.get("runId") == item.get("runId") == cert.get("runId")
                and plan.get("projectId") == item.get("projectId") == cert.get("projectId")
                and item.get("sourceSha256") == cert.get("sourceSha256"),
                "signed GA certificate and actual migrated project differ: " + cls)
        require(isinstance(plan.get("sourceArchive"), str)
                and sha(Path(plan["sourceArchive"])) == item["sourceSha256"],
                "original Gravit source changed: " + cls)
        if commit is None:
            commit, target = cert.get("commitSha"), cert.get("targetReleaseSha256")
        require(cert.get("commitSha") == commit and cert.get("targetReleaseSha256") == target,
                "independent projects must use the same final release commit/digest")
        require(isinstance(item.get("installedBeforeSha256"), str)
                and HEX.fullmatch(item["installedBeforeSha256"]) and
                isinstance(item.get("installedAfterSha256"), str)
                and HEX.fullmatch(item["installedAfterSha256"]) and
                item["installedBeforeSha256"] != item["installedAfterSha256"],
                "client was not updated for " + cls)
        for step, field, expected in (("pre-update-live", "preUpdateWitnessSha256", "installedBeforeSha256"),
                                      ("post-update-live", "postUpdateWitnessSha256", "installedAfterSha256")):
            witness = root / cls / (step + ".json")
            require(sha(witness, MAX_JSON) == item.get(field), "game witness changed: " + step)
            w = doc(witness)
            data = w.get("data", w)
            require(type(data) is dict and data.get("runId") == item["runId"],
                    "witness run differs from certified project")
            live = data.get("liveSession")
            require(type(live) is dict and live.get("clientSha256") == item[expected]
                    and isinstance(live.get("joinedAt"), str) and bool(live["joinedAt"])
                    and bool(live.get("playerUuid")), "missing real client/UUID game witness")
            probes = data.get("probes")
            require(type(probes) is list and len(probes) == len(rehearsal.PROBES)
                    and [p.get("name") for p in probes if type(p) is dict] == list(rehearsal.PROBES)
                    and all(p.get("passed") is True and type(p.get("evidenceSha256")) is str
                            and HEX.fullmatch(p["evidenceSha256"]) for p in probes),
                    "game checks absent or not passed")
            if step == "pre-update-live":
                old_player = live["playerUuid"]
                require(data.get("ready") is True and data.get("blockers") == [],
                        "pre-update rehearsal was not approved by Backend")
            else:
                require(live["playerUuid"] == old_player and data.get("ready") is False,
                        "post-update UUID changed or local witness forged backend readiness")
        update = doc(root / cls / "signed-update.json")
        require(update.get("status") == "committed" and
                update.get("packageSha256") == item.get("updatePackageSha256"),
                "signed client update was not committed")
        plans[cls] = ref
    require(isinstance(commit, str) and len(commit) in (40, 64)
            and isinstance(target, str) and HEX.fullmatch(target), "invalid release identity")
    return plans, commit, target


def live_certificate_verification(cfg: dict, refs: dict) -> None:
    checker = pinned(cfg["checker"], cfg["checkerSha256"], executable=True)
    trusted = Path(cfg["trustedPublicKey"])
    require(trusted.is_absolute() and regular(trusted, 65536), "trusted independent public key required")
    argv = [str(checker), "verify-cohort-live", "--public-key", str(trusted)]
    for cls in CLASSES:
        ref = refs[cls]
        e = Path(ref["evidenceDir"])
        require(e.is_absolute() and e.is_dir() and not e.is_symlink(),
                "retained signed private evidence unavailable")
        argv += ["--" + cls + "-plan", ref["plan"], "--" + cls, ref["certificate"],
                 "--" + cls + "-evidence", str(e)]
    require(bool(os.environ.get("LAUNCHER_MIGRATION_GA_TOKEN", "").strip()),
            "live Backend verification requires a short-lived administrator token")
    execute(argv, timeout=180, env=os.environ.copy(), max_out=65536)
    require(sha(checker, 128 << 20) == cfg["checkerSha256"],
            "Migration GA verifier changed during live attestation")


def check_modules(cfg: dict, refs: dict, output: Path) -> list[dict]:
    modules = cfg.get("modules")
    require(type(modules) is dict and set(modules) == set(MODULE_IDS),
            "19 real Gravit module parity checks required, including unsafe-command alternative")
    result = []
    for module in MODULE_IDS:
        probe = modules[module]
        require(type(probe) is dict and set(probe) == {"referenceClass", "executable", "executableSha256", "args", "timeoutSeconds"},
                "module requires a bounded pinned executable and exact test")
        cls = probe["referenceClass"]
        require(cls in CLASSES and type(probe["args"]) is list and
                all(type(x) is str and len(x) <= 1024 for x in probe["args"]),
                "invalid module reference or command")
        seconds = probe["timeoutSeconds"]
        require(type(seconds) is int and 1 <= seconds <= 900, "module test timeout out of bounds")
        exe = pinned(probe["executable"], probe["executableSha256"], executable=True)
        case = doc(Path(refs[cls]["certificate"]), private=True)
        started = time.time()
        stdout = execute([str(exe), *probe["args"]], timeout=seconds, env=clean_env())
        require(sha(exe, 128 << 20) == probe["executableSha256"],
                "module test executable changed during execution")
        try:
            observation = json.loads(stdout)
        except (ValueError, UnicodeError) as exc:
            raise Blocked("Некорректное значение: «module output:»" + module) from exc
        require(type(observation) is dict and observation.get("moduleId") == module
                and observation.get("runId") == case["runId"]
                and observation.get("projectId") == case["projectId"]
                and observation.get("sourceSha256") == case["sourceSha256"]
                and observation.get("passed") is True,
                "module did not pass actual certified project test: " + module)
        events = observation.get("observations")
        require(type(events) is list and len(events) >= 2 and
                all(type(x) is str and 1 <= len(x) <= 256 for x in events),
                "module did not provide multiple behavioral observations: " + module)
        file = observation.get("evidenceFile")
        eh = observation.get("evidenceSha256")
        require(type(file) is str and file.startswith("/") and type(eh) is str and
                HEX.fullmatch(eh) and sha(Path(file), 128 << 20) == eh,
                "real module evidence absent or changed: " + module)
        evidence = Path(file)
        require(evidence.lstat().st_mtime >= started - 2,
                "module evidence was not generated by current run: " + module)
        result.append({"moduleId": module, "referenceClass": cls, "executableSha256": probe["executableSha256"],
                       "evidenceSha256": eh, "observationSha256": digest(stdout), "observations": events})
        # Preserve raw evidence privately, not only its checksum. No overwrite.
        dest = output / (module + ".evidence")
        with evidence.open("rb") as source, dest.open("xb") as target:
            os.chmod(dest, 0o600)
            shutil.copyfileobj(source, target, 1 << 20)
            target.flush()
            os.fsync(target.fileno())
        require(sha(dest, 128 << 20) == eh, "preserved module evidence differs from executed check")
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
        "checker", "checkerSha256", "trustedPublicKey"}, "invalid full acceptance configuration")
    require(output.is_absolute() and output.is_dir() and not output.is_symlink()
            and output.stat().st_mode & 0o077 == 0 and not list(output.iterdir()),
            "evidence output must be a new empty private 0700 directory")
    cohort = doc(Path(cfg["rehearsalReport"]), private=True)
    refs, commit, release = check_migration(cfg, cohort)
    # Go checker uses the real TLS Backend and verifies ALL 36 signed E2E probes,
    # their preserved raw evidence, active PostgreSQL route and distinct projects.
    live_certificate_verification(cfg, refs)
    tests = check_modules(cfg, refs, output)
    # After untrusted module probes, re-query the Backend again: a revoked or
    # rolled-back release cannot be approved based on the earlier live read.
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
        print("LIVE CHECKS PASSED (not GA approval):", result["migrationChecks"],
              "migration E2E and", result["moduleCheckCount"], "module checks")
        return 0
    except (Blocked, OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
