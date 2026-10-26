#!/usr/bin/env python3
"""NeverLauncher 0.31.14 adversarial test executor and evidence gate.

Runs real Go test executables (never parses source text as proof of success).
A skipped/absent required test, unsupported runtime or failing command is BLOCKED
or FAIL, never PASS. The release gate requires separate live-platform evidence.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "services/api"
OFFLINE = {
    "./internal/attestverify": ["TestAdversarialCertifyReplayAndCrossBinding03114", "TestAdversarialQuotePCRAndPolicyReplay03114", "TestRealTPMCertifyChainAndExactDevice0312", "TestQuote0315ValidAndAdversarial"],
    "./internal/extensionpolicy": ["TestAdversarialSignedPolicyEscalation03114", "TestSignedPolicy0318OwnerReview", "TestSignedPolicy0318FailClosedRuntime"],
    "./internal/extensionbroker": ["TestAdversarialBrokerPathBoundary03114", "TestAdversarialBrokerAtomicConcurrentWriters03114", "TestAdversarialBrokerSymlinkSwap03114", "TestScopedFilesystemBrokers03110", "TestSignedOutboundOrigin03110"],
    "./internal/extensionhost": ["TestAdversarialHostReconnectAndBurst03114", "TestAdversarialHostQuotaFailsClosed03114", "TestScopedBrokerCapabilities03110", "TestHostBudget03113RateAndOutput"],
    "./internal/trustbaseline": ["TestLegacyHardwareClaimCannotGrantStrict0311", "TestStandardRequiresVerifiedBinding0311", "TestMacOSSecureEnclaveLabelsNeverGrantRemoteProvenance0316"],
    "./internal/linuxsandbox": ["TestPolicyGateAndHostPaths0319", "TestConfigFDIsSealedAndNotOnFilesystem0319", "TestUnsupportedKernelOrMissingDelegationFailsClosed0319"],
    "./internal/macossandbox": ["TestValidateGrants", "TestPathContainment"],
}
BACKEND_SECURITY = {"./internal/httpapi": ["TestRuntimePolicy0317NormalizationAndValidation", "TestRuntimePolicy0317RejectsMissingOrMalformedAllowlist", "TestGuardRuntime0317MinecraftSessionBinding", "TestRuntimePolicy0317AdditionalHashPinning"]}
LINUX_LIVE = {"./internal/linuxsandbox": ["TestLinuxIsolationLive0319", "TestLinuxAdversarialDescendants03114"]}
WINDOWS_LIVE = {"./internal/windowssandbox": ["TestRealWindowsAppContainerAndJob03111"]}


def source_fingerprint():
    sha = hashlib.sha256()
    paths = [ROOT / "VERSION", ROOT / "scripts/security/certify_03114.py"]
    for sub in ["services/api/internal/attestverify", "services/api/internal/httpapi", "services/api/internal/trustbaseline", "services/api/internal/extensionpolicy", "services/api/internal/extensionbroker", "services/api/internal/extensionhost", "services/api/internal/linuxsandbox", "services/api/internal/windowssandbox", "services/api/internal/macossandbox"]:
        paths.extend(x for x in (ROOT / sub).rglob("*") if x.is_file())
    for path in sorted(set(paths)):
        sha.update(str(path.relative_to(ROOT)).encode() + b"\x00")
        sha.update(hashlib.sha256(path.read_bytes()).digest())
    return sha.hexdigest()


def run_test(package, required, env):
    cmd = ["go", "test", "-tags", "neverlauncher_nopgx", "-race", "-count=1", "-json", package]
    try:
        p = subprocess.run(cmd, cwd=API, env=env, capture_output=True, text=True, timeout=240)
    except (FileNotFoundError, subprocess.TimeoutExpired) as ex:
        return {"package": package, "command":cmd, "status":"BLOCKED", "error":str(ex), "required":required}
    outcomes = {}
    for line in p.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = event.get("Test")
        if name and "/" not in name and event.get("Action") in ("pass", "fail", "skip"):
            outcomes[name] = event["Action"].upper()
    missing = [name for name in required if name not in outcomes]
    failures = [name for name in required if outcomes.get(name) == "FAIL"]
    skipped = [name for name in required if outcomes.get(name) == "SKIP"]
    status = "FAIL" if failures or (p.returncode and outcomes) else "BLOCKED" if p.returncode or missing or skipped else "PASS"
    return {"package":package,"command":cmd,"status":status,"exitCode":p.returncode,"required":{name:outcomes.get(name,"ABSENT") for name in required},"stderr":p.stderr[-3000:],"failureOutput":p.stdout[-9000:] if status != "PASS" else ""}


def run_tier(tier):
    if tier == "offline":
        specs = OFFLINE
        env = os.environ.copy()
        if platform.system() != "Linux":
            # The Linux fd-relative broker is platform-specific. The offline
            # tier here is intentionally Linux-only, not a portable pass.
            return [{"status":"BLOCKED","error":"offline adversarial tier requires Linux"}]
    elif tier == "backend-security":
        specs = BACKEND_SECURITY
        env = os.environ.copy()
    elif tier == "linux-live":
        specs = LINUX_LIVE
        env = {**os.environ, "NL_RUN_LIVE_LINUX_SANDBOX":"1"}
        if platform.system() != "Linux":
            return [{"status":"BLOCKED","error":"requires Linux kernel"}]
    elif tier == "windows-live":
        specs = WINDOWS_LIVE
        env = {**os.environ, "NL_RUN_LIVE_WIN_SANDBOX":"1"}
        if platform.system() != "Windows":
            return [{"status":"BLOCKED","error":"requires Windows host"}]
    else:
        return [{"status":"BLOCKED","error":"hardware and macOS isolation require external equipment and verified capability; no automatic certification"}]
    return [run_test(pkg,names,env) for pkg,names in specs.items()]


def assemble_release(paths):
    tiers = {"offline", "backend-security", "linux-live", "windows-live", "hardware-live", "macos-live", "compatibility-live"}
    reports = {}
    for path in paths:
        obj = json.loads(pathlib.Path(path).read_text())
        tier = obj.get("tier")
        if tier not in tiers or tier in reports:
            raise ValueError(f"unexpected or duplicated evidence tier: {tier}")
        reports[tier] = obj
    if reports.keys() != tiers:
        return {"status":"BLOCKED", "missing":sorted(tiers - reports.keys()), "unexpected":sorted(reports.keys()-tiers)}
    reference = source_fingerprint()
    problems = []
    now = dt.datetime.now(dt.timezone.utc)
    for tier, report in reports.items():
        if report.get("sourceSha256") != reference:
            problems.append(f"{tier}: source fingerprint mismatch")
        if report.get("status") != "PASS":
            problems.append(f"{tier}: not PASS")
        try:
            generated = dt.datetime.fromisoformat(report["generatedAt"].replace("Z", "+00:00"))
            if abs((now-generated).total_seconds()) > 7*86400:
                problems.append(f"{tier}: evidence older than seven days")
        except (KeyError, ValueError):
            problems.append(f"{tier}: missing timestamp")
        if not report.get("results"):
            problems.append(f"{tier}: no executable test results")
    return {"status":"PASS" if not problems else "BLOCKED", "problems":problems, "note":"Evidence ingestion is not cryptographically authenticated; use trusted CI artifacts and commit provenance in production"}


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--tier",choices=["offline","backend-security","linux-live","windows-live","macos-live","hardware-live","compatibility-live","release"],required=True)
    cli.add_argument("--output",type=pathlib.Path,required=True)
    cli.add_argument("--evidence",type=pathlib.Path,nargs="*",default=[])
    args=cli.parse_args()
    if args.tier == "release":
        outcome = assemble_release(args.evidence)
        report = {"schema":"neverlauncher/security-certification/03114","tier":"release","status":outcome["status"],"generatedAt":dt.datetime.now(dt.timezone.utc).isoformat(),"sourceSha256":source_fingerprint(),"gate":outcome}
    else:
        results = run_tier(args.tier)
        status = "FAIL" if any(x["status"] == "FAIL" for x in results) else "BLOCKED" if any(x["status"] != "PASS" for x in results) else "PASS"
        report = {"schema":"neverlauncher/security-certification/03114","tier":args.tier,"status":status,"generatedAt":dt.datetime.now(dt.timezone.utc).isoformat(),"sourceSha256":source_fingerprint(),"host":{"system":platform.system(),"release":platform.release(),"architecture":platform.machine()},"results":results}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"tier":args.tier,"status":report["status"],"report":str(args.output)},ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1

if __name__ == "__main__": sys.exit(main())
