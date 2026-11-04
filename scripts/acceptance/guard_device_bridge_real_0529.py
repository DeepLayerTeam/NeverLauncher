#!/usr/bin/env python3
"""0.52.9 actual Guard/Device Trust/ServerBridge acceptance executor.

Local mode executes *production* Java and Guard JVM processes. Live mode
consumes the ORIGINAL private native/protocol/JVM logs and actively probes a
running Vanilla sidecar, while re-running verification of 10 other Docker JVMs.
A success here is pending external review; it is never permission to publish GA.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text().strip()
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
NATIVE = ('linux-x64','linux-arm64','windows-x64','windows-arm64','darwin-x64','darwin-arm64')

class Blocked(ValueError):
    pass

def require(condition, error):
    if not condition:
        raise Blocked(error)

def module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    require(spec is not None and spec.loader is not None, 'missing verification implementation: ' + relative)
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    return target

def secure_file(path, limit=8<<20):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'missing/unsafe evidence file: '+str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
            'hardlinked/empty/oversized evidence: ' + str(path))
    require(not any(parent.is_symlink() for parent in path.parents), 'symlinked evidence ancestor')
    return path

def read_json(path):
    def reject_duplicates(pairs):
        data = {}
        for key,value in pairs:
            require(key not in data, 'duplicate evidence JSON key: '+key)
            data[key] = value
        return data
    data = json.loads(secure_file(path).read_bytes(), object_pairs_hook=reject_duplicates,
                      parse_constant=lambda x: (_ for _ in ()).throw(Blocked('nonfinite evidence JSON')))
    require(type(data) is dict, 'evidence root must be JSON object')
    return data

def sha(path):
    digest=hashlib.sha256()
    with secure_file(path, 2<<30).open('rb') as stream:
        for piece in iter(lambda: stream.read(1<<20), b''):
            digest.update(piece)
    return digest.hexdigest()

def run_command(argv, timeout=600):
    completed = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False)
    require(completed.returncode == 0 and len(completed.stdout) < 16<<20,
            'failed executable check: ' + Path(argv[0]).name)
    return hashlib.sha256(completed.stdout).hexdigest()

def inspect_device(root, commit, run_id):
    device = module('scripts/device_trust/matrix.py', 'device_matrix_0529')
    targets = device.load_targets(ROOT / 'device-trust/targets.json')['targets']
    require(sum(x['required'] for x in targets) == 7, 'Device Trust required scope changed')
    found, errors = device.discover_results(root)
    require(not errors and set(found) == {t['id'] for t in targets},
            'incomplete/duplicate/unsafe native Device Trust target results')
    result = {}
    for target in targets:
        path, doc = found[target['id']]
        require(not path.is_symlink(), 'symlink Device Trust result')
        failures = device.verify_result(target, doc, result_path=path, commit=commit, run_id=run_id)
        require(not failures, target['id'] + ': '+ '; '.join(failures))
        # The matrix checks hashes; this additionally rejects hardlinked and
        # ancestor-symlink files which can be swapped by another process.
        for name in doc['evidence']['files']:
            secure_file(path.parent / name, 2<<30)
        result[target['id']] = sha(path)
    return result

def inspect_guard_ci(root, commit, run_id, repository):
    guard = module('scripts/guard_ci/matrix.py', 'guard_matrix_0529')
    targets = guard.load_targets(ROOT / 'guard-ci/targets.json')['targets']
    require(len(targets) == 3 and all(t['required'] for t in targets), 'Guard targets incomplete')
    found, errors = guard.discover_results(root)
    require(not errors and set(found) == {t['id'] for t in targets}, 'missing/duplicate Guard native results')
    out = {}
    for target in targets:
        path, data = found[target['id']]
        require(not path.is_symlink(), 'symlink Guard result')
        failures = guard.verify_result(target, data, commit=commit, run_id=run_id, repository=repository)
        require(not failures, target['id'] + ': ' + '; '.join(failures))
        # An arbitrary JSON "passed" with invented package hashes is NOT
        # native evidence. Rehash every original compiled package/binary.
        for item in data['artifacts'].values():
            actual = secure_file(path.parent / item['name'], 2<<30)
            require(actual.stat().st_size == item['size'] and sha(actual) == item['sha256'],
                    target['id'] + ': original Guard package/binary altered or absent')
        out[target['id']] = sha(path)
    return out

def inspect_jvm(root):
    tests = module('scripts/guard_ci/adversarial_pilot_05012.py', 'adversarial_0529')
    expected = {'loader-transformations','continuous-watchdog'}
    results = {}
    for native in NATIVE:
        run = read_json(root / native / 'result.json')
        suites = run.get('suites')
        names = set(expected)
        if native.startswith('linux-'):
            names |= {'runtime-integrity', 'linux-process-protection'}
        require(run.get('schema') == 'neverlauncher.guard-adversarial-jvm/v1' and
                run.get('version') == VERSION and run.get('status') == 'PASS_JVM_REGRESSIONS_ONLY' and
                type(suites) is list and {x['name'] for x in suites} == names,
                native + ': missing actual JVM Guard scenarios')
        for suite in suites:
            name = suite['name']
            require(suite.get('status') == 'PASS' and suite.get('exitCode') == 0 and
                    type(suite.get('testsRun')) is int and suite['testsRun'] >= suite.get('minimumTests',10**9) > 0,
                    native + '/' + name + ': tests did not pass')
            log = root / native / 'logs' / (name + '.log')
            require(suite.get('logFile') == log.name and suite.get('logSha256') == sha(log),
                    native + '/' + name + ': original JVM output missing or changed')
            output = secure_file(log, 32<<20).read_text(errors='replace')
            require(re.search(r'(?m)^OK\s*$', output) and
                    re.search(r'Ran \d+ tests? in [0-9.]+s', output),
                    native + '/' + name + ': no successful real unittest execution')
        results[native] = sha(root / native / 'result.json')
    return results

def inspect_serverbridge(runtime):
    live = module('serverbridge/live_matrix_04113.py', 'serverbridge_live_0529')
    # Re-check the Docker-derived process identity, Bridge JAR, native log,
    # network allow-then-deny and actual Paper client join for all 10 targets.
    targets = read_json(ROOT / 'serverbridge/targets.json')['targets']
    require(len(targets) == 14 and len({t['id'] for t in targets}) == 14, '14 adapter set changed')
    base = read_json(runtime / 'result.json')
    require(base.get('version') == VERSION and base.get('status') == 'passed' and
            base.get('mode') == 'full', 'full real Docker/Minecraft run missing')
    outcome = {}
    for target in targets:
        if target['id'] not in live.CORE:
            continue
        proof = live.verify_runtime(target['id'], target, runtime, VERSION, 'E2EPlayer', ROOT)
        require(proof['status'] == 'passed', target['id'] + ': real server runtime blocked')
        node_id, _ = live.CORE[target['id']]
        for kind in ('allow', 'deny'):
            name = ('runtime-launch-minecraft.json' if kind == 'allow' else 'probe-paper-deny.txt') if target['id'] == 'paper' else f'probe-{node_id}-{kind}.txt'
            secure_file(runtime / name, 32<<20)
        secure_file(runtime / f"live-{target['id']}-04113.log", 128<<20)
        outcome[target['id']] = sha(runtime / f"live-{target['id']}-04113.json")
    require(len(outcome) == 10, 'missing 10 real JVM/proxy adapters')
    return outcome

def run_live(cfg):
    require(type(cfg) is dict and set(cfg) == {
        'sourceCommit','runId','repository','deviceResults','guardResults','guardJvmResults',
        'guardShadowDir','guardShadowKeyFile','guardIncidentReviews','frameBaseline','frameGuard',
        'gameRuntime','gameServerLog','player','serverbridgeRuntime','vanilla'},
        'live config must specify every real acceptance dependency')
    commit, run_id, repo = cfg['sourceCommit'], cfg['runId'], cfg['repository']
    require(type(commit) is str and COMMIT.fullmatch(commit) and
            type(run_id) is str and RUN.fullmatch(run_id) and
            type(repo) is str and re.fullmatch(r'[A-Za-z0-9._/-]{3,150}', repo),
            'live run must bind exact commit, CI run and repository')
    all_paths = {k: Path(cfg[k]) for k in ('deviceResults','guardResults','guardJvmResults','guardShadowDir',
                  'guardShadowKeyFile','guardIncidentReviews','frameBaseline','frameGuard','gameRuntime',
                  'gameServerLog','serverbridgeRuntime')}
    require(all(p.is_absolute() for p in all_paths.values()), 'absolute external evidence paths required')
    # The private per-server MAC key is never exported in this acceptance report.
    pilot = module('scripts/guard_ci/adversarial_pilot_05012.py', 'shadow_0529')
    shadow = pilot.analyze_shadow(all_paths['guardShadowDir'], all_paths['guardShadowKeyFile'],
                                  all_paths['guardIncidentReviews'])
    require(shadow['status'] == 'EVIDENCE_REVIEW_REQUIRED' and
            shadow['unreviewedRevocations'] == 0 and
            not shadow['reviewed']['false_positive'] and not shadow['reviewed']['inconclusive'],
            'Guard pilot hours or false-positive incident review BLOCKED')
    frames = pilot.compare_performance(all_paths['frameBaseline'], all_paths['frameGuard'])
    require(frames['status'] == 'PASS_MEASURED', 'actual Guard frame-time regression unacceptable')
    game = pilot.verify_game(all_paths['gameRuntime'], all_paths['gameServerLog'], cfg['player'])
    require(game['status'] == 'EVIDENCE_VERIFIED_NOT_INDEPENDENT', 'real authenticated Minecraft join missing')
    native = inspect_guard_ci(all_paths['guardResults'], commit, run_id, repo)
    devices = inspect_device(all_paths['deviceResults'], commit, run_id)
    jvm = inspect_jvm(all_paths['guardJvmResults'])
    # Invoke the existing production release JAR verifier, not a test stub.
    release = run_command([sys.executable, str(ROOT / 'serverbridge/certify_release.py'),
                           '--artifacts', str(ROOT / 'artifacts/plugins')], timeout=180)
    bridge = inspect_serverbridge(all_paths['serverbridgeRuntime'])
    vanilla = module('scripts/acceptance/vanilla_sidecar_live_0529.py', 'vanilla_0529')
    vanilla_result = vanilla.verify(cfg['vanilla'])
    # The 3 build compatibility targets must be present in the real production
    # release JAR cohort, not upgraded to runtime status by a build test.
    return {'schema': 'neverlauncher.guard-device-bridge-live/0.52.9', 'version': VERSION,
            'sourceCommit': commit, 'runId':run_id, 'repository':repo,
            'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED', 'independentGA':False,
            'guard':{'nativeCi':native,'sixJvm':jvm,'shadow':shadow,'performance':frames,'game':game},
            'deviceTrust':{'targets':devices, 'nativeSecureStorageHardwareCertification':False},
            'serverBridge':{'tenRealRuntime':bridge,'threeBuildCompatibility':
                ['bukkit','quilt','sponge'], 'vanillaSidecar':vanilla_result,
                'productionJarVerificationOutputSha256':release},
            'reviewRequired':'Independent final signed native packages, pilot observations, hardware secure storage and actual upstream runtimes',
            'completedAt':datetime.now(timezone.utc).isoformat()}

def run_local(output, only=None):
    import shutil
    require(shutil.which('java') is not None and shutil.which('javac') is not None,
            'real JDK required for Java adapter tests')
    bridge = run_command(['bash',str(ROOT/'e2e/scripts/run-serverbridge-adapter-capabilities-0286.sh')], timeout=120)
    guard = module('scripts/guard_ci/adversarial_pilot_05012.py', 'adversarial_local_0529')
    result = guard.run_jvm_suites(output.parent / 'jvm-logs', only)
    require(result['status'] == 'PASS_JVM_REGRESSIONS_ONLY',
            'actual native JVM Guard regression suites failed')
    complete = len(result['suites']) == 4 and all(x['status'] == 'PASS' for x in result['suites'])
    return {'schema':'neverlauncher.guard-device-bridge-local/0.52.9', 'version':VERSION,
            'status':'LOCAL_REAL_JVM_REGRESSIONS_ONLY' if complete else 'LOCAL_PARTIAL_JVM_REGRESSIONS_NOT_GA', 'javaAdapterStdoutSha256':bridge,
            'guardJvm':result, 'independentGA':False}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('local','live'))
    parser.add_argument('--config',type=Path)
    parser.add_argument('--only-suite',action='append', choices=['loader-transformations','runtime-integrity','continuous-watchdog','linux-process-protection'])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        require(VERSION == '0.52.9', 'wrong source version for 0.52.9 acceptance')
        require(args.mode == 'local' or args.config is not None, 'external live config required')
        report=run_local(args.output, set(args.only_suite) if args.only_suite else None) if args.mode=='local' else run_live(read_json(args.config))
        require(not args.output.exists() and args.output.is_absolute(), 'new absolute output path required')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(json.dumps(report,ensure_ascii=False,indent=2).encode()+b'\n')
            stream.flush();os.fsync(stream.fileno())
        print(report['status'])
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as exc:
        print('BLOCKED 0.52.9: '+str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
