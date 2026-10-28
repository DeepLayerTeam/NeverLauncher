#!/usr/bin/env python3
"""Execute the *released staged bytes*, not an upstream/Client Factory rebuild.

Must run on an isolated CI host with a real GUI renderer for startup. A report
from this script is observational, never accepted as stable certification.
"""
import argparse
import time
from staged_readiness_0343 import StartupObserver, log_health
from staged_matching_0344 import MatchingServer, GameplayObserver
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "neverlauncher.staged-runtime-run.v1"


def iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_path(value):
    if not value or '\\' in value or '\x00' in value:
        raise ValueError(f"unsafe manifest path: {value!r}")
    components = PurePosixPath(value).parts
    if PurePosixPath(value).is_absolute() or any(p in ('.', '..', '') for p in components) or '/'.join(components) != value:
        raise ValueError(f"unsafe manifest path: {value!r}")
    return value


def request_json(base, relative, bearer, body=None):
    url = base.rstrip('/') + relative
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + bearer,
                                          "Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=60) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError("unexpected API response")
        return json.load(resp)


def download_exact(base, rel_url, bearer, target, size, expected):
    parsed = urllib.parse.urlsplit(rel_url)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or not rel_url.startswith('/api/v1/staged-runs/'):
        raise ValueError('untrusted staged download URL')
    if size < 0 or size > (8 << 30) or len(expected) != 64:
        raise ValueError('invalid staged object metadata')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError('staged object destination already exists')
    url = base.rstrip('/') + rel_url
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + bearer}, method="GET")
    temporary = target.with_name(target.name + '.partial')
    total = 0
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=120) as response, open(temporary, 'xb') as stream:
            if response.status != 200:
                raise ValueError('staged download failed')
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise ValueError('staged object exceeds signed size')
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if total != size or digest.hexdigest() != expected.lower():
            raise ValueError('staged download differs from signed snapshot (size / sha256)')
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_checked(cmd, result_file, env):
    # No shell execution and no backend token forwarded to the client/JVM.
    with open(result_file.with_suffix('.log'), 'wb') as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=5400, check=False)
    if proc.returncode:
        raise RuntimeError(f"command failed rc={proc.returncode}: {cmd[1]} (see {result_file.with_suffix('.log').name})")
    if not result_file.is_file():
        raise RuntimeError(f'command did not write evidence {result_file.name}')
    return json.loads(result_file.read_text(encoding='utf-8'))



def run_runtime_observed(cmd, result_file, env, deadline, observer):
    # NeverRuntime owns the real Java/Guard lifecycle. Never pipe its JSON
    # stdout while polling: the large bounded log tail can fill a pipe and
    # deadlock the runtime before it exits.
    stdout_path = result_file.with_suffix('.stdout')
    with open(result_file.with_suffix('.log'), 'wb') as diagnostic, open(stdout_path, 'xb') as stdout_file:
        proc = subprocess.Popen(cmd, stdout=stdout_file, stderr=diagnostic, env=env,
                                start_new_session=True)
        observer.root_pid = proc.pid
        try:
            until = time.monotonic() + deadline
            while proc.poll() is None:
                if time.monotonic() >= until:
                    raise TimeoutError('NeverRuntime itself hung beyond its termination deadline')
                observer.tick()
                time.sleep(0.5)
            proc.wait(timeout=10)
        except BaseException:
            # Never leave an orphan Minecraft/Guard process after a bad run.
            import signal
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=10)
            raise
    if proc.returncode:
        raise RuntimeError(f'NeverRuntime failed rc={proc.returncode}')
    if stdout_path.stat().st_size > 4 * 1024 * 1024:
        raise RuntimeError('NeverRuntime structured output exceeded limit')
    try:
        output = stdout_path.read_bytes()
        result = json.loads(output)
        if not isinstance(result, dict) or not isinstance(result.get('timed_out'),bool) or not isinstance(result.get('success'),bool):
            raise ValueError('NeverRuntime returned no valid launch result')
        result_file.write_bytes(output)
    finally:
        stdout_path.unlink(missing_ok=True)
    return result


def execute(args):
    if not args.backend.startswith('https://') and not args.backend.startswith(('http://127.0.0.1:', 'http://localhost:')):
        raise ValueError('staged runtime requires HTTPS (localhost HTTP is test-only)')
    if not args.package_id or '/' in args.package_id:
        raise ValueError('invalid package ID')
    if args.grant_file:
        grant_data = json.loads(Path(args.grant_file).read_text(encoding='utf-8'))
        if grant_data.get('packageId') != args.package_id:
            raise ValueError('pre-issued grant bound to different staged package')
    else:
        if not args.admin_token:
            raise ValueError('operator token required outside trusted attestation executor')
        grant_data = request_json(args.backend, '/api/v1/packages/' + urllib.parse.quote(args.package_id) + '/staged-runs', args.admin_token, {})['data']
    grant = grant_data['token']
    run_id = grant_data['runId']
    # Not printed or written to report/logs: a grant can fetch staged bytes.
    base_path = '/api/v1/staged-runs/' + urllib.parse.quote(args.package_id)
    report = {'schemaVersion': SCHEMA, 'runId': run_id, 'packageId': args.package_id,
              'manifestSha256': grant_data['manifestSha256'], 'artifactSha256': grant_data['artifactSha256'],
              'startedAt': iso(), 'stages': {}}
    work = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    stage = work / 'payload'
    if stage.exists():
        raise ValueError('output/payload must be new for each run')
    stage.mkdir(mode=0o700)
    client_dir = work / 'client'
    stage_name = ''
    error = None
    server = None
    subprocess_env = {k:v for k,v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN','SECRET','PASSWORD','PRIVATE_KEY','CREDENTIAL'))}
    try:
        stage_name = 'manifest-files'
        snapshot = request_json(args.backend, base_path + '/snapshot', grant)
        if any(snapshot[k] != report[k] for k in ('runId','packageId','manifestSha256','artifactSha256')):
            raise ValueError('server returned different run/snapshot identity')
        pkg = snapshot['package']
        signed = snapshot['signedManifest']
        if (pkg['packageId'] != args.package_id or pkg['projectId'] != signed['projectId'] or
                pkg['profileId'] != signed['profileId'] or pkg['channel'] != signed['channel'] or
                pkg['version'] != signed['version']):
            raise ValueError('staged snapshot release identity mismatch')
        if not pkg['files']:
            raise ValueError('staged release contains no installable client files')
        manifest_files = {entry['path']: entry for entry in signed['files']}
        if len(manifest_files) != len(pkg['files']):
            raise ValueError('staged file count mismatch')
        for item in pkg['files']:
            name = checked_path(item['path'])
            if name not in manifest_files:
                raise ValueError('file missing from signed manifest')
            source = manifest_files[name]
            if item['sha256'].lower() != source['sha256'].lower() or item['size'] != source['size']:
                raise ValueError('staged file metadata does not match signed manifest')
            download_exact(args.backend, item['url'], grant, stage / name, item['size'], item['sha256'])
        package_path = stage / 'staged-package-description.json'
        package_path.write_text(json.dumps(pkg, sort_keys=True, indent=2), encoding='utf-8')
        signed_manifest_path = stage / 'signed-release-manifest.json'
        signed_manifest_path.write_text(json.dumps(signed, sort_keys=True, indent=2), encoding='utf-8')
        report['stages'][stage_name] = {'status':'passed', 'detail': f"{len(pkg['files'])} staged files fetched and SHA-256 verified"}
        stage_name = 'materialization'
        install = work / 'install.json'
        cmd = [args.cli, 'client', 'install', '--package', str(package_path), '--client-dir', str(client_dir),
               '--storage-dir', str(work / 'empty-storage'), '--output', str(install)]
        installed = run_checked(cmd, install, subprocess_env)
        if installed.get('status') != 'applied-and-verified' or installed.get('packageId') != args.package_id:
            raise ValueError('updater did not verify exact package')
        verify_path = work / 'verified.json'
        verified = run_checked([args.cli,'client','verify','--package',str(package_path),'--client-dir',str(client_dir),'--output',str(verify_path)], verify_path, subprocess_env)
        if verified.get('status') != 'valid' or verified.get('verify',{}).get('checkedFiles') != len(pkg['files']):
            raise ValueError('installed package was not byte-identical to staged manifest')
        report['stages'][stage_name] = {'status':'passed','detail':'normal transactional client install and verify succeeded', 'evidenceSha256':sha_file(verify_path)}
        stage_name = 'startup'
        # Run the exact installed release with NeverRuntime's ordinary signed
        # manifest/launch path. A special Client Factory certification probe
        # would reject additional staged mods and is NOT the normal game path.
        if len(args.pinned_public_key) != 64 or signed.get('signature', {}).get('publicKey', '').lower() != args.pinned_public_key.lower():
            raise RuntimeError('staged release signing key does not match operator-pinned key')
        runtime_java = signed.get('runtime', {}).get('java', {})
        required_major = int(runtime_java.get('majorVersion', 0))
        if signed.get('schemaVersion') in ('2.0', '3.0') and int(runtime_java.get('recommendedMajorVersion') or 0) > 0:
            required_major = int(runtime_java['recommendedMajorVersion'])
        if required_major not in (8, 16, 17, 21, 25):
            raise RuntimeError(f'unsupported pinned release Java major {required_major}')
        if args.java == 'auto':
            home = os.environ.get(f'JAVA_HOME_{required_major}_X64', '')
            if not home:
                raise RuntimeError(f'Java {required_major} is not installed on this runner')
            selected_java = str((Path(home) / 'bin' / 'java').resolve())
        else:
            selected_java = str(Path(args.java).resolve())
        if not Path(selected_java).is_file():
            raise RuntimeError('selected Java binary unavailable')
        if not Path(args.runtime).is_file():
            raise RuntimeError('NeverRuntime executable unavailable')
        runtime_hash = sha_file(args.runtime)
        run_path = work / 'runtime-launch.json'
        cmd = [args.runtime, 'launch', '--manifest', str(signed_manifest_path),
               '--pinned-public-key', args.pinned_public_key, '--root', str(client_dir),
               '--java', selected_java, '--max-runtime-seconds', str(args.runtime_seconds)]
        loader = signed.get('minecraft', {}).get('loader', 'vanilla').lower()
        observer = StartupObserver(0, client_dir, work / 'startup-diagnostics', loader, time.time(), selected_java)
        if observer.blocked:
            # A missing X11/OpenGL renderer is infrastructure incapability,
            # not proof that the staged Minecraft release is incompatible.
            readiness_file = work / 'startup-readiness.json'
            readiness_file.write_text(json.dumps(observer.evidence(), indent=2), encoding='utf-8')
            report['stages']['startup'] = {'status':'blocked','detail':observer.blocked,
                                           'evidenceSha256':sha_file(readiness_file)}
            report['stages']['loader-readiness'] = {'status':'blocked','detail':'GUI runtime did not start'}
            raise RuntimeError('staged GUI validation blocked: ' + observer.blocked)
        try:
            launched = run_runtime_observed(cmd, run_path, subprocess_env, args.runtime_seconds + 150, observer)
            status, detail = observer.conclude(launched)
        finally:
            readiness_file = work / 'startup-readiness.json'
            readiness_file.write_text(json.dumps(observer.evidence(), indent=2), encoding='utf-8')
        loader_ready, loader_detail = log_health(client_dir, observer.runtime_log, loader)
        report['stages']['loader-readiness'] = {
            'status': 'passed' if loader_ready else 'failed',
            'detail': loader_detail[:2048],
            'evidenceSha256': sha_file(readiness_file),
        }
        report['stages'][stage_name] = {
            'status': status,
            'detail': (detail + '; neverruntime=' + runtime_hash + '; launch=' + sha_file(run_path))[:2048],
            'evidenceSha256': sha_file(readiness_file),
        }
        if status == 'failed':
            raise RuntimeError('staged Minecraft startup failed: ' + detail)
        if status == 'blocked':
            raise RuntimeError('staged Minecraft startup blocked: ' + detail)
        if not loader_ready:
            raise RuntimeError('staged loader readiness failed: ' + loader_detail)

        java_version_result = subprocess.run([selected_java, '-version'], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=subprocess_env, timeout=12, check=False)
        if java_version_result.returncode or not java_version_result.stdout:
            raise RuntimeError('selected Java version cannot be verified')
        java_version = java_version_result.stdout.decode('utf-8',errors='replace').splitlines()[0]
        # Execution identity is checked by the independent attestor, not signed by the worker.
        runtime_identity = {
            'javaSha256': sha_file(selected_java), 'javaVersionRaw': java_version,
            'cliSha256': sha_file(args.cli), 'neverRuntimeSha256': runtime_hash,
            'installAdapterSha256': hashlib.sha256((sha_file(args.cli)+runtime_hash).encode()).hexdigest(),
            'resolvedPlanSha256': hashlib.sha256(json.dumps({'minecraft':signed.get('minecraft'),
                'runtime':signed.get('runtime'), 'fileHashes':sorted((f['path'],f['sha256']) for f in pkg['files'])},
                sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'guardMode': str(signed.get('runtime',{}).get('guard',{}).get('mode') or 'disabled'),
            'guardPolicySha256': hashlib.sha256(json.dumps(signed.get('runtime',{}).get('guard',{}),
                sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'loader': loader, 'preset': str(signed.get('optionalPreset') or 'default'),
        }
        (work / 'execution-identity.json').write_text(json.dumps(runtime_identity,indent=2),encoding='utf-8')

        # A second ordinary NeverRuntime launch auto-enters the real matching
        # server; the first launch above independently proves the main menu.
        # A server distribution is pinned as a whole, not substituted with an
        # unrelated Vanilla server when the signed client uses a mod loader.
        mc = signed.get('minecraft', {})
        minecraft = mc.get('version', '')
        loader_version = mc.get('loaderVersion', '')
        if not minecraft or not loader or loader not in ('vanilla','fabric','quilt','forge','neoforge'):
            raise ValueError('unknown signed Minecraft version or loader')
        stage_name = 'server-readiness'
        if not signed.get('runtime', {}).get('launch', {}).get('offlineMode', False):
            report['stages']['server-readiness'] = {'status':'blocked',
                'detail':'authenticated Minecraft login requires real-provider V07 credentials; offline mock cannot certify gameplay'}
            raise RuntimeError('real authenticated test session unavailable for matching-server execution')
        server = MatchingServer(work, selected_java, args.cli, minecraft, loader, loader_version,
                                args.server_bundle, args.server_sha256, args.bridge_path,
                                args.bridge_sha256, args.server_entry, args.bridge_version)
        server.prepare()
        server.start(args.server_startup_seconds)
        server_report = work / 'server-readiness.json'
        server_report.write_text(json.dumps({'runId':run_id,'serverArtifactSha256':server.artifact_sha,
            'minecraftVersion':minecraft,'loader':loader,'loaderVersion':loader_version,
            'bridgeRequired':server.requires_bridge,'startup':'passed'},indent=2),encoding='utf-8')
        report['stages'][stage_name] = {'status':'passed', 'detail':'exact matching server/version, loader and required bridge booted; RCON world clock available',
                                        'evidenceSha256':sha_file(server_report)}
        stage_name = 'matching-server'
        username = 'NL_Cert_Client'
        game = GameplayObserver(server, client_dir, selected_java, loader, username,
                                work / 'gameplay-diagnostics', run_id, time.time())
        joining = work / 'runtime-gameplay-launch.json'
        join_cmd = [args.runtime, 'launch', '--manifest', str(signed_manifest_path),
                    '--pinned-public-key', args.pinned_public_key, '--root', str(client_dir),
                    '--java', selected_java, '--username', username,
                    '--matching-server-port', str(server.port),
                    '--max-runtime-seconds', str(args.gameplay_seconds)]
        launch_error = None
        try:
            gameplay_launch = run_runtime_observed(join_cmd, joining, subprocess_env,
                                                  args.gameplay_seconds + 150, game)
            if not gameplay_launch.get('timed_out') and not gameplay_launch.get('success'):
                raise RuntimeError('Minecraft JVM exited unsuccessfully after matching-server launch')
        except Exception as exc:
            launch_error = str(exc)
        game_proof = work / 'gameplay-smoke.json'
        game_proof.write_text(json.dumps(game.evidence(), indent=2), encoding='utf-8')
        proof_hash = sha_file(game_proof)
        from staged_matching_0344 import CRASH
        if (server.process.poll() is not None or game.failure or
                CRASH.search(server.log_text()) or not log_health(client_dir, None, loader)[0]):
            game.status = 'failed'
            game.failure = game.failure or 'client/server crashed or loader readiness lost after join'
        joined = game.joined and game.client_log_seen and game.window_pid is not None and not game.failure
        report['stages']['matching-server'] = {'status':'passed' if joined else 'failed',
            'detail':'matching server confirms login and player online; client log and PID-bound GUI observed' if joined else
                     ('matching client/server join not established: ' + (launch_error or game.failure or getattr(game,'last_error','no positive join evidence')))[:2048],
            'evidenceSha256':proof_hash}
        report['stages']['gameplay-smoke'] = {'status':'passed' if game.status == 'passed' and not launch_error else 'failed',
            'detail':'real GUI movement changed server-side position; world rendered and game ticks advanced' if game.status == 'passed' and not launch_error else
                     ('real gameplay state not confirmed: ' + (launch_error or game.failure or getattr(game,'last_error','no positive gameplay proof')))[:2048],
            'evidenceSha256':proof_hash}
        if launch_error or game.status != 'passed':
            raise RuntimeError('actual staged client gameplay failed: ' + (launch_error or game.failure or getattr(game,'last_error','missing required positive signals')))
    except Exception as exc:
        error = str(exc)
        if stage_name not in report['stages']:
            report['stages'][stage_name] = {'status':'failed' if stage_name in ('manifest-files','materialization','startup','server-readiness','matching-server','gameplay-smoke') else 'blocked', 'detail':error[:2048]}
    finally:
        if server is not None:
            server.close()
        # Worker-generated signatures are not trusted for stable publication.
        report['finishedAt'] = iso()
        report_path = work / 'staged-execution.json'
        report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
        try:
            request_json(args.backend,base_path+'/results',grant,report)
        except Exception as exc:
            print(f'report upload failed: {exc}',file=sys.stderr)
            if error is None:
                error = 'cannot persist execution report'
        for file in ('worker.key',):
            (work / file).unlink(missing_ok=True)
    if error:
        raise RuntimeError(error)
    print('completed staged runtime:', report_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', required=True)
    parser.add_argument('--admin-token', default='')
    parser.add_argument('--grant-file', default='', help='Limited staged grant injected by trusted host; not operator admin credentials')
    parser.add_argument('--package-id', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--java', required=True)
    parser.add_argument('--pinned-public-key', required=True)
    parser.add_argument('--runtime-seconds', type=int, default=180)
    parser.add_argument('--server-bundle', default='', help='Pinned server ZIP containing matching loader runtime; Vanilla can use official verified server download')
    parser.add_argument('--server-sha256', default='', help='Operator-pinned SHA-256 for full server distribution')
    parser.add_argument('--server-entry', default='', help='Launcher at bundle root: server.jar or run.sh')
    parser.add_argument('--bridge-path', default='', help='Required ServerBridge mod/plugin path inside pinned server bundle')
    parser.add_argument('--bridge-sha256', default='', help='Operator-pinned SHA-256 of the real bridge mod/plugin')
    parser.add_argument('--bridge-version', default='', help='Operator-pinned ServerBridge version observed in the actual server log')
    parser.add_argument('--server-startup-seconds', type=int, default=180)
    parser.add_argument('--gameplay-seconds', type=int, default=120)
    args = parser.parse_args()
    if not 15 <= args.runtime_seconds <= 3600:
        parser.error('runtime seconds must be 15..3600')
    if not 30 <= args.gameplay_seconds <= 1200 or not 30 <= args.server_startup_seconds <= 600:
        parser.error('gameplay must be 30..1200s and server startup 30..600s')
    try:
        execute(args)
    except Exception as exc:
        print('staged runtime failed:', str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
