#!/usr/bin/env python3
"""Execute the *released staged bytes*, not an upstream/Client Factory rebuild.

Must run on an isolated CI host with a real GUI renderer for startup. A report
from this script is observational, never accepted as stable certification.
"""
import argparse
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


def run_runtime(cmd, result_file, env, deadline):
    # Native NeverRuntime returns its structured execution result on stdout;
    # the Go client lifecycle commands instead support --output <file>.
    proc = subprocess.run(cmd, capture_output=True, env=env, timeout=deadline, check=False)
    result_file.with_suffix('.log').write_bytes(proc.stderr[:2 * 1024 * 1024])
    if proc.returncode:
        raise RuntimeError(f'NeverRuntime launch failed rc={proc.returncode} (see {result_file.with_suffix(".log").name})')
    if len(proc.stdout) > 4 * 1024 * 1024:
        raise RuntimeError('NeverRuntime structured output exceeded limit')
    result = json.loads(proc.stdout)
    if not isinstance(result, dict) or 'timed_out' not in result or 'success' not in result:
        raise ValueError('NeverRuntime returned no valid launch result')
    result_file.write_bytes(proc.stdout)
    return result


def execute(args):
    if not args.backend.startswith('https://') and not args.backend.startswith(('http://127.0.0.1:', 'http://localhost:')):
        raise ValueError('staged runtime requires HTTPS (localhost HTTP is test-only)')
    if not args.package_id or '/' in args.package_id:
        raise ValueError('invalid package ID')
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
        launched = run_runtime(cmd, run_path, subprocess_env, args.runtime_seconds + 150)
        if launched.get('exit_code') not in (None, 0):
            raise RuntimeError('actual staged Minecraft JVM exited with failure')
        if launched.get('timed_out') is not True and launched.get('success') is not True:
            raise RuntimeError('actual staged Minecraft JVM failed before runtime deadline')
        # 0.34.2 records execution, not visual menu readiness. A timeout is
        # deliberately never converted into a successful certification.
        report['stages'][stage_name] = {
            'status': 'inconclusive',
            'detail': f"actual NeverRuntime launch executed installed staged release; menu readiness not proven; timedOut={bool(launched.get('timed_out'))}; runtimeSHA256={runtime_hash}",
            'evidenceSha256': sha_file(run_path),
        }
    except Exception as exc:
        error = str(exc)
        report['stages'][stage_name] = {'status':'failed' if stage_name in ('manifest-files','materialization','startup') else 'blocked', 'detail':error[:2048]}
    finally:
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
    parser.add_argument('--admin-token', required=True)
    parser.add_argument('--package-id', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--java', required=True)
    parser.add_argument('--pinned-public-key', required=True)
    parser.add_argument('--runtime-seconds', type=int, default=45)
    args = parser.parse_args()
    if not 15 <= args.runtime_seconds <= 3600:
        parser.error('runtime seconds must be 15..3600')
    try:
        execute(args)
    except Exception as exc:
        print('staged runtime failed:', str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
