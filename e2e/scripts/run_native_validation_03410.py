#!/usr/bin/env python3
"""V10 independent native worker: fresh job dir, bounded execution, redacted export.

This is an OBSERVATIONAL runner. It never signs or uploads ValidationEvidence.
Only the independent attestation host can sign evidence from trusted execution.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from process_group_03410 import group_flags, kill_tree

PUBLIC_REPORTS=('host-capabilities.json','staged-execution.json','verified.json',
                'startup-readiness.json','server-readiness.json','gameplay-smoke.json',
                'update-recovery.json')


def export_reports(work, destination):
    destination=Path(destination).resolve()
    destination.mkdir(parents=True,exist_ok=True)
    for name in PUBLIC_REPORTS:
        source=Path(work)/name
        if source.is_file() and not source.is_symlink() and source.stat().st_size<=2*1024*1024:
            # Export only sanitized/allowlisted JSON, never auth, worker grants,
            # raw JVM logs, session data, or private test identities.
            try:
                data=json.loads(source.read_text(encoding='utf-8'))
                if not isinstance(data,dict):continue
                if name=='staged-execution.json':
                    data={k:v for k,v in data.items() if k in
                          ('schemaVersion','runId','packageId','manifestSha256','artifactSha256',
                           'startedAt','finishedAt','stages')}
                    data['stages']={k:{'status':v.get('status'),
                        'detail':str(v.get('detail',''))[:240] if v.get('status')=='blocked'
                        and any(word in str(v.get('detail','')).lower() for word in
                                ('renderer','display','gui','headless','java','capability'))
                        else '[redacted]'} for k,v in data.get('stages',{}).items()}
                if name=='host-capabilities.json':
                    data={k:v for k,v in data.items() if k not in ('host','user','environment')}
                # Don't export possibly sensitive provider auth fields from any
                # generic diagnostics: V12 handles centralized log redaction.
                if name not in ('host-capabilities.json','staged-execution.json','verified.json',
                                'startup-readiness.json','server-readiness.json','gameplay-smoke.json',
                                'update-recovery.json'):
                    continue
                (destination/name).write_text(json.dumps(data,indent=2),encoding='utf-8')
            except (OSError,ValueError,TypeError):
                continue


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('headless','gui'),required=True)
    parser.add_argument('--report-dir',required=True)
    parser.add_argument('--deadline-seconds',type=int,default=7200)
    args,remainder=parser.parse_known_args()
    if not 120<=args.deadline_seconds<=14400:
        parser.error('deadline must be 120..14400 seconds')
    if remainder and remainder[0]=='--':remainder=remainder[1:]
    if not remainder or not {'--package-id','--backend','--cli','--runtime','--java','--pinned-public-key'} <= set(remainder):
        parser.error('staged execution flags must include package, backend, CLI, runtime, Java and manifest key')
    if '--output' in remainder or '--execution-mode' in remainder:
        parser.error('worker controls output directory and execution mode')
    if Path(args.report_dir).exists() and any(Path(args.report_dir).iterdir()):
        parser.error('report directory must be empty')
    old_umask=os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='nl-validation-v10-') as root:
            work=Path(root)/'execution'
            invocation=[sys.executable,str(Path(__file__).parent/'run-staged-package-0342.py'),
                        *remainder,'--execution-mode',args.mode,'--output',str(work)]
            # The worker inherits only the current job's environment. On shared
            # hosts run it as a dedicated OS account/VM with no production secrets.
            proc=subprocess.Popen(invocation,stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**group_flags())
            try:
                rc=proc.wait(timeout=args.deadline_seconds)
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait(timeout=20)
                rc=3
            finally:
                if proc.poll() is None:
                    kill_tree(proc)
                    proc.wait(timeout=20)
            export_reports(work,args.report_dir)
            if args.mode=='headless':
                report=Path(args.report_dir)/'staged-execution.json'
                if report.exists():
                    stages=json.loads(report.read_text())['stages']
                    if (stages.get('manifest-files',{}).get('status')=='passed' and
                        stages.get('materialization',{}).get('status')=='passed'):
                        print('headless materialization verified; gameplay BLOCKED (not a PASS)')
                        return 3
            if rc:
                print('native runtime target not certified; see stage statuses in redacted report',file=sys.stderr)
                return 3
            print('native observational runtime stages completed; not signed evidence')
            return 0
    finally:
        os.umask(old_umask)

if __name__=='__main__':
    sys.exit(main())
