#!/usr/bin/env python3
"""Production publication guard for 0.53.0.

Verify the exact 18-group independent verifier signature and compare all six
signed installers with BOTH the separately pinned distribution index and the
actual files being published. Never accept a merely completed CI workflow.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from cryptography.exceptions import InvalidSignature

import full_real_acceptance_0530 as ga

class Blocked(ValueError):pass

def need(ok, why):
    if not ok:raise Blocked(why)

def verify(approval:Path, signature:Path, verifier_public:Path, verifier_pin:str,
           packages:Path, index:Path, index_pin:str, bundle:Path,
           source_commit:str, project:str):
    need(ga.VERSION=='0.53.0' and ga.rehearsal.COMMIT.fullmatch(source_commit),
         '0.53.0 exact source SHA required for protected publication')
    report=ga.verify_signed(approval,signature,verifier_public,verifier_pin,ga.FINAL_DOMAIN)
    need(set(report)=={'schema','version','commit','project','sourceTree',
         'sourceIndexSha256','finalPackages','qaSha256','fullSweepSha256','e2eGroups','status'} and
         report['schema']==ga.FINAL_SCHEMA and report['version']==ga.VERSION and
         report['commit']==source_commit and report['project']==project and
         report['status']=='PASS' and report['sourceIndexSha256']==index_pin and
         report['e2eGroups']==list(ga.GROUPS) and
         ga.rehearsal.COMMIT.fullmatch(report.get('sourceTree','')) and
         all(ga.rehearsal.SHA.fullmatch(report.get(x,'')) for x in ('qaSha256','fullSweepSha256')),
         'not a valid independently signed FULL user acceptance decision')
    raw=ga.rehearsal.safe(index,ga.rehearsal.native.MAX_INDEX).read_bytes()
    need(hashlib.sha256(raw).hexdigest()==index_pin, 'independent source index bytes changed')
    original=ga.rehearsal.package_set(packages,index,index_pin,source_commit,project)
    need(original==report['finalPackages'] and len(original)==8,
         'actual final signed installer bytes differ from verified GA')
    # A separate signed-release bundle is *not* the approved installer. Don't
    # silently publish other executable packages just because their source is
    # the same. Exact six final-byte assets must enter the signed bundle.
    need(bundle.is_absolute() and bundle.is_dir() and not bundle.is_symlink(),
         'real signed publication bundle missing')
    present={p.name for p in bundle.iterdir() if p.is_file() and not p.is_symlink()}
    need(set(original).issubset(present),
         'the actual publication bundle does not contain approved final packages')
    for name,row in original.items():
        file=ga.rehearsal.safe(bundle/name,ga.rehearsal.native.MAX_PACKAGE)
        need(file.stat().st_size==row['size'] and ga.rehearsal.sha(file)==row['sha256'],
             'publication attempts to replace approved signed package '+name)
    # Existing publisher verifies that these files are covered by SHA256SUMS,
    # RELEASE_MANIFEST and release-root signature; this guard is complementary.
    return {'version':ga.VERSION,'commit':source_commit,'status':'PASS',
            'authorizedPackages':len(original),
            'gaApprovalSha256':ga.rehearsal.sha(approval)}
