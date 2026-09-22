#!/usr/bin/env python3
from pathlib import Path
import json, subprocess, sys
ROOT=Path(__file__).resolve().parents[3]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def req(text, needles, label):
    missing=[x for x in needles if x not in text]
    if missing: raise SystemExit(f"{label} missing: {', '.join(missing)}")
version=read('VERSION').strip()
if version!='0.13.0': raise SystemExit(f'VERSION must be 0.13.0, got {version}')
api_migs=sorted((ROOT/'services/api/internal/dbmigrate/sql').glob('*.sql'))
cli_migs=sorted((ROOT/'cli/internal/dbmigrate/sql').glob('*.sql'))
if [p.name for p in api_migs] != [p.name for p in cli_migs]: raise SystemExit('API/CLI migration catalogs differ')
if not api_migs or api_migs[-1].name!='0018_device_trust_stabilization_01210.sql': raise SystemExit('0.13.0 must ship sealed 0018 as latest migration; empty 0019 is forbidden')
for a,b in zip(api_migs,cli_migs):
    if a.read_bytes()!=b.read_bytes(): raise SystemExit(f'migration differs: {a.name}')
release=read('cli/cmd/neverlauncher/device_trust_release.go')
req(release,['DEVICE_TRUST_TARGETS.json','DEVICE_TRUST_MATRIX.json','DEVICE_TRUST_CERTIFICATION.json','deviceTrustCertificationRequired','all-required-device-trust-targets-must-pass-exact-commit-evidence','deviceTrustRelease0130'], 'CLI Device Trust certification')
runtime=read('services/api/internal/httpapi/device_trust_release_0130.go')
req(runtime,['0018_device_trust_stabilization_01210','sessionDeviceBinding','deviceBoundRefresh','minecraftServerBridge','not-remotely-verified','exact-commit-public-device-trust-matrix'], 'runtime release contract')
e2e=read('e2e/scripts/run-device-trust-e2e.sh')
req(e2e,['release-capabilities.json','release-readiness.json','deviceTrustRelease0130:true','deviceTrustRelease:$version'], 'protocol E2E release evidence')
targets=json.loads(read('device-trust/targets.json'))
if targets.get('productVersion')!='0.13.0': raise SystemExit('Device Trust targets version mismatch')
for t in targets['targets']:
    if 'deviceTrustRelease0130' not in t.get('requiredChecks',[]): raise SystemExit(f"target {t.get('id')} missing deviceTrustRelease0130")
build=read('scripts/release/build-release.sh')
req(build,['NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE','--device-trust-matrix','Publish-check Minecraft Compatibility + Device Trust Release'], 'release pipeline')
subprocess.run(['go','test','./cmd/neverlauncher'],cwd=ROOT/'cli',check=True)
subprocess.run(['go','test','-tags','neverlauncher_nopgx','./internal/httpapi'],cwd=ROOT/'services/api',check=True)
subprocess.run([sys.executable,str(ROOT/'scripts/device_trust/matrix.py'),'validate','--targets',str(ROOT/'device-trust/targets.json')],check=True)
subprocess.run([sys.executable,str(ROOT/'scripts/device_trust/test_matrix.py')],check=True)
print('[NeverLauncher] Device Trust Release 0.13.0 gate OK')
