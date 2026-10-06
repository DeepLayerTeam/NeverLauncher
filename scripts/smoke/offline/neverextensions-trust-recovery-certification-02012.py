#!/usr/bin/env python3
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[3]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def require(cond,msg):
    if not cond: raise SystemExit(msg)
require((ROOT/'VERSION').read_text().strip()=='0.20.12','VERSION must be 0.20.12')
mig=read('services/api/internal/dbmigrate/sql/0048_neverextensions_trust_recovery_certification_02012.sql')
for token in ['extension_trust_policy','extension_quarantine','extension_emergency_disables','revoked_at','neverlauncher_revoke_extension_key_02012']:
    require(token in mig,f'migration missing {token}')
repo=read('services/api/internal/repository/extension_trust_02012.go')
for token in ['RevokeExtensionRegistryPublisherKey','SaveExtensionQuarantine','IsExtensionPackageQuarantined','SetExtensionEmergencyDisable','ClearExtensionEmergencyDisable']:
    require(token in repo,f'repository missing {token}')
trust=read('services/api/internal/extensiontrust/trust_02012.go')
for token in ['EvaluatePublisher','EvaluatePublication','artifact signing key is revoked or inactive','artifact is quarantined']:
    require(token in trust,f'trust engine missing {token}')
host=read('services/api/internal/extensionhost/host_0205.go')
for token in ['GetExtensionEmergencyDisable','IsExtensionPackageQuarantined','SetCrashLoopHandler','crashloop']:
    require(token in host,f'host missing {token}')
main=read('services/api/cmd/neverlauncher-api/main.go')
for token in ['--no-extensions','SetCrashLoopHandler','SetExtensionEmergencyDisable','ExtensionSafeMode']:
    require(token in main,f'backend safe-mode/crash-loop integration missing {token}')
http=read('services/api/internal/httpapi/extension_trust_02012.go')
for token in ['enforceExtensionTrustRuntime02012','extensionRecoveryBackup02012','extensionRecoveryRestore02012','StateSHA256','quarantineRejectedUpload02012']:
    require(token in http,f'HTTP production implementation missing {token}')
routes=read('services/api/internal/httpapi/routes_packages.go')
for token in ['/extension-trust/policy','/extension-quarantine','/emergency-disable','/extension-recovery/backup','/extension-recovery/restore']:
    require(token in routes,f'route missing {token}')
mal=read('services/api/internal/extensionpackage/malicious_02012_test.go')
for token in ['traversal','windows-device','symlink','case-collision']:
    require(token in mal,f'malicious package test missing {token}')
targets=json.loads(read('neverextensions/trust-recovery-targets-02012.json'))
require({x['os'] for x in targets['targets'] if x.get('required')}=={'linux','windows','macos'},'cross-platform target set incomplete')
workflow=read('.github/workflows/neverextensions-trust-recovery-02012.yml')
for token in ['ubuntu-latest','windows-latest','macos-latest','public-matrix','go build ./cmd/neverlauncher-api']:
    require(token in workflow,f'cross-platform workflow missing {token}')
openapi=read('schemas/openapi.yaml')
for token in ['/api/v1/admin/extension-trust/policy','/api/v1/admin/extension-recovery/restore']:
    require(token in openapi,f'OpenAPI missing {token}')
print('NeverExtensions Trust, Recovery & Certification 0.20.12 offline gate OK')
