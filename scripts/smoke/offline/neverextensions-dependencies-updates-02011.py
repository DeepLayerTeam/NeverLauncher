#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]
def read(rel): return (ROOT/rel).read_text(encoding='utf-8')
def require(ok,msg):
    if not ok: raise SystemExit(msg)

version=tuple(int(x) for x in read('VERSION').strip().split('.')[:3]); require(version >= (0,20,11),'VERSION must be >= 0.20.11')
required=[
 'services/api/internal/extensionresolver/semver_02011.go',
 'services/api/internal/extensionresolver/resolver_02011.go',
 'services/api/internal/extensionupdates/updates_02011.go',
 'services/api/internal/repository/extension_updates_02011.go',
 'services/api/internal/model/extension_updates_02011.go',
 'services/api/internal/dbmigrate/sql/0047_neverextensions_dependencies_updates_02011.sql',
 'cli/internal/dbmigrate/sql/0047_neverextensions_dependencies_updates_02011.sql',
 'cli/cmd/neverlauncher/extension_updates_02011.go',
]
for rel in required: require((ROOT/rel).is_file(),f'missing production dependency/update file {rel}')

semver=read('services/api/internal/extensionresolver/semver_02011.go')
for token in ('ParseVersion','Matches','^','~','||'):
    require(token in semver,f'SemVer resolver missing {token}')
resolver=read('services/api/internal/extensionresolver/resolver_02011.go')
for token in ('required','optional','conflict','topologicalOrder','cycle','stable','beta','dev','MinAPI','MaxAPI','SupportedOS','SupportedArchitectures','ListExtensionUpdatePins'):
    require(token.lower() in resolver.lower(),f'resolver missing {token}')
updates=read('services/api/internal/extensionupdates/updates_02011.go')
for token in ('AcquireExtensionUpdateLease','SaveExtensionUpdateTransaction','recoverInterrupted02011','InFlight','PermissionDiff','stale update plan','Rollback','waitHealthy','rollback_failed','PackageIdentity'):
    require(token in updates,f'transaction engine missing {token}')
repo=read('services/api/internal/repository/extension_updates_02011.go')
for token in ('SetExtensionUpdatePin','AcquireExtensionUpdateLease','ReleaseExtensionUpdateLease','SaveExtensionUpdateTransaction','GetExtensionUpdateTransaction'):
    require(token in repo,f'update repository missing {token}')
migration=read('services/api/internal/dbmigrate/sql/0047_neverextensions_dependencies_updates_02011.sql')
for token in ('min_api','max_api','extension_update_pins','extension_update_leases','extension_update_transactions','in_flight'):
    require(token in migration,f'migration 0047 missing {token}')
manifest=json.loads(read('schemas/neverlauncher-extension.schema.json'))
require('conflicts' in manifest.get('properties',{}),'canonical manifest schema missing conflicts')
routes=read('services/api/internal/httpapi/routes_packages.go')
for token in ('/api/v1/admin/extension-updates/plan','/api/v1/admin/extension-updates/apply','/api/v1/admin/extension-updates/pins/{extensionId}'):
    require(token in routes,f'update API route missing {token}')
legacy=read('services/api/internal/httpapi/extension_lifecycle_0204.go')
require('resolver02011' in legacy and 'updateManager02011' in legacy,'legacy update path bypasses dependency-aware transaction engine')
cli=read('cli/cmd/neverlauncher/extension_updates_02011.go')
for token in ('plan','apply','pins','pin','unpin','transaction'):
    require(token in cli,f'CLI update workflow missing {token}')
tables=read('cli/cmd/neverlauncher/release_commands.go')
for token in ('extension_update_pins','extension_update_leases','extension_update_transactions'):
    require(token in tables,f'productionTables missing {token}')
print('NeverExtensions Dependencies & Updates 0.20.11 production gate: OK')
