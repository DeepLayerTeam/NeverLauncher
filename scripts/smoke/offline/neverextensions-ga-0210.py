#!/usr/bin/env python3
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[3]

def read(p): return (ROOT/p).read_text(encoding='utf-8')
def require(cond,msg):
    if not cond: raise SystemExit(msg)

require((ROOT/'VERSION').read_text().strip()=='0.21.0','VERSION must be 0.21.0')
contract=read('services/api/internal/extensioncontract/contract_0210.go')
for token in ['PackageFormatVersion','ManifestSchemaVersion','HostProtocolVersion','ExtensionAPIVersion','LegacyExtensionAPIVersion','RequireGAAPIVersion','SupportsHostHello']:
    require(token in contract,f'GA contract missing {token}')
registry=read('services/api/internal/httpapi/extension_registry_0203.go')
for token in ['RequireGAAPIVersion','extension:registry:reject-contract','quarantineRejectedUpload02012']:
    require(token in registry,f'production Registry GA enforcement missing {token}')
host=read('services/api/internal/extensionhost/host_0205.go')
for token in ['NEVERLAUNCHER_EXTENSION_API_VERSION','SupportsHostHello','extensionApiVersion']:
    require(token in host,f'Backend Host API negotiation missing {token}')
cli_host=read('services/api/internal/extensionhost/cli_0209.go')
require('NEVERLAUNCHER_EXTENSION_API_VERSION' in cli_host,'CLI Host API negotiation missing')
admin=read('apps/admin/src/admin_extensions_0208.tsx')
desktop=read('apps/desktop/src/extensions_0209.tsx')
require('extensionApiVersion: EXTENSION_API_VERSION' in admin,'Admin host context API version missing')
require("type: 'host.context', context:" in desktop and 'extensionApiVersion: EXTENSION_API_VERSION' in desktop,'Desktop host context envelope/API version missing')
ga=read('services/api/internal/extensionga/manager_0210.go')
for token in ['VerifyLockfile','EvaluatePublication','IsKnownPermission','dependencies.missing','dependencies.conflict','SetExtensionEmergencyDisable','extension:ga:reconcile:disable']:
    require(token in ga,f'GA reconciliation missing {token}')
routes=read('services/api/internal/httpapi/routes_packages.go')
for token in ['/extension-ga/status','/extension-ga/reconcile']:
    require(token in routes,f'GA route missing {token}')
cli=read('cli/cmd/neverlauncher/extension_ga_0210.go')
for token in ['upgrade-source','signed .nlext packages are immutable','requiresRepackAndResign','neverExtensionsSDKVersion0210','strings.ReplaceAll']:
    require(token in cli,f'0.20->0.21 source upgrader missing {token}')
mig=read('services/api/internal/dbmigrate/sql/0049_neverextensions_ga_0210.sql')
for token in ['extension_ga_contract','package_format_version','manifest_schema_version','host_protocol_version','extension_api_version','3.7']:
    require(token in mig,f'GA migration missing {token}')
spec=json.loads(read('sdk/api/extension-host-protocol.json'))
require(spec.get('hostProtocolVersion')=='1.0' and spec.get('extensionApiVersion')=='1.0','SDK protocol freeze mismatch')
require(spec['types']['HelloRequest'].get('extensionApiVersion')=='string','SDK hello API version field missing')
for f in ['sdk/admin/typescript/package.json','sdk/desktop/typescript/package.json']:
    require(json.loads(read(f)).get('version')=='0.21.0',f'{f} must be 0.21.0')
require('version = "0.21.0"' in read('sdk/desktop/rust/Cargo.toml'),'Rust SDK must be 0.21.0')
targets=json.loads(read('neverextensions/ga-targets-0210.json'))
require({x['os'] for x in targets['targets'] if x.get('required')}=={'linux','windows','macos'},'GA cross-platform target set incomplete')
workflow=read('.github/workflows/neverextensions-ga-0210.yml')
for token in ['ubuntu-latest','windows-latest','macos-latest','NEVEREXTENSIONS_GA_CERTIFICATE.json','extensioncontract','extensionga','npm ci']:
    require(token in workflow,f'GA workflow missing {token}')
print('NeverExtensions GA 0.21.0 offline gate OK')
