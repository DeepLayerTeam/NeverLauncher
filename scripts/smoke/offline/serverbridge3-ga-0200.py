#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]

def read(rel): return (ROOT/rel).read_text(encoding='utf-8')
def require(rel, tokens):
    text=read(rel)
    missing=[t for t in tokens if t not in text]
    if missing: raise SystemExit(f'{rel}: missing {missing}')

require('services/api/internal/httpapi/server_bridge_ga_0200.go', [
    'ServerBridge 3 GA','ga-frozen','compatibility-deprecated','098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc',
    'recentControls0200','topology','telemetry','audit','protocolMigrationsRequired'])
require('cli/cmd/neverlauncher/serverbridge_provisioning_0199.go', [
    'migrate-v3','protocol-v3-ga-migration.json','protocolV3Frozen','serverBridgeV3FrozenFeatureDigest0200','provisionServerBridge0199'])
require('cli/cmd/neverlauncher/serverbridge_release.go', [
    'SchemaVersion','1.1','GA','ProtocolV3Frozen','InstallerUpgradePath','UnifiedOperatorAPI','PublicCompatibilityMatrix'])
require('serverbridge/certify_release.py', [
    "'schemaVersion': '1.1'","'ga': True","'protocolV3Frozen': True","'installerUpgradePath': True","'/api/v1/server-bridge/overview'"])
require('scripts/build/bridge-plugins.sh', ['"ga":true','"protocolV3Frozen":true','"protocolV2Mode":"compatibility-deprecated"'])
require('apps/admin/src/main.tsx', ['/api/v1/server-bridge/overview','ServerBridgeOverview','protocolMigrationRequired','Topology','Control','Audit'])
require('services/api/internal/dbmigrate/sql/0041_serverbridge3_ga_0200.sql', ['protocol_version=2','compatibility/deprecation-only','migrate-v3'])
require('serverbridge/GA.md', ['Production migration v2 → v3','SERVERBRIDGE3_CERTIFICATION.json','14 supported artifacts'])
require('scripts/serverbridge/matrix.py', ['3 GA (frozen)','deprecated; migrate to v3'])
print('ServerBridge 3 GA 0.20.0 production gate: OK')
