#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]
version=(root/'VERSION').read_text().strip()
parts=tuple(int(x) for x in version.split('-',1)[0].split('+',1)[0].split('.')[:3])
if parts < (0,15,0): raise SystemExit(f'ServerBridge 2 release gate requires VERSION>=0.15.0, got {version}')
def read(p): return (root/p).read_text(encoding='utf-8')
def require(text, needles, label):
    missing=[n for n in needles if n not in text]
    if missing: raise SystemExit(f'{label}: missing {missing}')
cert=read('serverbridge/certify_release.py')
require(cert,[
    "EXPECTED = ['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge']",
    'BRIDGE_RELEASE_ALLOWLIST.json','PLUGIN_MANIFEST.json','SHA256SUMS','SERVERBRIDGE2_CERTIFICATION.json',
    'platform-matched release required','folia-supported: true','clientModRequired'
],'ServerBridge 2 certification')
build=read('scripts/build/bridge-plugins.sh')
require(build,['serverbridge/certify_release.py','Production ServerBridge 2 artifacts'],'bridge build')
release=read('scripts/release/build-release.sh')
require(release,['SERVERBRIDGE2_CERTIFICATION.json','BRIDGE_RELEASE_ALLOWLIST.json','BRIDGE_PLUGIN_MANIFEST.json'],'release bundle')
required=read('scripts/smoke/release-required/release-bundle.sh')
require(required,['SERVERBRIDGE2_CERTIFICATION.json','BRIDGE_RELEASE_ALLOWLIST.json','BRIDGE_PLUGIN_MANIFEST.json'],'publish gate')
status=read('services/api/internal/httpapi/bridge_plugins.go')
require(status,['NeverLauncher 0.15.0 ServerBridge 2 Release'],'runtime release status')
import json
targets=json.loads(read('serverbridge/targets.json'))
if targets.get('productVersion') != version or targets.get('protocolVersion') != 2: raise SystemExit('ServerBridge matrix version/protocol mismatch')
ids=[x.get('id') for x in targets.get('targets',[])]
if ids != ['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge']:
    raise SystemExit(f'ServerBridge 2 target cohort mismatch: {ids}')
print(f'NeverLauncher {version} ServerBridge 2 release gate: OK (11-platform certified cohort)')
