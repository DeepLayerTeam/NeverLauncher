#!/usr/bin/env python3
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[3]
version = tuple(map(int, (ROOT/'VERSION').read_text().strip().split('.')[:3]))
if version < (0,19,6):
    raise SystemExit(f'Topology & Routing 2 gate requires VERSION>=0.19.6, got {version}')
required = [
 'services/api/internal/httpapi/server_bridge_routing_0196.go',
 'services/api/internal/repository/server_bridge_routing_0196.go',
 'services/api/internal/dbmigrate/sql/0037_serverbridge_topology_routing2_0196.sql',
 'cli/internal/dbmigrate/sql/0037_serverbridge_topology_routing2_0196.sql',
 'plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeRoutingSnapshot.java',
]
for rel in required:
    if not (ROOT/rel).is_file(): raise SystemExit(f'missing 0.19.6 production file: {rel}')
proto=(ROOT/'services/api/internal/httpapi/server_bridge_protocol_0191.go').read_text()
route=(ROOT/'services/api/internal/httpapi/server_bridge_routing_0196.go').read_text()
repo=(ROOT/'services/api/internal/repository/server_bridge_v2.go').read_text()
client=(ROOT/'plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java').read_text()
cert=(ROOT/'serverbridge/certify_release.py').read_text()
preflight=(ROOT/'scripts/release/preflight.sh').read_text()
ci=(ROOT/'.github/workflows/ci.yml').read_text()
for text, wants, label in [
 (proto,['topology.routing-v2','bridgeRoutingV3Contract0196'],'protocol'),
 (route,['ed25519.Verify','ListServerBridgeAllowedBackends','serverBridgeAllowedRoutes0196','ensureRoutable0196'],'routing'),
 (repo,['RequireRoutingProof','SourceRoutingDigest','TargetRoutingDigest','routing_state=\'ready\'','server_bridge_handoffs_v2'],'handoff'),
 (client,['FEATURE_ROUTING_V2','verifyTargetRoute','BridgeRoutingSnapshot.create','setRoutingModes'],'client'),
 (cert,['BridgeRoutingSnapshot.class','topologyRouting2','handoffSourceTargetProof'],'certification'),
]:
    for want in wants:
        if want not in text: raise SystemExit(f'{label} missing {want!r}')
for text, want, label in [(preflight,'serverbridge-topology-routing2-0196.py','preflight'),(ci,'serverbridge-topology-routing2-0196.py','CI')]:
    if want not in text: raise SystemExit(f'{label} missing {want!r}')
if any(x in client for x in ['ProcessBuilder(', 'Runtime.getRuntime().exec']):
    raise SystemExit('routing/control client must not execute OS shell')
print('ServerBridge 0.19.6 Topology & Routing 2 production gate: PASS')
