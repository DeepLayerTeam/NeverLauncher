#!/usr/bin/env python3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
version = tuple(map(int, (ROOT/'VERSION').read_text().strip().split('.')[:3]))
if version < (0,19,7):
    raise SystemExit(f'Player Session Integration 3 gate requires VERSION>=0.19.7, got {version}')
required = [
 'services/api/internal/repository/server_bridge_player_sessions_0197.go',
 'services/api/internal/dbmigrate/sql/0038_serverbridge_player_session_integration3_0197.sql',
 'cli/internal/dbmigrate/sql/0038_serverbridge_player_session_integration3_0197.sql',
 'plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgePlayerSessionRegistry.java',
]
for rel in required:
    if not (ROOT/rel).is_file(): raise SystemExit(f'missing 0.19.7 production file: {rel}')
proto=(ROOT/'services/api/internal/httpapi/server_bridge_protocol_0191.go').read_text()
repo=(ROOT/'services/api/internal/repository/server_bridge_player_sessions_0197.go').read_text()
repo_core=(ROOT/'services/api/internal/repository/server_bridge_v2.go').read_text()
validate=(ROOT/'services/api/internal/httpapi/bridge_plugins.go').read_text()
handoff=(ROOT/'services/api/internal/httpapi/server_bridge_topology_handoff_0148.go').read_text()
client=(ROOT/'plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java').read_text()
registry=(ROOT/'plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgePlayerSessionRegistry.java').read_text()
migration=(ROOT/'services/api/internal/dbmigrate/sql/0038_serverbridge_player_session_integration3_0197.sql').read_text()
cert=(ROOT/'serverbridge/certify_release.py').read_text()
preflight=(ROOT/'scripts/release/preflight.sh').read_text()
ci=(ROOT/'.github/workflows/ci.yml').read_text()
checks=[
 (proto,['session.player-lifecycle-v3','SessionCorrelationID'],'protocol'),
 (migration,['server_bridge_player_sessions_v3','server_bridge_player_transfers_v3','uq_server_bridge_player_never_session_active_0197','uq_server_bridge_player_minecraft_session_active_0197','recheck_required'],'migration'),
 (repo,['session-clone-replaced','queuePlayerKickTx0197','transfer_sequence','recheck_required=TRUE','transfer-consumed','session-clone-replaced'],'repository lifecycle'),
 (repo_core,['activatePlayerSessionTx0197','issuePlayerTransferTx0197','consumePlayerTransferTx0197','applyPlayerLifecycleEventTx0197','PlayerSessionsInvalidated'],'repository integration'),
 (validate,['TrustReason = trust.Reason','IntegrityReason = minecraftIntegrity.Reason','trustIntegrityRechecked','invalidateSession(join.SessionID, "")'],'trust/guard recheck'),
 (handoff,['serverbridge_session_correlation_required','SessionCorrelationID: req.SessionCorrelationID','transferSequence'],'handoff correlation proof'),
 (client,['FEATURE_PLAYER_SESSION_V3','BridgePlayerSessionRegistry','sessionCorrelationId','playerSessions.bind','playerSessions.get','playerSessions.clear'],'bridge runtime'),
 (registry,['ConcurrentHashMap','normalizeCorrelation','correlation.length() != 64'],'runtime registry'),
 (cert,['BridgePlayerSessionRegistry.class','playerSessionIntegration3','sessionCloneProtection','topologyWideSessionInvalidation'],'certification'),
]
for text,wants,label in checks:
    for want in wants:
        if want not in text: raise SystemExit(f'{label} missing {want!r}')
for text,want,label in [(preflight,'serverbridge-player-session-integration3-0197.py','preflight'),(ci,'serverbridge-player-session-integration3-0197.py','CI')]:
    if want not in text: raise SystemExit(f'{label} missing {want!r}')
for forbidden in ['ProcessBuilder(', 'Runtime.getRuntime().exec']:
    if forbidden in repo or forbidden in client:
        raise SystemExit(f'player session integration must not invoke OS shell: {forbidden}')
print('ServerBridge 0.19.7 Player Session Integration 3 production gate: PASS')
