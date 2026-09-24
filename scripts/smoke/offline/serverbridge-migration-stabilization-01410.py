#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]
version=(root/'VERSION').read_text().strip()
if tuple(int(x) for x in version.split('.')[:3]) < (0,14,10): raise SystemExit('VERSION is older than 0.14.10')
def read(p): return (root/p).read_text(encoding='utf-8')
def require(text, needles, label):
    missing=[n for n in needles if n not in text]
    if missing: raise SystemExit(f'{label}: missing {missing}')
api=read('services/api/internal/dbmigrate/sql/0030_serverbridge_migration_stabilization_01410.sql')
cli=read('cli/internal/dbmigrate/sql/0030_serverbridge_migration_stabilization_01410.sql')
if api != cli: raise SystemExit('0.14.10 API/CLI migrations differ')
require(api,[
    'idx_server_bridge_join_consumed_source_01410',
    'idx_server_bridge_nodes_name_folded_01410',
    'idx_server_bridge_join_terminal_retention_01410',
    'idx_server_bridge_handoff_terminal_retention_01410',
    "status='invalidated'", "status='expired'", 'DELETE FROM server_bridge_node_nonces_v2'
],'0.14.10 migration')
repo=read('services/api/internal/repository/server_bridge_v2.go')+read('services/api/internal/httpapi/server_bridge_ha_0149.go')
require(repo,[
    'FOR UPDATE SKIP LOCKED',
    'TerminalJoinTicketsPurged',
    'TerminalHandoffsPurged',
    'serverBridgeMaintenanceTimeout01410',
    "a.status<>'active' OR a.expires_at <= $1",
    "interval '1 hour'"
],'0.14.10 maintenance')
if 'ctid IN (SELECT ctid FROM server_bridge_' in repo:
    raise SystemExit('legacy ctid maintenance path is still present')
model=read('services/api/internal/model/model.go')
require(model,['terminalJoinTicketsPurged','terminalHandoffsPurged'],'maintenance telemetry')
preflight=read('scripts/release/preflight.sh')
require(preflight,['serverbridge-migration-stabilization-01410.py'],'release preflight')
ci=read('.github/workflows/ci.yml')
require(ci,['serverbridge-migration-stabilization-01410.py','run-serverbridge-migration-stabilization-e2e.sh'],'CI wiring')
print(f'NeverLauncher 0.14.10 ServerBridge migration + stabilization gate: OK ({version})')
