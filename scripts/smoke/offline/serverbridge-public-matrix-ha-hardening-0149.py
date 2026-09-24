#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]
version=(root/'VERSION').read_text().strip()
if tuple(int(x) for x in version.split('.')[:3]) < (0,14,9): raise SystemExit('VERSION is older than 0.14.9')
def read(p): return (root/p).read_text(encoding='utf-8')
def require(text, needles, label):
    missing=[n for n in needles if n not in text]
    if missing: raise SystemExit(f'{label}: missing {missing}')
api=read('services/api/internal/dbmigrate/sql/0029_serverbridge_public_matrix_ha_hardening_0149.sql')
cli=read('cli/internal/dbmigrate/sql/0029_serverbridge_public_matrix_ha_hardening_0149.sql')
if api != cli: raise SystemExit('0.14.9 API/CLI migrations differ')
require(api,['idx_server_bridge_nodes_active_heartbeat_0149','idx_server_bridge_topology_active_freshness_0149','idx_server_bridge_handoffs_active_expiry_0149'],'0.14.9 migration')
repo=read('services/api/internal/repository/server_bridge_v2.go')
require(repo,['MaintainServerBridge','ServerBridgeHAStatus','pg_try_advisory_xact_lock(1409,149)','effective_status','ExpiredNonceBacklog'],'HA repository')
consume=repo[repo.index('func (r *SQLRepository) ConsumeServerBridgeNodeNonce'):repo.index('func (r *SQLRepository) SetServerBridgeNodeIntegrity')]
if 'DELETE FROM server_bridge_node_nonces_v2' in consume: raise SystemExit('nonce hot path still performs global cleanup')
public=read('services/api/internal/httpapi/server_bridge_public_matrix_0149.go')+read('services/api/internal/httpapi/routes_public.go')
require(public,['/api/v1/server-bridge/matrix','serverBridgeMatrixPlatforms0149','drop-in-zero-patch','runtime-e2e','build-compatibility'],'public matrix endpoint')
hardening=read('services/api/internal/httpapi/server_bridge_http_hardening_0149.go')+read('services/api/internal/httpapi/server_bridge_identity_0142.go')+read('services/api/internal/httpapi/rate_limit.go')+read('services/api/internal/config/config.go')
require(hardening,['64 << 10','serverBridgeRequestTimeout0149','serverbridge','RateLimitServerBridgePerMinute','NEVERLAUNCHER_RATE_LIMIT_SERVERBRIDGE_PER_MINUTE'],'HTTP/rate hardening')
obs=read('services/api/internal/httpapi/observability.go')+read('services/api/internal/httpapi/bridge_plugins.go')
require(obs,['serverBridgeHA','neverlauncher_serverbridge_nodes_fresh','ha-advisory-lock-maintenance'],'HA observability')
matrix=read('serverbridge/targets.json')+read('scripts/serverbridge/matrix.py')
require(matrix,['"velocity"','"bungeecord"','"waterfall"','"bukkit"','"fabric"','"forge"','"neoforge"','productVersion'],'public matrix source')
e2e=read('e2e/scripts/run-serverbridge-ha-hardening-migration-e2e.sh')+read('services/api/internal/repository/server_bridge_ha_0149_integration_test.go')
require(e2e,['0028_zero_patch_topology_handoff_0148','0029_serverbridge_public_matrix_ha_hardening_0149','TestServerBridgeHA0149','exactly one nonce consumer'],'HA PostgreSQL E2E')
preflight=read('scripts/release/preflight.sh')
require(preflight,['serverbridge-public-matrix-ha-hardening-0149.py'],'release preflight')
ci=read('.github/workflows/ci.yml')
require(ci,['serverbridge-public-matrix-ha-hardening-0149.py','scripts/serverbridge/matrix.py validate','run-serverbridge-ha-hardening-migration-e2e.sh'],'CI wiring')
print(f'NeverLauncher 0.14.9 Public ServerBridge Matrix + HA/hardening gate: OK ({version})')
