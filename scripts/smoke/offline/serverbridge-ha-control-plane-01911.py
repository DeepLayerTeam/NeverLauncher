#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel): return (ROOT / rel).read_text(encoding="utf-8")
def require(text, needles, label):
    for needle in needles:
        if needle not in text: raise SystemExit(f"{label}: missing {needle!r}")

version = read("VERSION").strip()
parts = tuple(int(x) for x in version.split("-",1)[0].split(".")[:3])
if parts < (0,19,11): raise SystemExit(f"HA Control Plane gate requires VERSION>=0.19.11, got {version}")

control = read("services/api/internal/httpapi/server_bridge_control_0195.go")
repo = read("services/api/internal/repository/server_bridge_v2.go")
coord = read("services/api/internal/serverbridgeha/redis.go")
migration = read("services/api/internal/dbmigrate/sql/0040_serverbridge_ha_control_plane_01911.sql")
runtime = read("services/api/internal/httpapi/rate_limit.go")
observability = read("services/api/internal/httpapi/observability.go")
config = read("services/api/internal/config/config.go")
client = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java")
pool = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeBackendPool.java")
journal = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlJournal.java")
command = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlCommand.java")
bridge_config = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeConfig.java")
redis_tests = read("services/api/internal/serverbridgeha/redis_test.go")
pg_tests = read("services/api/internal/repository/server_bridge_ha_control_plane_01911_integration_test.go")
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")

require(bridge_config,["backend.urls","NEVERLAUNCHER_BACKEND_URLS","failoverCooldownMs"],"multi-endpoint config")
require(pool,["AtomicInteger","blockedUntilMillis","candidates(","success(","failure("],"endpoint pool")
require(client,["sendSignedWithFailover","sendUnsignedGetWithFailover","isRetryableBackendStatus","status == 502 || status == 503 || status == 504","FEATURE_HA_CONTROL_PLANE","channelId=","resumeAfter="],"bridge failover/resume")
require(journal,["_channel.id","_channel.ackedSequence","acknowledgeSequence"],"durable channel cursor")
require(command,["deliverySequence","leaseToken","executionDigest","deliberately excludes lease attempt/timestamps"],"stable exactly-once identity")
require(migration,["delivery_sequence BIGSERIAL","lease_owner","lease_token","idx_server_bridge_control_resume_01911","idx_server_bridge_control_owner_01911"],"HA migration")
require(repo,["FOR UPDATE SKIP LOCKED","lease_owner=$4","delivery_sequence>$6","invalid control lease identity","idempotent fenced commit"],"PostgreSQL ownership")
require(coord,["acquireLeaseScript","releaseLeaseScript","AcquireCommandLease","VerifyCommandLease","ReleaseCommandLease","TouchChannel"],"Redis fencing")
require(runtime,["ServerBridgeCoordinator","coordinator.Health","ServerBridge HA coordinator is required but unavailable"],"runtime fail closed")
require(observability,["ServerBridgeHARequired","serverBridgeCoordinator","ServerBridgeCoordinator.Health"],"HA readiness fail closed")
require(config,["NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED","NEVERLAUNCHER_REPLICA_ID","NEVERLAUNCHER_REDIS_URL обязателен для ServerBridge HA fencing"],"HA config")
require(control,["authenticateBridgeNodeRequest0142(r)","serverbridge_ha_coordinator_unavailable","serverbridge_control_lease_fenced","DeliverySequence","LeaseToken","serverBridgeFeatureHAControlPlane"],"HA control handlers")
require(redis_tests,["TestRedisCoordinatorFencesCommandOwnership01911","competing acquire must be fenced"],"Redis runtime tests")
require(pg_tests,["TestServerBridgeHAControlPlane01911MultiReplica","expected one distributed owner","cross-replica idempotent ACK"],"PostgreSQL multi-replica tests")
for forbidden in ["status == 401 ||", "status == 403 ||"]:
    if forbidden in client: raise SystemExit("authentication rejection must not trigger endpoint failover")
for text, needle, label in [(preflight,"serverbridge-ha-control-plane-01911.py","preflight"),(ci,"serverbridge-ha-control-plane-01911.py","CI")]:
    if needle not in text: raise SystemExit(f"{label}: missing {needle!r}")
print("ServerBridge HA Control Plane 0.19.11+ production gate: OK")
