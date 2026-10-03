#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]

required_files = [
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeTelemetrySampler.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeTelemetrySnapshot.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgePlatformTelemetry.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeTickSampler.java",
    "services/api/internal/httpapi/server_bridge_telemetry_0193.go",
    "services/api/internal/dbmigrate/sql/0034_serverbridge_telemetry_0193.sql",
    "cli/internal/dbmigrate/sql/0034_serverbridge_telemetry_0193.sql",
]
for rel in required_files:
    if not (ROOT / rel).is_file():
        raise SystemExit(f"missing telemetry production file: {rel}")

checks = {
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java": [
        "FEATURE_SERVER_TELEMETRY", "telemetryFields", "telemetrySampler.sample",
    ],
    "plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java": [
        "recordPlatformTelemetry", "telemetrySamplingBudgetMs", "getChunkCount", "getEntityCount",
    ],
    "plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java": [
        "ServerTickEvents.START_SERVER_TICK", "ServerTickEvents.END_SERVER_TICK", "iterateEntities", "getLoadedChunkCount",
    ],
    "plugins/forge-bridge/src/main/java/ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.java": [
        "ServerTickEvent.Pre", "ServerTickEvent.Post", "getLoadedChunksCount", "getAllEntities",
    ],
    "plugins/neoforge-bridge/src/main/java/ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.java": [
        "ServerTickEvent.Pre", "ServerTickEvent.Post", "getLoadedChunksCount", "getAllEntities",
    ],
    "plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java": [
        "getPlayerCount", "getShowMaxPlayers", "recordPlatformTelemetry",
    ],
    "plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java": [
        "getOnlineCount", "recordPlatformTelemetry",
    ],
    "services/api/internal/httpapi/server_bridge_protocol_0191.go": [
        'telemetry.server-v1', "bridgeServerTelemetryV3Contract0193",
    ],
    "services/api/internal/httpapi/bridge_plugins.go": [
        "validateBridgeTelemetry0193", "saveTelemetry0193", "serverbridge_telemetry_conflict",
    ],
    "services/api/internal/repository/server_bridge_v2.go": [
        "SaveServerBridgeTelemetry", "server_bridge_telemetry_samples_v3", "OFFSET 4096", "interval '7 days'",
    ],
    "serverbridge/certify_release.py": [
        "BridgeTelemetrySampler.class", "boundedTelemetrySampling",
    ],
}
for rel, needles in checks.items():
    text = (ROOT / rel).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{rel}: missing {needle!r}")

if (ROOT / "VERSION").read_text(encoding="utf-8").strip() != "0.19.3":
    raise SystemExit("VERSION is not 0.19.3")

print("ServerBridge 0.19.3 telemetry production gate: PASS")
