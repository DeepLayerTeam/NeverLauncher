#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

version = tuple(map(int, (ROOT / "VERSION").read_text(encoding="utf-8").strip().split(".")[:3]))
if version < (0, 19, 4):
    raise SystemExit("VERSION is older than the event-stream 0.19.4 release")

required_files = [
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeEventRecord.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeEventJournal.java",
    "services/api/internal/httpapi/server_bridge_events_0194.go",
    "services/api/internal/dbmigrate/sql/0035_serverbridge_event_stream_0194.sql",
    "cli/internal/dbmigrate/sql/0035_serverbridge_event_stream_0194.sql",
    "services/api/internal/httpapi/server_bridge_events_0194_test.go",
    "services/api/internal/repository/server_bridge_event_stream_0194_integration_test.go",
]
for rel in required_files:
    if not (ROOT / rel).is_file():
        raise SystemExit(f"missing ServerBridge event-stream production file: {rel}")

checks = {
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java": [
        "FEATURE_EVENT_STREAM", "publishEvent", "flushEventsNow", "closeEventStreamCleanly",
        "eventJournal", "acknowledge", "nextBatch(64)",
    ],
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeEventJournal.java": [
        "MAX_PENDING", "acknowledge", "compact", "StandardCopyOption.ATOMIC_MOVE",
    ],
    "plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java": [
        '"server.startup"', '"server.ready"', '"server.shutdown"', '"player.login"',
        '"player.join"', '"player.quit"', '"player.kick"', '"world.load"', '"world.unload"',
    ],
    "plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java": [
        '"player.login"', '"proxy.connect"', '"proxy.switch"',
    ],
    "plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java": [
        '"player.login"', '"proxy.connect"', '"proxy.switch"',
    ],
    "plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java": [
        "ServerPlayConnectionEvents", "ServerWorldEvents", '"server.shutdown"', '"server.error"',
    ],
    "plugins/forge-bridge/src/main/java/ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.java": [
        "PlayerEvent.PlayerLoggedInEvent", "PlayerEvent.PlayerLoggedOutEvent", "LevelEvent.Load", "LevelEvent.Unload",
    ],
    "plugins/neoforge-bridge/src/main/java/ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.java": [
        "PlayerEvent.PlayerLoggedInEvent", "PlayerEvent.PlayerLoggedOutEvent", "LevelEvent.Load", "LevelEvent.Unload",
    ],
    "services/api/internal/httpapi/server_bridge_protocol_0191.go": [
        'events.ordered-stream-v1',
    ],
    "services/api/internal/httpapi/routes_bridge.go": [
        'POST /api/v1/server-bridge/servers/{serverId}/events',
    ],
    "services/api/internal/httpapi/server_bridge_events_0194.go": [
        "ed25519.Verify", "serverBridgeEventBatchMax0194", "ackSequence", "serverbridge_event_stream_conflict",
    ],
    "services/api/internal/repository/server_bridge_v2.go": [
        "AppendServerBridgeEvents", "server_bridge_event_cursors_v3", "server_bridge_events_v3",
        "serverbridge:event:", "interval '30 days'", "EventStreamRowsPurged",
    ],
    "serverbridge/certify_release.py": [
        "BridgeEventRecord.class", "BridgeEventJournal.class", "serverEventStream", "eventReplayProtection",
    ],
    "scripts/contracts/generate_openapi.py": [
        'ServerBridgeEventBatchV3', 'ServerBridgeEventAckV3', '/api/v1/server-bridge/servers/{serverId}/events',
    ],
}
for rel, needles in checks.items():
    text = (ROOT / rel).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{rel}: missing {needle!r}")

required_types = {
    "server.startup", "server.ready", "server.shutdown", "server.crash", "server.error",
    "player.login", "player.join", "player.quit", "player.kick",
    "world.load", "world.unload", "proxy.connect", "proxy.switch",
}
event_source = (ROOT / "services/api/internal/httpapi/server_bridge_events_0194.go").read_text(encoding="utf-8")
for event_type in sorted(required_types):
    if f'"{event_type}"' not in event_source:
        raise SystemExit(f"missing event type {event_type}")

print("ServerBridge 0.19.4 ordered event-stream production gate: PASS")
