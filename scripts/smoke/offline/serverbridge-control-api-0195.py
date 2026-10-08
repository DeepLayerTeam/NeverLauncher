#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
version = tuple(map(int, (ROOT / "VERSION").read_text(encoding="utf-8").strip().split(".")[:3]))
if version < (0, 19, 5):
    raise SystemExit(f"ServerBridge Control API gate requires VERSION>=0.19.5, got {version}")

required = [
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlCommand.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlExecutor.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlJournal.java",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlTrust.java",
    "services/api/internal/httpapi/server_bridge_control_0195.go",
    "services/api/internal/httpapi/server_bridge_control_0195_test.go",
    "services/api/internal/repository/server_bridge_control_0195_integration_test.go",
    "services/api/internal/dbmigrate/sql/0036_serverbridge_control_api_0195.sql",
    "cli/internal/dbmigrate/sql/0036_serverbridge_control_api_0195.sql",
]
for rel in required:
    if not (ROOT / rel).is_file():
        raise SystemExit(f"missing 0.19.5 Control API production file: {rel}")

checks = {
    "services/api/internal/httpapi/routes_bridge.go": [
        "POST /api/v1/server-bridge/servers/{serverId}/control",
        "GET /api/v1/server-bridge/servers/{serverId}/control/{commandId}",
        "GET /api/v1/server-bridge/servers/{serverId}/control/poll",
        "POST /api/v1/server-bridge/servers/{serverId}/control/ack",
        "serverbridge:control",
    ],
    "services/api/internal/httpapi/server_bridge_control_0195.go": [
        "serverbridge:console", "Idempotency-Key", "ed25519.Sign", "serverBridgeControlCanonical0195",
        "player.kick", "message.broadcast", "whitelist.add", "ban.add", "server.save",
        "server.maintenance", "server.drain", "server.shutdown", "server.console",
        "serverBridgeConsoleAllowlist0195",
    ],
    "services/api/internal/repository/server_bridge_v2.go": [
        "CreateServerBridgeControlCommand", "LeaseServerBridgeControlCommand", "CompleteServerBridgeControlCommand",
        "server_bridge_control_commands_v3", "pg_advisory_xact_lock", "serverbridge:control:queued",
        "serverbridge:control:delivered", "serverbridge:control:", "ControlCommandsPurged",
    ],
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java": [
        "startControlChannel", "FEATURE_CONTROL_API", "BridgeControlTrust", "BridgeControlJournal",
        "controlJournal.begin", "controlJournal.complete", "indeterminate",
    ],
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlCommand.java": [
        "executionDigest", "Control-Execution-v1", "canonical()",
    ],
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlTrust.java": [
        "Ed25519", "https", "localhost", "ATOMIC_MOVE",
    ],
    "plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java": [
        "executeControl", "server.maintenance", "server.drain", "server.console", "dispatchCommand",
    ],
    "plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java": [
        "executeControl", "server.console", "executeAsync", "operation_not_supported_by_velocity_core",
    ],
    "plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java": [
        "executeControl", "server.console", "dispatchCommand", "operation_not_supported_by_bungee_core",
    ],
    "plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java": [
        "executeControl", "executeWithPrefix", "server.shutdown",
    ],
    "plugins/forge-bridge/src/main/java/ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.java": [
        "executeControl", "performPrefixedCommand", "server.shutdown",
    ],
    "plugins/neoforge-bridge/src/main/java/ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.java": [
        "executeControl", "performPrefixedCommand", "server.shutdown",
    ],
    "serverbridge/certify_release.py": [
        "BridgeControlCommand.class", "BridgeControlJournal.class", "BridgeControlTrust.class", "controlShellExecution",
    ],
    "scripts/contracts/generate_openapi.py": [
        "ServerBridgeControlCreateV3", "ServerBridgeControlDeliveryV3", "ServerBridgeControlAckRequestV3",
    ],
}
for rel, needles in checks.items():
    text = (ROOT / rel).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{rel}: missing {needle!r}")

# OS shell/process execution is forbidden in the complete Control API path.
control_sources = [
    ROOT / "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java",
    ROOT / "plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java",
    ROOT / "plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java",
    ROOT / "plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java",
    ROOT / "plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java",
    ROOT / "plugins/forge-bridge/src/main/java/ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.java",
    ROOT / "plugins/neoforge-bridge/src/main/java/ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.java",
]
for path in control_sources:
    text = path.read_text(encoding="utf-8")
    for forbidden in ("ProcessBuilder", "Runtime.getRuntime().exec", "java.lang.Process", "server.shell"):
        if forbidden in text:
            raise SystemExit(f"{path.relative_to(ROOT)}: forbidden arbitrary process execution marker {forbidden!r}")

migration = (ROOT / "services/api/internal/dbmigrate/sql/0036_serverbridge_control_api_0195.sql").read_text(encoding="utf-8")
for required_sql in ("UNIQUE (server_id, requested_by, idempotency_key)", "runtime_epoch", "runtime_id", "serverbridge:control", "serverbridge:console"):
    if required_sql not in migration:
        raise SystemExit(f"control migration missing {required_sql!r}")

print("ServerBridge 0.19.5 Control API production gate: PASS")
