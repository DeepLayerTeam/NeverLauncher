#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / 'VERSION').read_text(encoding='utf-8').strip()
parts = tuple(int(x) for x in version.split('-', 1)[0].split('+', 1)[0].split('.')[:3])
if parts < (0, 19, 2):
    raise SystemExit(f'ServerBridge runtime identity gate requires VERSION>=0.19.2, got {version}')


def read(path: str) -> str:
    return (root / path).read_text(encoding='utf-8')


def require(path: str, needles: list[str]) -> None:
    text = read(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f'{path}: missing {missing}')


require('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeRuntimeIdentity.java', [
    'NeverLauncher-ServerBridge-RuntimeIdentity-v1',
    'NeverLauncher-ServerBridge-RuntimeId-v1',
    'BridgeRuntimeProbe.jvmStartMillis()',
    'BridgeRuntimeProbe.processId()',
    'identity.sign(canonical)',
    'runtimeId',
    'uptimeSeconds',
    'nodeKeyFingerprint',
])
require('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java', [
    'FEATURE_RUNTIME_DISCOVERY', 'FEATURE_RUNTIME_IDENTITY', 'runtimeIdentity.toJson()',
])
require('services/api/internal/httpapi/server_bridge_runtime_0192.go', [
    'bridgeRuntimeID0192', 'ed25519.Verify', 'runtime_id_binding_invalid',
    'runtime identity mutated for existing runtime id', 'transition = "replacement"', 'transition = "restart"',
])
require('services/api/internal/repository/server_bridge_v2.go', [
    'TouchServerBridgeNodeRuntimeHeartbeat', 'server_bridge_runtime_instances_v3', 'FOR UPDATE',
])
require('services/api/internal/dbmigrate/sql/0033_serverbridge_runtime_identity_0192.sql', [
    'runtime_identity_signature', 'runtime_process_id', 'server_bridge_runtime_instances_v3', 'replacement_detected',
])
if read('services/api/internal/dbmigrate/sql/0033_serverbridge_runtime_identity_0192.sql') != read('cli/internal/dbmigrate/sql/0033_serverbridge_runtime_identity_0192.sql'):
    raise SystemExit('API/CLI 0.19.2 ServerBridge runtime migrations differ')

for path, platform in [
    ('plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java', 'plugin.bukkit-api'),
    ('plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java', 'proxy.bungee-api'),
    ('plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java', 'proxy.velocity-api'),
    ('plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java', 'loader.fabric'),
    ('plugins/forge-bridge/src/main/java/ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.java', 'loader.forge'),
    ('plugins/neoforge-bridge/src/main/java/ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.java', 'loader.neoforge'),
]:
    require(path, ['BridgeRuntimeDescriptor', 'runtime.discovery', 'runtime.ed25519-attestation', platform])

require('serverbridge/certify_release.py', ['BridgeRuntimeIdentity.class', 'BridgeRuntimeDescriptor.class', 'BridgeRuntimeProbe.class', 'runtimeReplacementDetection'])
require('schemas/openapi.yaml', ['ServerBridgeRuntimeIdentityV3', 'startedAtUnixMillis', 'nodeKeyFingerprint', 'identitySignature'])
require('services/api/internal/httpapi/server_bridge_runtime_0192_test.go', ['VerifiesNodeBoundProcessIdentity', 'DetectsReplacementAndRestart'])
print(f'NeverLauncher {version} ServerBridge Node Discovery & Runtime Identity gate: OK')
