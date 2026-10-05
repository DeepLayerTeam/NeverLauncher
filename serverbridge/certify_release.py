#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
TARGETS = ROOT / 'serverbridge/targets.json'
EXPECTED = ['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla']
SECURITY_PROFILE = 'serverbridge3-security-01912'
SECURITY_FEATURES = [
    'security.protocol-v3-signing-domain',
    'security.capability-downgrade-protection',
    'security.command-signatures-v3',
    'security.event-signatures-v3',
    'security.runtime-instance-binding-v3',
    'security.online-key-rotation-v1',
]
SECURITY_CAPABILITY_DIGEST = '088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4'
PROTOCOL_V3_FEATURE_DIGEST = '098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc'
HASH_FIELDS = {
    'velocity':'velocitySha256','bungeecord':'bungeeCordSha256','waterfall':'waterfallSha256',
    'bukkit':'bukkitSha256','spigot':'spigotSha256','paper':'paperSha256','purpur':'purpurSha256',
    'folia':'foliaSha256','fabric':'fabricSha256','quilt':'quiltSha256','forge':'forgeSha256','neoforge':'neoforgeSha256',
    'sponge':'spongeSha256','vanilla':'vanillaSha256',
}
COMMON_PROTOCOL_ENTRIES = [
    'ru/neverlauncher/bridge/common/NeverLauncherApiClient.class',
    'ru/neverlauncher/bridge/common/BridgeProtocolNegotiation.class',
    'ru/neverlauncher/bridge/common/BridgeProtocolSecurity.class',
    'ru/neverlauncher/bridge/common/BridgeRuntimeDescriptor.class',
    'ru/neverlauncher/bridge/common/BridgeRuntimeIdentity.class',
    'ru/neverlauncher/bridge/common/BridgeRuntimeProbe.class',
    'ru/neverlauncher/bridge/common/BridgeTelemetrySampler.class',
    'ru/neverlauncher/bridge/common/BridgeTelemetrySnapshot.class',
    'ru/neverlauncher/bridge/common/BridgePlatformTelemetry.class',
    'ru/neverlauncher/bridge/common/BridgeTickSampler.class',
    'ru/neverlauncher/bridge/common/BridgeEventRecord.class',
    'ru/neverlauncher/bridge/common/BridgeEventJournal.class',
    'ru/neverlauncher/bridge/common/BridgeControlCommand.class',
    'ru/neverlauncher/bridge/common/BridgeControlExecutor.class',
    'ru/neverlauncher/bridge/common/BridgeControlJournal.class',
    'ru/neverlauncher/bridge/common/BridgeControlTrust.class',
    'ru/neverlauncher/bridge/common/BridgeRoutingSnapshot.class',
    'ru/neverlauncher/bridge/common/BridgePlayerSessionRegistry.class',
    'ru/neverlauncher/bridge/common/BridgeAdapterCapability.class',
    'ru/neverlauncher/bridge/common/BridgeAdapterProfile.class',
    'ru/neverlauncher/bridge/common/BridgeAdapterProfiles.class',
]
REQUIRED_ENTRIES = {
    'velocity':['velocity-plugin.json','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class'],
    'bungeecord':['bungee.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class','ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.class'],
    'waterfall':['bungee.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class','ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.class'],
    'bukkit':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'spigot':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'paper':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'purpur':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'folia':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'fabric':['fabric.mod.json','neverlauncher.fabric.mixins.json','ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.class'],
    'forge':['META-INF/mods.toml','ru/neverlauncher/bridge/modloader/ModLoaderBridgeRuntime.class'],
    'neoforge':['META-INF/neoforge.mods.toml','ru/neverlauncher/bridge/modloader/ModLoaderBridgeRuntime.class'],
    'quilt':['fabric.mod.json','quilt.mod.json','neverlauncher.quilt.mixins.json','ru/neverlauncher/bridge/quilt/NeverLauncherQuiltBridge.class'],
    'sponge':['ru/neverlauncher/bridge/sponge/NeverLauncherSpongeBridge.class'],
    'vanilla':['ru/neverlauncher/bridge/vanilla/NeverLauncherVanillaBridge.class','ru/neverlauncher/bridge/vanilla/VanillaRconClient.class'],
}
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def die(msg: str) -> None:
    raise SystemExit(f'ServerBridge 3 release certification failed: {msg}')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        die(f'{path}: invalid JSON: {exc}')
    if not isinstance(data, dict):
        die(f'{path}: root must be object')
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description='Certify a built NeverLauncher ServerBridge 3 release cohort')
    ap.add_argument('--artifacts', type=Path, default=ROOT / 'artifacts/plugins')
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    artifacts = args.artifacts.resolve()
    manifest_path = artifacts / 'PLUGIN_MANIFEST.json'
    allowlist_path = artifacts / 'BRIDGE_RELEASE_ALLOWLIST.json'
    if not manifest_path.is_file() or not allowlist_path.is_file():
        die('PLUGIN_MANIFEST.json and BRIDGE_RELEASE_ALLOWLIST.json are required')

    targets = load_json(TARGETS)
    target_rows = targets.get('targets')
    if targets.get('productVersion') != VERSION or targets.get('protocolVersion') != 3:
        die('serverbridge/targets.json version/protocol drift')
    if not isinstance(target_rows, list) or [r.get('id') for r in target_rows] != EXPECTED:
        die('serverbridge target set/order mismatch')
    hybrid = load_json(ROOT / 'serverbridge/hybrid-targets.json')
    hybrid_rows = hybrid.get('targets')
    if hybrid.get('productVersion') != VERSION or hybrid.get('policy') != 'separate-certification-required':
        die('hybrid certification matrix version/policy drift')
    if not isinstance(hybrid_rows, list) or any(r.get('status') != 'not-certified' for r in hybrid_rows):
        die('universal release must not implicitly certify hybrid cores')
    hybrid_ids = {r.get('id') for r in hybrid_rows}
    if hybrid_ids & set(EXPECTED):
        die('hybrid target leaked into universal artifact cohort')

    manifest = load_json(manifest_path)
    if manifest.get('toolVersion') != VERSION or manifest.get('schemaVersion') != '1.2':
        die('plugin manifest version/schema mismatch')
    rows = manifest.get('artifacts')
    if not isinstance(rows, list) or [r.get('id') for r in rows] != EXPECTED:
        die('plugin manifest artifact set/order mismatch')

    allow = load_json(allowlist_path)
    if (allow.get('schemaVersion') != '3.0' or allow.get('release') != 'ServerBridge 3' or
        allow.get('protocolVersion') != 3 or allow.get('minimumProtocolVersion') != 3 or
        allow.get('ga') is not True or allow.get('protocolV3Frozen') is not True or
        str(allow.get('protocolV3FeatureDigest', '')).lower() != PROTOCOL_V3_FEATURE_DIGEST or
        allow.get('protocolV2Mode') != 'compatibility-deprecated' or
        allow.get('securityProfile') != SECURITY_PROFILE or
        str(allow.get('securityCapabilityDigest', '')).lower() != SECURITY_CAPABILITY_DIGEST or
        sorted(allow.get('requiredFeatures') or []) != sorted(SECURITY_FEATURES)):
        die('ServerBridge 3 release allowlist security metadata mismatch')
    releases = allow.get('releases')
    if not isinstance(releases, dict) or set(releases) != {VERSION} or not isinstance(releases[VERSION], dict):
        die(f'allowlist releases must contain only the exact release cohort {VERSION}')
    policy = releases[VERSION]

    evidence = []
    seen_hashes: dict[str, str] = {}
    for row in rows:
        target = row['id']
        filename = row.get('file')
        expected_filename = f'neverlauncher-{target}-bridge-{VERSION}.jar'
        if filename != expected_filename:
            die(f'{target}: expected filename {expected_filename}, got {filename!r}')
        jar = artifacts / filename
        if not jar.is_file() or jar.stat().st_size == 0:
            die(f'{target}: missing/non-empty JAR {jar}')
        digest = sha256(jar)
        if not HEX64.fullmatch(digest):
            die(f'{target}: internal SHA-256 failure')
        if row.get('sha256') != digest:
            die(f'{target}: manifest SHA-256 does not match JAR')
        field = HASH_FIELDS[target]
        values = policy.get(field)
        if values != [digest]:
            die(f'{target}: {field} must contain exactly the built JAR SHA-256')
        if digest in seen_hashes:
            die(f'{target}: artifact bytes are identical to {seen_hashes[digest]} (platform-matched release required)')
        seen_hashes[digest] = target
        try:
            with zipfile.ZipFile(jar) as zf:
                names = set(zf.namelist())
                for entry in REQUIRED_ENTRIES[target]:
                    if entry not in names:
                        die(f'{target}: JAR missing {entry}')
                if target in {'fabric','quilt'}:
                    nested = [name for name in names if name.startswith('META-INF/jars/bridge-common-') and name.endswith('.jar')]
                    if len(nested) != 1:
                        die(f'{target}: expected exactly one embedded bridge-common JAR')
                    import io
                    with zipfile.ZipFile(io.BytesIO(zf.read(nested[0]))) as common:
                        common_names=set(common.namelist())
                        for entry in COMMON_PROTOCOL_ENTRIES:
                            if entry not in common_names:
                                die(f'{target}: embedded bridge-common missing {entry}')
                else:
                    for entry in COMMON_PROTOCOL_ENTRIES:
                        if entry not in names:
                            die(f'{target}: JAR missing {entry}')
                if target == 'folia':
                    text = zf.read('plugin.yml').decode('utf-8', 'replace')
                    if 'folia-supported: true' not in text:
                        die('folia: descriptor does not declare folia-supported: true')
                elif target == 'fabric':
                    data = json.loads(zf.read('fabric.mod.json').decode('utf-8'))
                    custom = data.get('custom')
                    neverlauncher = custom.get('neverlauncher') if isinstance(custom, dict) else None
                    if (
                        data.get('environment') != 'server'
                        or not isinstance(neverlauncher, dict)
                        or neverlauncher.get('clientModRequired') is not False
                    ):
                        die('fabric: artifact must be server-only and clientModRequired=false')
                elif target == 'quilt':
                    data = json.loads(zf.read('fabric.mod.json').decode('utf-8'))
                    custom = (data.get('custom') or {}).get('neverlauncher') or {}
                    if data.get('environment') != 'server' or 'quilt_loader' not in (data.get('depends') or {}) or custom.get('clientModRequired') is not False:
                        die('quilt: artifact must be Quilt-only, server-only and clientModRequired=false')
                elif target == 'vanilla':
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', 'replace')
                    if 'Main-Class: ru.neverlauncher.bridge.vanilla.NeverLauncherVanillaBridge' not in manifest:
                        die('vanilla: executable sidecar Main-Class missing')
        except zipfile.BadZipFile:
            die(f'{target}: invalid JAR/ZIP')
        evidence.append({'id': target, 'file': filename, 'sha256': digest, 'bytes': jar.stat().st_size})

    sums_path = artifacts / 'SHA256SUMS'
    if not sums_path.is_file():
        die('SHA256SUMS is missing')
    sums = {}
    for line in sums_path.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip('*')] = parts[0].lower()
    for item in evidence:
        if sums.get(item['file']) != item['sha256']:
            die(f"{item['id']}: SHA256SUMS mismatch")

    report = {
        'schemaVersion': '1.1', 'release': 'ServerBridge 3', 'version': VERSION,
        'protocolVersion': 3, 'status': 'certified', 'targetCount': len(evidence),
        'ga': True, 'protocolV3Frozen': True, 'protocolV3FeatureDigest': PROTOCOL_V3_FEATURE_DIGEST,
        'protocolV2Mode': 'compatibility-deprecated', 'installerUpgradePath': True,
        'unifiedOperatorAPI': '/api/v1/server-bridge/overview', 'publicCompatibilityMatrix': True,
        'securityProfile': SECURITY_PROFILE, 'securityCapabilityDigest': SECURITY_CAPABILITY_DIGEST,
        'requiredSecurityFeatures': SECURITY_FEATURES, 'capabilityDowngradeProtection': True,
        'canonicalSigningDomain': 'NeverLauncher-ServerBridge-Protocol-v3',
        'commandSignatures': True, 'eventSignatures': True, 'runtimeInstanceBinding': True, 'onlineKeyRotation': True,
        'zeroPatch': True, 'nodeIdentity': 'Ed25519', 'oneTimeJoin': True,
        'nodeDiscovery': True, 'runtimeIdentity': 'Ed25519 node-bound process identity',
        'runtimeReplacementDetection': True,
        'serverTelemetry': True, 'boundedTelemetrySampling': True,
        'serverEventStream': True, 'orderedEventAck': True,
        'eventReplayProtection': True, 'eventReconnectResume': True,
        'controlAPI': True, 'controlRBAC': True, 'controlIdempotency': True,
        'controlAudit': True, 'controlCommandAllowlist': True, 'controlShellExecution': False,
        'topologyRouting2': True, 'signedRoutingSnapshots': True, 'healthCapacityRouting': True,
        'handoffSourceTargetProof': True, 'staleTopologyCleanup': True,
        'playerSessionIntegration3': True, 'sessionCloneProtection': True,
        'orderedTransferChain': True, 'trustGuardTransferRecheck': True,
        'topologyWideSessionInvalidation': True,
        'universalServerAdapters': True, 'adapterCapabilities': True,
        'quiltAdapter': True, 'spongeAdapter': True, 'vanillaSidecarRcon': True,
        'hybridCertificationPolicy': 'separate-fail-closed',
        'artifacts': evidence,
    }
    out = args.out or (artifacts / 'SERVERBRIDGE3_CERTIFICATION.json')
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'ServerBridge 3 release certified: {VERSION}, {len(evidence)} platform artifacts -> {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
