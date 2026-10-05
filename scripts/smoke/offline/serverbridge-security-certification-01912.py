#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
def read(rel): return (ROOT/rel).read_text(encoding='utf-8')
def require(text, needles, label):
    for needle in needles:
        if needle not in text: raise SystemExit(f'{label}: missing {needle!r}')

version=read('VERSION').strip(); base=tuple(int(x) for x in version.split('-',1)[0].split('.')[:3])
if base < (0,19,12): raise SystemExit(f'Security & Certification gate requires VERSION>=0.19.12, got {version}')
security=read('services/api/internal/httpapi/server_bridge_security_01912.go')
identity=read('services/api/internal/httpapi/server_bridge_identity_0142.go')
protocol=read('services/api/internal/httpapi/server_bridge_protocol_0191.go')
events=read('services/api/internal/httpapi/server_bridge_events_0194.go')
control=read('services/api/internal/httpapi/server_bridge_control_0195.go')
client=read('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java')
trust=read('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeControlTrust.java')
event_record=read('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeEventRecord.java')
build=read('scripts/build/bridge-plugins.sh')
cert=read('serverbridge/certify_release.py')
cli=read('cli/cmd/neverlauncher/serverbridge_release.go')
contracts=read('scripts/contracts/generate_openapi.py')
tests=read('services/api/internal/httpapi/server_bridge_security_01912_test.go')
event_tests=read('services/api/internal/httpapi/server_bridge_events_0194_test.go')
harness=read('e2e/java/ru/neverlauncher/bridge/common/ServerBridgeSecurityCertification01912Harness.java')
preflight=read('scripts/release/preflight.sh'); ci=read('.github/workflows/ci.yml'); e2e=read('e2e/scripts/run-serverbridge-security-certification-01912-e2e.sh')

require(security,['NeverLauncher-ServerBridge-Protocol-v3','serverbridge3-security-01912','serverBridgeNodeRequestCanonical01912','serverBridgeEventCanonical01912','serverBridgeControlCanonical01912','ServerBridgeControlPreviousSigningPrivateKey'],'canonical v3 domain')
require(protocol,['securityCapabilityDigest','capabilitySignature','previousCapabilitySignature','activeSigningKeyFingerprint'],'signed capability negotiation')
require(identity,['X-NeverLauncher-Security-Profile','X-NeverLauncher-Capability-Digest','X-NeverLauncher-Runtime-Id','serverbridge_capability_downgrade_detected','serverbridge_runtime_binding_mismatch'],'node v3 binding')
require(events,['securityCapabilityDigest','nodeKeyFingerprint','serverBridgeEventCanonical01912','serverbridge_event_security_binding_invalid'],'event signatures')
require(control,['identityEpoch','v3SigningPublicKey','previousV3SigningPublicKey','serverBridgeControlCanonical01912','legacyKey = *previousKey'],'command signatures/rotation')
require(client,['SUPPORTED_PROTOCOLS = List.of(BridgeDefaults.PROTOCOL_VERSION)','Protocol v3 downgrade detected','BridgeProtocolSecurity.REQUIRED_FEATURES','X-NeverLauncher-Runtime-Id','X-NeverLauncher-Capability-Digest'],'bridge downgrade/runtime protection')
if 'LEGACY_PROTOCOL_VERSION)' in client.split('SUPPORTED_PROTOCOLS',1)[1].split(';',1)[0]: raise SystemExit('0.19.12 bridge must not offer Protocol v2')
require(trust,['verifyCapabilities','persistPins','previousPublicKey','command endpoint can never bootstrap trust'],'online key rotation trust')
require(event_record,['BridgeProtocolSecurity.eventCanonical','nodeKeyFingerprint','securityCapabilityDigest'],'v3 event signer')
require(build,['"schemaVersion":"3.0"','"release":"ServerBridge 3"','serverbridge3-security-01912','088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4'],'ServerBridge 3 release allowlist')
require(cert,['SECURITY_PROFILE','SECURITY_FEATURES','securityCapabilityDigest','BridgeProtocolSecurity.class'],'release certification')
require(cli,['serverBridgeSecurityCertificationRequired01912','ServerBridge 3 release allowlist security metadata mismatch'],'CLI release verifier')
require(contracts,['serverbridge3-security-01912','securityCapabilityDigest','activeSigningKeyFingerprint','previousCapabilitySignature','nodeKeyFingerprint'],'OpenAPI v3 security contract')
require(tests,['NodeCanonicalRejectsTamper','EventRejectsTamper','CommandCanonicalRejectsReplayAcrossRuntime','AllowlistRejectsTamperedBridge','SecurityFeatureSetIsExact'],'Go adversarial tests')
require(event_tests,['TestServerBridgeEventMemoryAckReplay0194'],'event replay/idempotency regression')
require(e2e,['TARGETS=(velocity bungeecord waterfall bukkit spigot paper purpur folia fabric quilt forge neoforge sponge vanilla)','for target in "${TARGETS[@]}"'],'per-target E2E execution')
require(harness,['overlap key rotation','retired previous key cannot authorize rotation after finalize','capability downgrade rejected','tampered bridge artifact rejected by certified hash','replayed event preserves original signed sequence','tampered/runtime-replayed command rejected','tampered/runtime-replayed event rejected','tampered node runtime rejected'],'runtime adversarial harness')

matrix=json.loads(read('serverbridge/security-e2e-matrix.json'))
expected=['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla']
required={'canonical-v3-domain','capability-downgrade','tampered-bridge-artifact','tampered-node-request','tampered-event','replayed-event','tampered-command','replayed-command','runtime-instance-rebind','online-key-rotation'}
if matrix.get('targets') != expected or set(matrix.get('requiredScenarios',[])) != required or matrix.get('coverage') != 'all-required-scenarios-on-every-target': raise SystemExit('complete ServerBridge 3 E2E matrix missing')
for text,needle,label in [(preflight,'serverbridge-security-certification-01912.py','preflight gate'),(preflight,'run-serverbridge-security-certification-01912-e2e.sh','preflight E2E'),(ci,'serverbridge-security-certification-01912.py','CI gate'),(ci,'run-serverbridge-security-certification-01912-e2e.sh','CI E2E')]:
    if needle not in text: raise SystemExit(f'{label}: missing {needle}')
print('ServerBridge Security & Certification 0.19.12+ production gate: OK')
