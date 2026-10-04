#!/usr/bin/env python3
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[3]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def require(text, needles, label):
    for n in needles:
        if n not in text: raise SystemExit(f'{label}: missing {n!r}')

version=read('VERSION').strip()
if version!='0.19.9': raise SystemExit(f'expected VERSION 0.19.9, got {version}')
main=read('cli/cmd/neverlauncher/main.go')
prov=read('cli/cmd/neverlauncher/serverbridge_provisioning_0199.go')
tests=read('cli/cmd/neverlauncher/serverbridge_provisioning_0199_test.go')
release=read('cli/cmd/neverlauncher/serverbridge_release.go')
require(main,['case "server-bridge", "serverbridge":','handleServerBridge0199'], 'CLI command wiring')
require(prov,[
    'case "detect":','case "install":','case "enroll":','case "status":','case "upgrade":','case "rollback":',
    'detectServerBridgePlatform0199','detectHybridCore0199','mohist','arclight','magma','catserver','banner','cardboard',
    'verifyBridgeArtifactShape0199','SERVERBRIDGE3_CERTIFICATION.json','BRIDGE_RELEASE_ALLOWLIST.json',
    'ed25519.GenerateKey','x509.MarshalPKCS8PrivateKey','privateKeyPkcs8','KeyFingerprint',
    'beginBridgeTransaction0199','txSnapshotPath0199','restoreBridgeTransaction0199','--dry-run',
    'coreFilesModified','installVanillaSidecarLaunchers0199','already-enrolled','rotate-identity',
], 'Zero-Patch provisioning implementation')
for forbidden in ['server.properties =', 'authlib-injector', 'patchAuthlib', 'rewriteCoreJar']:
    if forbidden in prov: raise SystemExit(f'provisioner contains forbidden core/authlib patch path: {forbidden}')
require(tests,[
    'TestServerBridgeDetectPaper0199','TestServerBridgeDetectHybridFailsClosed0199',
    'TestServerBridgeInstallIdentityEnrollmentAndRollback0199','TestServerBridgeDryRunDoesNotMutate0199',
    'TestServerBridgeReleaseTargetCohortIncludesUniversalAdapters0199',
], '0.19.9 provisioning tests')
require(release,['serverBridgeUniversalReleaseTargets0198','serverBridgeReleaseTargetsForVersion0150','serverBridgeUniversalAdaptersRequired0198'], 'release cohort verifier')
targets=json.loads(read('serverbridge/targets.json'))
if targets.get('productVersion')!='0.19.9' or len(targets.get('targets',[]))!=14:
    raise SystemExit('0.19.9 ServerBridge target metadata mismatch')
hybrid=json.loads(read('serverbridge/hybrid-targets.json'))
if hybrid.get('productVersion')!='0.19.9' or any(x.get('status')!='not-certified' for x in hybrid.get('targets',[])):
    raise SystemExit('0.19.9 hybrid certification metadata mismatch')
print('ServerBridge Zero-Patch Provisioning 0.19.9 production gate: OK')
