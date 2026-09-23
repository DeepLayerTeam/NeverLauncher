#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]

def read(path): return (root/path).read_text(encoding='utf-8')
def require(text, needles, label):
    missing=[needle for needle in needles if needle not in text]
    if missing: raise SystemExit(f'{label}: missing {missing}')

def version_tuple(value): return tuple(int(part) for part in value.split('.'))
if version_tuple((root/'VERSION').read_text().strip()) < (0,13,8): raise SystemExit('VERSION is older than 0.13.8')

policy=read('runtime/neverruntime/src/macos_policy.rs')
require(policy,['PT_DENY_ATTACH','RLIMIT_CORE','kqueue','EVFILT_PROC','NOTE_EXIT','setpgid','codesign','Hardened Runtime','neverguard/macos-runtime-process-policy/v1'],'macOS runtime hardening')
ipc=read('runtime/neverruntime/src/macos_guard.rs')
require(ipc,['UnixListener','UnixStream','peer_cred','0o600','client-auth','Hmac','MACOS_PACKAGE_MANIFEST.json','spctl','guard-attestation','integrity-evidence','desktop_sha256','guard_sha256','ru.skif4er.neverlauncher.guard'],'macOS authenticated IPC/package verification')
integrity=read('runtime/neverruntime/src/integrity.rs')
require(integrity,['neverguard/macos-integrity-evidence/v1','proc_pidinfo','proc_pidpath','MacOSProcessSecurityEvidence','hardened_runtime','library_validation'],'macOS integrity evidence')
att=read('runtime/neverruntime/src/attestation.rs')
require(att,['neverguard/macos-guard-attestation/v1','Guard Attestation Core macOS v1'],'macOS attestation')
desktop=read('apps/desktop/src-tauri/src/main.rs')
require(desktop,['target_os = "macos"','NEVERGUARD_MACOS_PROCESS_POLICY_VERSION','ensure_macos_production_hardening','NeverGuard macOS production hardening verification failed'],'Desktop macOS enforcement')
backend=read('services/api/internal/httpapi/guard_attestation_0134.go')
require(backend,['guardMacOSAttestationSchema0138','guardMacOSIntegritySchema0138','guardMacOSProcessPolicySchema0138','isMacOSDevicePlatform0138','NeverGuard macOS process policy verification failed'],'Backend macOS verification')
tests=read('services/api/internal/httpapi/guard_attestation_0134_test.go')
require(tests,['TestMacOSGuardAttestationValidation0138','LibraryValidation = false'],'Backend macOS tests')
release=read('scripts/release/build-macos-desktop.sh')
require(release,['aarch64-apple-darwin','x86_64-apple-darwin','lipo -create','Developer','notarytool submit','stapler staple','spctl --assess','GUARD_RELEASE_ALLOWLIST_MACOS.json','MACOS_PACKAGE_MANIFEST.json','desktopSha256','guardSha256','desktopSize','guardSize','--identifier ru.skif4er.neverlauncher.guard'],'macOS release package')
ci=read('.github/workflows/ci.yml')
require(ci,['neverguard-macos:','neverguard_macos','codesign --force --sign - --options runtime','build-macos-desktop.sh','macos-production-implementation-0138.py'],'CI macOS gate')
preflight=read('scripts/release/preflight.sh')
require(preflight,['macos-production-implementation-0138.py'],'preflight macOS gate')
print('NeverLauncher 0.13.8 macOS production implementation gate: OK')
