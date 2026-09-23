#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]

def read(p): return (root/p).read_text(encoding='utf-8')
def require(text, needles, label):
    missing=[n for n in needles if n not in text]
    if missing: raise SystemExit(f'{label}: missing {missing}')

if (root/'VERSION').read_text().strip()!='0.13.7': raise SystemExit('VERSION is not 0.13.7')
policy=read('runtime/neverruntime/src/linux_policy.rs')
require(policy,['PR_SET_NO_NEW_PRIVS','PR_SET_DUMPABLE','RLIMIT_CORE','PR_SET_PDEATHSIG','SIGKILL','setpgid','neverguard/linux-runtime-process-policy/v1'],'Linux runtime policy')
ipc=read('runtime/neverruntime/src/linux_guard.rs')
require(ipc,['UnixListener','UnixStream','SO_PEERCRED','XDG_RUNTIME_DIR','0o600','client-auth','Hmac','LINUX_PACKAGE_MANIFEST.json','guard-attestation','integrity-evidence'],'Linux authenticated IPC')
integrity=read('runtime/neverruntime/src/integrity.rs')
require(integrity,['neverguard/linux-integrity-evidence/v1','/proc/{pid}/maps','/proc/{pid}/status','LinuxProcessSecurityEvidence'],'Linux integrity evidence')
att=read('runtime/neverruntime/src/attestation.rs')
require(att,['neverguard/linux-guard-attestation/v1','Guard Attestation Core Linux v1'],'Linux attestation')
desktop=read('apps/desktop/src-tauri/src/main.rs')
require(desktop,['target_os = "linux"','NEVERGUARD_LINUX_PROCESS_POLICY_VERSION','ensure_linux_production_hardening','NeverGuard Linux production hardening verification failed'],'Desktop Linux enforcement')
backend=read('services/api/internal/httpapi/guard_attestation_0134.go')
require(backend,['guardLinuxAttestationSchema0137','guardLinuxIntegritySchema0137','guardLinuxProcessPolicySchema0137','isLinuxDevicePlatform0137','NeverGuard Linux process policy verification failed'],'Backend Linux verification')
release=read('scripts/release/build-linux-desktop.sh')
require(release,['neverguard-linux-amd64','LINUX_PACKAGE_MANIFEST.json','GUARD_RELEASE_ALLOWLIST_LINUX.json','sha256sum'],'Linux release package')
ci=read('.github/workflows/ci.yml')
require(ci,['neverguard_linux','build-linux-desktop.sh','linux-production-implementation-0137.py'],'CI Linux gate')
preflight=read('scripts/release/preflight.sh')
require(preflight,['linux-production-implementation-0137.py'],'preflight Linux gate')
print('NeverLauncher 0.13.7 Linux production implementation gate: OK')
