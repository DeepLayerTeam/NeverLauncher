# NeverLauncher 0.31.1 — executable Trust & Isolation baseline

## Implemented and enforced in 0.31.1

`TrustAssessment` is computed by the API from authenticated session binding and the stored device record. API paths `GET /api/v1/auth/device-trust` and `/api/v1/auth/devices` return per-profile decisions with stable machine-readable reasons. `GET /api/v1/auth/device-trust?requireProfile=standard|strict` returns HTTP 403 and the denial details when a requested profile is not satisfied (and 400 for an unknown profile). The ordinary status endpoint remains backwards compatible.

**Standard** permits an active, verified device with an accepted key algorithm/fingerprint only when a currently active session is bound to that device. It does not require TPM; losing a TPM is not a generic launcher failure. Existing dual-proof key rotation and passkey-step-up key recovery remain the supported repair flows. A client-reported provider name is labelled `client-reported`, not remotely verified. An expired challenge-response does not grant a higher assurance; it is **not** the basis of the standard profile in 0.31.1.

**Strict** is fail-closed: no remotely verifiable hardware provenance verifier and no complete Guard runtime evidence evaluator are implemented in this release. Therefore strict always denies, including legacy DB records claiming `remoteHardwareProvenance=verified`. A future implementation must verify actual hardware evidence against the *registered exact key*, nonces, session, epoch and trusted roots before changing this result. Merely changing a DB field cannot enable strict. Repository device writes downgrade such legacy claims; API serialization and attestation responses do likewise.

Backend extension runtime reports `legacy-unisolated` and `isolationStatus=unsupported` with `osSandbox=none`, `networkSandbox=none` and `filesystemSandbox=none`; no auto-upgrade to trusted or isolated is possible. Linux PGID/RSS limits, sanitized environment and broker RPC checks are **not** an OS sandbox. Existing unsigned/untrusted package admission policies are separate from the runtime isolation claim. Existing extensions remain backwards compatible, but 0.31.1 must not be described as making them safe to execute against untrusted local users.

## Executable diagnosis

From an installed backend binary, without a database connection:

```shell
neverlauncher-api diagnose device-trust
neverlauncher-api diagnose extension-sandbox
neverlauncher-api diagnose device-trust --require-strict       # exit 2 until verifier is implemented
neverlauncher-api diagnose extension-sandbox --require-isolation # exit 2 until isolation is enforced
```

Diagnostics write machine-readable JSON to stdout, including reasons, platform/architecture and **observed capabilities**. They do not request elevation, read key material, or modify system resources. Read-only kernel interface detection is not an assertion that creating the corresponding namespace, resource boundary or network broker will succeed. This describes the **backend host**, not the remote game device. Neither the local TPM character device nor a provider label proves remote key provenance.

## Platform capability / release constraints

| Platform | Hardware provenance baseline | Extension isolation baseline | Known refusal / next implementation |
| --- | --- | --- | --- |
| Windows 10/11 / Windows Server | Device's claimed TPM provider is not remotely verified, regardless of hardware KSP. Presence unverified on the backend host. | No AppContainer restricted token, ACL confinement, Job Objects or IPC/network broker enforced yet. | `remote-hardware-verifier-unavailable`, `extension-os-sandbox-not-enforced`. Native Windows TPM evidence producer/verifier 0.31.3; AppContainer/Job confinement 0.31.11. |
| Linux x64/arm64 (incl. containers) | `/dev/tpmrm0` / `/dev/tpm0` probed without reading contents. TPM absence, vTPM and `swtpm` are not hardware certification. | Probes `/proc/self/ns/user`, kernel userns knobs, seccomp actions and cgroups-v2 hierarchy; *none* is currently applied to extensions. No dedicated UID, mount/network namespaces or writable delegated cgroup enforced. | `cgroups-v2-delegation-not-writable`, `user-namespace-limit-zero`, `extension-os-sandbox-not-enforced`. Real isolation 0.31.9. |
| macOS Intel / Apple Silicon | Secure Enclave local key availability does not prove provenance of the registered key; App Attest may be available only to supported app/device configurations with a cryptographically linked attestation flow. No verification here. | No verified signed/entitled App Sandbox helper in this release. | `macos-device-key-provenance-unsupported` (when evaluated on macOS host), `signed-sandbox-helper-not-provisioned`. Feasibility and signed helper 0.31.6/0.31.12. |

WSL, virtual machines, disabled user namespaces, containerized services, restricted TPM permissions, firmware reset, revoked or missing manufacturer roots, missing entitlements and legacy manifests may alter support. A supported claim requires an actual corresponding verifier/enforcement result, not just a platform version or CPU architecture.

## Reason codes, UX and recovery

- `device-not-verified`: log in and prove possession again, or use supported passkey-step-up recovery; revoked keys may not be resurrected.
- `session-device-binding-missing`: verify the actual session's device binding; cross-device sessions cannot borrow a positive assessment.
- `challenge-response-expired-or-invalid`: refresh challenge-response if needed for an existing feature; this is distinct from hardware provenance.
- `remote-hardware-verifier-unavailable`, `guard-runtime-evidence-unavailable`: strict profile explicitly unsupported. User may select the standard profile if the protected operation allows it; do not silently relax a strict server policy.
- `extension-os-sandbox-not-enforced`: no isolated status may be displayed. A future isolation-required package must fail closed, not silently execute with trusted privileges.

Firmware/TPM reset, motherboard replacement or key loss: ordinary authentication remains available. Use the existing key recovery with fresh phishing-resistant step-up, which creates a new key/binding epoch and revokes the previous identity according to server policy. Do **not** rewrite local metadata to assert new hardware provenance. Admins should not authorize strict-only operations while verification is unavailable.

## Threat model / non-guarantees

Threats: malicious extension or child process; forged client-supplied hardware strings; stale/proxy/cross-session or replayed device evidence; user-mode attach/injection; compromised local OS; inaccessible TPM; accessibility software, screen overlays and AV causing false positives. Boundaries: protocol/RPC and signing checks alone cannot prevent a same-user extension from reading arbitrary local files, making direct outbound requests or escaping a process group. Local hardware key storage cannot attest to the integrity of the JVM or Guard process, and PCR/Measured Boot measurements (once implemented) are a **separate** claim from key provenance.

No absolute anti-cheat or defense against a compromised kernel is claimed. Overlay, accessibility and AV compatibility cannot be certified without repeatable platform-native adversarial testing on real hardware; these tests are exit gates for 0.31.14, not fictitious passed results for 0.31.1.

## Reproducible tests and constraints

`go test ./internal/model ./internal/trustbaseline ./internal/repository ./internal/extensionhost ./internal/httpapi` from `services/api`. Tests cover no-TPM standard access, revoked/foreign session denial, forged legacy provenance downgrade, strict fail-closed, expired evidence and kernel probe honesty. `go build ./cmd/neverlauncher-api` then run diagnostics above. CI runs platform builds/tests against exact commits. Hardware-attestation and actual sandbox adversarial certification are **not** included in 0.31.1 and must not be inferred from green tests.
