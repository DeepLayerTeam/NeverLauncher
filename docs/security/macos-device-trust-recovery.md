# 0.31.6 macOS Device Trust and Device Recovery

## Implemented behavior

- On macOS the native Desktop process checks the existing Keychain record and, when present, validates the actual P-256 hardware signer and public-key fingerprint. Software Ed25519 devices are permitted under the **standard** profile. A local Secure Enclave key is **not** equivalent to remotely attested hardware identity.
- `DCAppAttestService.sharedService.isSupported` is invoked through Apple's DeviceCheck/Objective-C runtime, not inferred from an OS version string. Apple added App Attest to **macOS 27** for supported main applications. Earlier macOS releases and unsupported app types can return false. `api-supported-not-attested` does **not** mean an attestation has been generated or verified.
- The Launcher device key is created independently of Apple's App Attest key. **No server-side proof links those two keys.** Therefore even with `isSupported == true`, `remoteDeviceKeyProvenance` remains `not-verified` and the strict profile must deny. Do not advertise Secure Enclave remote provenance on arbitrary macOS setups.
- Device recovery requires a *fresh phishing-resistant passkey step-up* and proof of possession of a **new** device key. The previous fingerprint may not be reused. The old device record and its related sessions/challenges are revoked as part of existing replacement handling. A replacement has `proof-of-possession` assurance, not inherited TPM/Guard/PCR attestation.
- The staged key must remain recoverable after a lost HTTP response. `stage_device_key_replacement` reuses an existing staged identity, and the frontend attempts to reconcile it against an active server device before sending another request. Automatic destructive key reset after an HTTP 409 is disabled. Deletion of a staged identity must be an explicit action.

## Operator / support runbook

1. Sign in with a still-valid account credential and complete fresh passkey verification; having the lost local key is **not** required to perform recovery. A passkey may be on another trusted device. If no phishing-resistant account credential remains, an alternative verified account recovery procedure is required; the API will not bypass the step-up gate.
2. Choose **Восстановить ключ**. Launcher creates or reuses a staged key in OS Keychain and submits its public key. If the HTTP response is lost, do **not** delete application Keychain items or reset keys. Re-authenticate, then repeat recovery so the client can reconcile the server-bound staged identity.
3. The server revokes the old fingerprint; any old key or stale challenge cannot be reused. Re-verify the session and obtain fresh device attestation for the new key if supported. The strict profile remains unavailable without separately verified Guard evidence.
4. On macOS, inspect **macOS Device Trust** in the authentication screen for `localSecureEnclave` and `appAttest` values. `api-unavailable` is not a general launcher failure; standard device proof can still work. `keychain-unavailable-or-key-invalid` indicates a device-side Keychain/Enclave problem.

## Verification and limitations

- Backend tests enforce fresh passkey, reject identical old/new fingerprints, prove the new key, revoke the old record and refuse replay. Trust tests reject fake `remoteHardwareProvenance=verified` on macOS, including Apple silicon labels.
- CI compiles/runs on GitHub-hosted macOS. Hardware/OS testing must additionally cover Intel Macs, Apple silicon, macOS 27 App Attest `isSupported` true and false, lost-key recovery, offline/network timeout during replacement, Keychain locked, reinstallation, and Secure Enclave reset.
- This release **does not implement** Apple's App Attest certificate and assertion verifier or Managed Device Attestation. These are distinct protocols and cannot be substituted for TPM2 Certify. It cannot claim remotely verified macOS key provenance, full strict trust, or independent user-process integrity.
