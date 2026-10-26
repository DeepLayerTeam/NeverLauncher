# NeverLauncher 0.31.3 — Windows TPM key attestation

## Implemented path

On Windows only, `windows_tpm_certify_0313` validates the local keyring's bound `deviceId`, key algorithm, `hardware-enclave` signing provider and registered P-256 public key. It opens that key **by its original PCP key name**, uses `PCP_PLATFORMHANDLE` to retrieve the loaded TPM object handle and the TBS context, and calls `TPM2_ReadPublic`. The returned P-256 public coordinates and TPM-origin key attributes must match the registered device key; no new device key is generated. A separate **pre-enrolled AK** is opened from Microsoft Platform Crypto Provider by operator-supplied name.

The client calls the existing `POST /api/v1/auth/devices/{deviceId}/tpm-certify/begin` endpoint with the authenticated bound session. The 32-byte domain-separated `tpmExtraDataSha256` is passed as `TPM2_Certify.qualifyingData` for that object and the AK. TPM response fields (`TPM2B_PUBLIC`, `TPM2B_ATTEST`, `TPMT_SIGNATURE`) are submitted to the existing 0.31.2 `/complete`. **Only the server** grants `tpm-ak-certified` on acceptance of certificate path, key attributes, nonce, device ID, active session, binding epoch, expiry and one-time use. It rechecks root validity on subsequent status requests. Failed proof attempts do not change the device's assurance.

No `NCryptCreateClaim`-based assertion, CNG backend name, software signature or self-asserted certificate is converted to provenance. `NCryptCreateClaim` may use a different transient signing key; the server requires the AK credential actually signing the `TPM2_Certify` statement. No PCR/measured-boot or Guard integrity assurance is derived.

## Prerequisites and operational setup

1. A physical or firmware TPM 2.0 with an existing Windows device identity key stored via **Microsoft Platform Crypto Provider**. The PCP name must be the name of the key `hardware-enclave` actually generated. If the dependency stores the key under a different name or refuses to expose its loaded TPM handle, the client **fails closed**. No silent key replacement or software fallback.
2. Independently enroll a **distinct TPM-backed Attestation Key (AK)** with a trusted attestation CA that *validates actual AK TPM provenance* (e.g. issuance bound to TPM credentials), record the AK's PCP key name and obtain the issued AK leaf X.509 certificate and intermediates. Enrollment is not performed by NeverLauncher. Do not use a general-purpose software CA or manually self-signed AK certificate as a production trust root.
3. On the backend, configure `NEVERLAUNCHER_TPM_AK_ROOTS_FILE` (see `tpm-certify-verifier-0312.md`) with the true AK-issuer CA and Windows in its allowed platforms. Root status and AK revocation are server-controlled.
4. Sign in, register and verify the Windows P-256 device, check device is bound to the current session, open **Device Management → Windows TPM Key Attestation**. Supply AK PCP name and provisioned AK certificate PEM (plus intermediary certificate if applicable) and run **Подтвердить TPM-происхождение**. The local certificate is public data; never paste AK private material or any EK/AK secrets.

Raw TPM2_Certify uses **two empty password authorization sessions** for the subject key's ADMIN role and AK's USER role. A TPM object requiring nonempty authValue, PolicyAuthorize, user presence, or an authorization mode mediated exclusively by the PCP will reject this command (TPM error returned to UI). Such hardware is **not supported by this producer** until an authorized session implementation is supplied; do **not** downgrade to unverifiable hardware metadata. The backend verifier does not accept unsupported exotic key formats or untrusted issuers. In particular, existence of a TPM alone does not mean this Windows release is compatible with all Windows Hello/enterprise provisioning policies.

## Security and failure cases

- Windows host, registered key, AK and issuer certificate must all refer to the actual TPM keys. A different name, key mismatch, no physical TPM, missing TBS context, unsupported auth session, unsupported TPM public parameters, invalid X.509 chain, revoked root/AK or expired/replayed challenge all return explicit errors and **no hardware verification**.
- Device and AK keys remain OS/TPM-managed. The desktop never exports private material or writes plaintext device private keys to logs. The trust-root file lives only on the server; client-supplied PEM is not a trust anchor.
- `TPM2_ReadPublic` is cryptographically consistent with the registered key via exact SEC1 compare; verifier computes Name from `TPM2B_PUBLIC` and checks signed certified Name and SHA-256 qualifying data independently.
- The process remains user mode. The attacker's ability to alter or impersonate a user-mode process is **not** eliminated by attestation. No measured boot or runtime Guard property is claimed, and `strict` remains dependent on its separate checks.

## Validation

Run on a Windows host with Rust/MSVC build tools:

```powershell
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml tpm_wire_0313
cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Re-run against at least two TPM 2.0 vendors, one supported user-provisioned AK/PCP pair and a CA-provisioned revoked AK, and collect evidence of a successfully accepted `/complete`. Platform-specific testing is a release prerequisite; tests on Linux cannot prove Win32/TBS behavior. Workstation with a hardware key that uses nonempty authorization will reject until native authorization is supported. CI compilation/tests are necessary but do not replace device verification.

Windows AK enrollment may place the identity key in the **machine** namespace. The producer opens the AK in the user namespace first and then with `NCRYPT_MACHINE_KEY_FLAG` if necessary; the subject identity is always opened in the user's namespace. A machine AK must be accessible to the invoking account under applicable ACLs. The server trusts neither namespace by itself—only the valid AK-issued certification signature and pinned issuer.
