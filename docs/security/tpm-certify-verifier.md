# Launcher 0.31.2 — TPM Certify verifier and AK trust roots

## Enforced behavior

The API accepts **real TPM2 `Certify`** evidence via `POST /api/v1/auth/devices/{deviceId}/tpm-certify/begin` and `/complete` for authenticated, currently bound and verified **P-256/hardware** devices registered on Windows or Linux. On begin, it issues a CSPRNG challenge, saves only a SHA-256 digest in the existing one-shot challenge repository, and returns the domain-separated SHA-256 hash for TPM's `extraData`. The response includes `issuedAt`, `expiresAt`, the session ID and `bindingEpoch`. The client signs nothing using a server private key; the TPM's attestation key (AK) signs the TPMS_ATTEST produced by `TPM2_Certify` of the already registered device identity key.

On complete, the backend consumes the challenge **atomically** (including unsuccessful verification attempts), rechecks the current bound session, challenge metadata and device fingerprint, and parses binary TPM2B_PUBLIC, TPM2B_ATTEST and TPMT_SIGNATURE. It verifies TPM `magic`, `TPM_ST_ATTEST_CERTIFY`, the exact SHA-256 `extraData`, the certified object's TPM Name, a real fixedTPM/fixedParent/sensitiveDataOrigin P-256 signing key, the registered SEC1 public key, and the AK's ECDSA-P256, RSA PKCS#1 v1.5 or RSA-PSS SHA-256 signature. The AK leaf certificate must be a non-CA signing certificate with a valid X.509 chain to an **operator-configured AK certification CA**. Certificate limits, expiry, root status and revocation deny by default.

A verified result is written to `device_hardware_evidence_0312` (PostgreSQL) or memory repository, separately from the legacy `trusted_devices.remote_hardware_provenance` claim. It contains the exact root certificate SHA-256 fingerprint (preventing root-ID reuse from reviving older evidence), AK fingerprint, session, epoch, key fingerprint and <= 1 hour expiry. `GET /api/v1/auth/device-trust` rechecks the record, epoch, session and freshly loaded trust-root policy every time. A revoked root, revoked AK, key replacement, expired evidence or changed session epoch **immediately downgrades** effective hardware provenance. The `strict` trust profile still **denies**: verifying a key's TPM provenance is not proof of measured boot, process integrity or Guard evidence.

## Operator root provisioning and revocation

Set `LAUNCHER_TPM_AK_ROOTS_FILE` to an absolute path to a **regular file** owned and provisioned by the backend administrator. The server does not auto-download or trust arbitrary device-supplied issuer chains, EK roots or certificates. Invalid/missing file = fail closed; never trust a claimed provider name. Restrict the file to administrative writers. Example (use a real provisioned AK CA PEM, not a generic public/WebPKI root):

```json
{
  "schema": "launcher/tpm-ak-trust-roots/v1",
  "roots": [{
    "id": "ak-issuer-prod-2026",
    "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "status": "active",
    "notBefore": "2026-10-01T00:00:00Z",
    "notAfter": "2027-10-01T00:00:00Z",
    "platforms": ["windows", "linux"]
  }],
  "revokedAkFingerprints": []
}
```

Roll forward by adding a second active root, verifying client cert transitions, then setting the old root to `revoked` or removing it. Update `revokedAkFingerprints` with lowercase SHA-256 hashes of DER AK leaf certificates for immediate AK revocation. Replace the JSON file **atomically** (write temp file, fsync, rename). The server reloads roots for every verification/status check; restart is unnecessary. Never issue AK certificates from a CA that does not independently validate hardware-bound AK provenance: a software-generated AK with an arbitrary X.509 certificate does **not** constitute trustworthy TPM attestation. The configured issuer and its enrolment policy form a security-critical trust boundary.

## Wire format

Send the fields returned by `begin` in the `complete` request:

```json
{
  "challengeId": "htc_...",
  "challenge": "htn_...",
  "evidence": {
    "tpm2bPublic": "<base64url unpadded bytes including outer size>",
    "tpm2bAttest": "<base64url unpadded bytes including outer size>",
    "tpmtSignature": "<base64url unpadded TPMT_SIGNATURE bytes>",
    "akCertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "intermediatesPem": []
  }
}
```

The TPM2_Certify `qualifyingData` must equal `tpmExtraDataSha256` returned by the begin call (decode URL-safe base64 without padding to a 32-byte digest). This digest covers user, device, session, binding epoch, challenge ID, challenge nonce, issued timestamp and expiry. Certify the TPM object whose public portion matches the **already registered** device public key. The client must not post a new public key to replace the registered one. The verifier accepts exactly SHA-256 and TPM ECC NIST-P256 signing object keys with null symmetric, signing scheme and KDF parameters; unsupported legitimate TPM configurations fail explicitly and do not receive verified status.

## Security boundaries

- TPM2_Certify proves that a TPM AK vouches for the name/properties of a TPM object, provided the AK issuer genuinely validated the AK's TPM provenance. **It does not prove PCR values, measured boot or user-process integrity**. TPM Quote/PCR policy and Guard runtime enforcement are distinct later milestones.
- Windows and Linux TPM evidence **producers** are still separate 0.31.3 and 0.31.4 platform tasks; this release provides an executable common backend verifier and protocol. No Secure Enclave generic public-key provenance claim is supported on macOS.
- A test CA used in unit tests is not a trusted production issuer. Do not configure test/dev roots in production or assume an AK certificate from an EK-rooted chain is valid without the required TPM provisioning/credential-activation checks.
- Legacy `challenge-response-v1` remains proof of possession and does not upgrade hardware assurance. The backend does not silently elevate `strict`, and no update to a legacy device DB field alone can grant a higher trust level.

## Verification

Run from `services/api`:

```sh
go test -race -count=1 ./internal/attestverify ./internal/trustbaseline ./internal/repository ./internal/httpapi
go build ./cmd/launcher-api
```

`internal/attestverify` uses only the Go standard library, so it can be run offline. Fixture tests create real X.509 CA/AK keys and cryptographically sign a TPM2 Certify-shaped statement, then test invalid key/name/nonce/session/user/device/epoch/expiry/signatures and root/AK revocation. These tests establish verifier behavior, not certification against physical TPM firmware or production AK issuers.
