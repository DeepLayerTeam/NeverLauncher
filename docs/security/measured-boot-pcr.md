# Launcher 0.31.5 — TPM2 Quote, Measured Boot & PCR Verification

## Guarantees and limits

This version **cryptographically verifies TPM2 Quote**, compares a single
SHA-256 PCR bank with an **operator-approved** exact PCR-value allowlist, pins
the Quote's AK certificate to the AK already verified via TPM2 Certify for the
**same user/device/session/binding epoch**, and consumes one-time challenges.

A verified Quote establishes only that the enrolled TPM AK signed the reported
PCR digest and that these PCR values match an active operator policy.
**It does not attest the active Guard process, JVM bytecode or user-mode memory.**
The Guard/strict-device profile remains independently governed by Guard checks.
There is no silent fallback to software evidence, generic TPM provider claims,
missing PCR measurements or an unsigned policy.

## Deployment

Provision a trusted AK issuer and root store as for 0.31.2–0.31.4. Set
`LAUNCHER_TPM_AK_ROOTS_FILE` to the operator-controlled absolute path.
Separately set `LAUNCHER_TPM_PCR_POLICY_FILE` to an absolute JSON policy
file, writable by the backend operator only (never writable by the launcher
user, an extension or the untrusted service worker).

Example policy (replace values with **independently measured, approved**
SHA-256 PCR digests from supported boot configurations; example values do not
represent an approved real system):

```json
{
  "schema": "launcher/tpm-pcr-policy/v1",
  "policies": [
    {
      "id": "linux-approved-boot-v1",
      "platform": "linux",
      "pcrs": {
        "0": "1111111111111111111111111111111111111111111111111111111111111111",
        "2": "2222222222222222222222222222222222222222222222222222222222222222",
        "7": "7777777777777777777777777777777777777777777777777777777777777777"
      },
      "notBefore": "2026-10-01T00:00:00Z",
      "notAfter": "2027-01-01T00:00:00Z"
    }
  ]
}
```

Choose the PCR set based on the platform's measured-boot design and threat
model. For Windows/UEFI policies, pin approved Secure Boot and boot-path
measurements. For Linux, policy must match the actual firmware/bootloader and
chosen boot path; PCR 7 alone is not a complete measured-boot policy. Maintain
separate IDs for different approved images and configurations. Independently
validate expected PCRs (including boot event log and image verification) before
allowlisting. **Never enroll the first PCR values submitted by a client.**

## Protocol

1. Register a hardware P-256 identity, bind the current device session, and
   complete the existing TPM2 Certify challenge successfully.
2. `POST /api/v1/auth/devices/{deviceId}/measured-boot/begin?policyId=<id>`
   with bearer token. Requires active pinned TPM Certify, a known active policy
   and current session epoch. Returns an unpredictable challenge, expiration,
   `sha256:` PCR selection, policy hash and domain-separated TPM extraData.
3. Desktop (Windows PCP/TBS or Linux `tpm2-tools`) asks the same TPM AK to
   sign TPM2_Quote with the 32-byte server qualifier. It reads selected PCR
   values; they are *untrusted until validated against the signed quote*.
4. `POST .../measured-boot/complete` sends `challengeId`, `challenge` and
   `evidence` containing `tpm2bAttest`, `tpmtSignature`, `pcrValues`,
   `akCertificatePem`, optional `intermediatesPem`.
5. Backend **atomically consumes** the challenge, re-checks session/epoch and
   root+AK pin, validates TPM magic/TPM_ST_ATTEST_QUOTE, full extraData,
   exact SHA-256 PCR bitmap, digest SHA256(concat(selected PCR values in index
   order)), operator-approved values, AK signature and X.509 chain. Successful
   results are stored separately from device-key and Guard attestations.
6. `GET /api/v1/auth/devices/{deviceId}/measured-boot` returns only an active
   status. Root revocation, expired evidence, policy file changes, changed
   device binding and session epoch invalidate the status. Evidence lifetime
   is capped at 5 minutes and by the AK+policy expiration.

**Failure modes:** missing TPM 2.0, missing trusted AK, unsupported PCR bank,
unknown PCR policy, malformed or replayed challenge, quote digest mismatch,
revoked AK/root, policy rotation, old session epoch → fail closed.

## Linux requirements

Access to `/dev/tpmrm0`, `tpm2-tools` 5.x (at fixed `/usr/bin` paths), a
pre-provisioned persistent AK (`0x81xxxxxx`) with a trusted issuer certificate,
and permission to use the TPM. Commands are invoked without a shell, with
bounded timeouts, and the fixed TPM Resource Manager TCTI.
`TPM2_Quote` and `PCR_Read` are separate operations. PCR values changing between
the operations cause a signed digest mismatch and rejection, not downgrade.

## Windows requirements

Windows Platform Crypto Provider and TPM Base Services (TBS), an enrolled AK
accessible as a PCP key, an AK certificate issued by the trusted CA and TPM
authorization compatible with empty-password AK sessions. Machines requiring
other authorization sessions fail closed. No software quote is synthesized.

## Verification and production signoff

`go test -race -count=1 ./internal/attestverify ./internal/trustbaseline`
from `services/api`. Windows/Linux compile/test in
`.github/workflows/measured-boot-pcr-0315.yml`. A real production signoff
requires fresh TPM 2.0 evidence on Windows and Linux with trusted EK/AK
provisioning, cold-boot baseline validation and negative hardware experiments
(replay, PCR mutation, wrong AK/chain/root, session/key rotation, AK revoke,
expired cert, policy update), plus PostgreSQL migration/application tests.
CI builds on hosted virtual machines do not substitute for physical TPM tests.
