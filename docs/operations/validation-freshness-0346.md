# 0.34.6 — live V05 evidence applicability, expiry and emergency key revocation

This upgrade **does not** open stable: the 0.34.1 database/Backend stable gate
remains in effect. It implements actual verification, rejection and revocation
of attestation evidence for staged releases, and reports required-target coverage.

## Before starting an attestor

1. Apply PostgreSQL migration `0104_validation_freshness_0346.sql` (also mirrored
   to the CLI migration bundle). Ensure all API instances use the same DB.
2. Keep `NEVERLAUNCHER_VALIDATION_ATTESTATION_PUBLIC_KEY` and
   `NEVERLAUNCHER_VALIDATION_RUNNER_IMAGE_SHA256` from 0.34.5, in the Backend
   process; the private attestation key stays on the isolated host.
3. Set `NEVERLAUNCHER_VALIDATION_REQUIRED_TARGETS_JSON` to an operator-controlled
   JSON array. For every required test target provide exactly these properties:

```
id, projectId, profileId, channel, version, manifestSha256,
artifactSha256, resolvedPlanSha256, sourceSha, buildSha, javaSha256,
javaVersion, os, arch, loader, installAdapterSha256, guardMode,
guardPolicySha256, serverBridgeSha256, serverPluginVersion, preset
```

All digests are **actual lower-case** SHA-256, except sourceSha which may be a
40-character Git commit SHA. There are no wildcards. Each target is bound to
an exact version and staged snapshot. Multiple presets/Java/OS combinations
must be listed as separate required targets; do not list hypothetical targets
that the provisioned attestor cannot execute. A changed snapshot or target
configuration invalidates previous attestations. An empty config cannot
confer an all-passed verdict.

4. Run the separate attestor with its pinned image; it obtains a Backend-issued
   run ID and **independent 256-bit nonce**. Backend stores the challenge before
   delivering a temporary download grant. The host verifies the installed
   bytes, stage artifacts, actual Java and ServerBridge, identifies the unique
   matching configured target and signs v3 evidence with domain separation.
5. Backend accepts signed evidence only while the challenge is active and
   before the evidence expires; it checks trust anchor, key fingerprint,
   purpose/audience, nonce, snapshot, target matrix and all seven recorded
   stages. One run ID may be recorded once. Signed evidence is valid at most
   24 hours and its applicability is re-evaluated on every query.

`GET /api/v1/packages/{packageId}/validation-attestations` returns:
`targetCoverage`, `targetBlockers`, `allRequiredTargetsVerified`, plus the
stored attestations. `allRequiredTargetsVerified` is deliberately separate from
`stablePublishEligible` (still `false`).

## Emergency signing-key revocation

Authenticate with `settings:manage` and fresh MFA, then POST:

```
POST /api/v1/admin/validation-attestation/keys/revoke
Content-Type: application/json

{"fingerprint":"<64 lowercase hex chars>","reason":"operator confirmed key compromise"}
```

Fingerprint is SHA-256 of the **raw Ed25519 public key**. The revocation is
stored permanently in PostgreSQL; every evidence acceptance and applicability
read consults that store and fails closed if unavailable. A key cannot be
unrevoked by the API. Rotating the configured trusted public key immediately
invalidates previous evidence even without explicit revocation.

## Invalidation and concurrency

- Changing manifest/files means a different staged snapshot: no reuse.
- Changing Java binary/version, preset, install adapter, source/build, loader,
  Guard mode/policy or server/plugin identity invalidates the exact target.
- Adding/removing/changing any required target changes the signed matrix hash.
- A run from a different package/version, with a replaced nonce, wrong scope,
  expired proof or revoked signer cannot be accepted as passing.
- The API rechecks freshness and policy immediately before immutable insertion,
  and reports always re-evaluate live revocation/applicability. Concurrent
  signer revocation can leave a stored row but can never make it *applicable*.
- The hard stable release and channel-head write guards stay in place until
  the separate V11 implementation replaces them atomically. No currently
  allowed stable publication race exists.

## Compatibility and rollout

ValidationEvidence v2 is **not** accepted as v3 and does not satisfy V05 target
coverage. The attestation host and Backend must be upgraded together. V01/V02
observational reports do not turn into trusted evidence retroactively.

Do not put private attestation keys or production auth credentials in the worker
container or build logs. Retain separate run logs and audit entries.
