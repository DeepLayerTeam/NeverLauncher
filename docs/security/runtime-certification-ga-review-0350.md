# NeverLauncher 0.35.0 — Runtime GA security review

## Protected assets and trust roots

The release signing key and the validation attestation key must never be shared. A normal CI runner may fetch staged bytes with a temporary limited token but must not possess a valid attestation signer. Independent attestation runs in an isolated, pinned OCI image; sensitive provider tokens are provisioned by the trusted host and removed after the run. Backend pins the verifier key, OCI digest, challenge nonce, purpose/audience, source/build SHA, exact Java/loader/Guard/ServerBridge, artifact and target matrix digest.

## Attacks addressed in GA changes

1. **Integrity-positive tampered bytes after verification:** SQL `0107` freezes file metadata and manifest after stable integrity PASS. Runtime startup/gameplay still rejects correctly owner-rehashed but broken artifacts. Direct DB writes to verified stable metadata are rejected even if an attacker does not use the HTTP API.
2. **Published stable record mutation:** the stable release trigger rejects changing manifest, status or published timestamp after publication, even if an attacker keeps `status=published`. Verified stable release deletion is blocked. Original channel-head V11 trigger remains authoritative.
3. **Integrity history rewrite:** stable integrity results cannot be updated/deleted after PASS. Insert-only history and latest-result checks remain in place.
4. **Mismatched source across targets:** Backend refuses a supposed stable certification whose mandatory targets derive from different source commits; read-only GA preflight requires the release workflow commit to match the source claim.
5. **Forged CI preflight or replay:** the preflight is not a certification and has no permission to grant a stable head; release signing calls the real Backend again; Backend/SQL re-evaluate at commit. The read-only API call disallows redirects to prevent token forwarding to another host.
6. **Expired, revoked or substituted evidence:** the v4 attestation verifier enforces Ed25519, audience/purpose, nonce, source/Java/preset/adapter and stage outcomes. The transaction rechecks stored evidence and revocations under locks; distinct targets require their own runs.
7. **Manual certification and alternate routes:** runtime coverage derives from trusted signed evidence, not `certified=true`. The V11 SQL trigger applies to durable publish, promotion, rollback and Migration Center changes to `channel_heads`.

## Residual risks and deliberate limits

- The PostgreSQL **owner/superuser** can disable triggers or forge database contents; provision separate least-privilege DB roles, audited migrations, backups and restricted DBA access. App role with arbitrary SQL write privileges to attestation/permit tables is outside the application API trust model; privilege separation must be reviewed in deployment.
- V12 audit records are immutable against normal writes but do not constitute an independent transparency log. Store externally signed backups for stronger non-repudiation.
- GUI recognition based on OCR and frames can false-negative on localized or custom menus. Treat uninstrumented environments as `blocked`, not passing or Minecraft incompatibility.
- CI GitHub actions are a software-supply-chain dependency. Pin actions and runners under the organization's supply-chain policy; the attestor must independently verify binary identity.
- Snapshot preflight can become stale between read and publication. It is deliberately advisory. Only the protected PostgreSQL channel-head transaction authorizes stable; its versioned permit has single-use semantics.
- The local development environment did **not** execute live Minecraft/server, official provider, PostgreSQL or all-platform runs. No verified GA certificate is asserted by this repository patch.

## Required security tests

Run `TestGAStableSnapshotImmutablePostgres0350` on PostgreSQL 17 and V11/V12 suites, plus the 18 deterministic Python acceptance negatives. On staging, demonstrate rollback/promotion/cutover bypass attempts, concurrent publish and revocation, forged and stale signed evidence, changed source/preset/Java, corrupted correctly rehashed release and provider outage. Record the actual results and logs in the readiness report; do not mark unexecuted checks as passed.
