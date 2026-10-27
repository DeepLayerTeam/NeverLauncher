# Migration Center — 0.33.6 Security & Trust Migration (MIG06)

## Supported scope

`0.33.6` provides an **executable PostgreSQL security reset** for accounts newly created by the completed MIG05 import. It does not import any old Gravit session tokens, device private keys, Guard attestations, publisher roots or trust anchors, and does not grant a cutover approval.

Existing Never users with matched UUIDs are **not touched**. Those users' Never-issued authentication and device credentials are unrelated to the source project; do not forcibly rotate them as a side effect of Gravit migration.

## Preconditions

1. Apply DB migrations through `0094_gravit_security_0336.sql`. Migrations 0.29.7 session cascade and 0.31.x device evidence are required.
2. Complete the MIG01 baseline, MIG03 inventory, MIG04 immutable UUID mapping and MIG05 **committed** credential import. At least one new account must be imported; no blocked identities.
3. Independently provision a **new** `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` and select `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID`. The active secret must have 32+ bytes. Remove any Gravit-derived key from configuration. Never reuse Gravit HMAC secrets, device keys, installer signing material, or trust roots.
4. Provision independent 32-byte Ed25519 seed in `NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY` (64 hex characters). Configure the existing game-trust publisher policy separately. All API replicas must run identical *new Never* active key configuration. Never transfer private keys via API, reports or archives.
5. Key independence cannot be established cryptographically without reliable metadata for the old secret; server verifies correct configured formats, not their provenance. An authorized operator must verify provenance out of band and acknowledge it before activation.

## Independent Never key generation

CLI can create new independent signing secrets locally without API access:

```bash
mkdir -m 700 -p /secure/never-secrets
nl migrate gravit generate-never-keys --output /secure/never-secrets/never-migration-keys.json
```

It creates the new JSON with exclusive creation (`O_EXCL`) and `0600` permissions in a private directory. Only an authorized operator can read it. Provision its `jwtKeys` as `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON`, its `jwtActiveKid` as `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID`, and its `manifestEd25519Seed` as `NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY` through your secret manager. **Never commit or upload the generated file**. Propagate the fresh signing configuration to all API replicas prior to activating reset. Do not discard other production token signers without a separate global rotation plan: this key-generation command does not rotate existing deployments.

## CLI

```bash
nl migrate gravit preview-security --backend https://api.example --token "$ADMIN_TOKEN" --run "$RUN_ID" --output security-preview.json
nl migrate gravit activate-security --backend https://api.example --token "$ADMIN_TOKEN" --run "$RUN_ID" --confirm "$RUN_ID" --output security-applied.json
nl migrate gravit security --backend https://api.example --token "$ADMIN_TOKEN" --run "$RUN_ID" --output security-verified.json
```

All mutating calls require `settings:manage`. `activate-security` explicitly confirms the run and newly provisioned keys. The API never accepts user IDs or key material in the request. Send via HTTPS (local IP loopback is allowed for isolated testing).

## Atomic effects

The server reads the committed `migration_auth_imports_0335` receipt and computes deterministic Never user IDs. Only `imported` identities qualify. Under a PostgreSQL SERIALIZABLE transaction with row locks:

- verifies the user and exact Minecraft UUID/name, player role, `gravit-import-v1` identity version and current workflow state;
- revokes active `auth_sessions`, invoking the existing database cascade across refresh families/tokens, Minecraft tokens/joins and ServerBridge admission/handoff state;
- consumes old `device_challenges` and revokes active `trusted_devices` with attestation reset;
- deletes old TPM and measured-boot evidence (only for affected imported users);
- commits an immutable report and workflow event **in the same transaction**.

A failed statement rolls back the entire reset. An exact replay returns the original receipt and verifies that pre-reset sessions, devices, challenges and evidence remain invalid. It **never revokes newly enrolled devices** or newly issued sessions. An attempt with different signing configuration fails rather than repeating side effects.

After applying, migrated players must perform a new Never login, enroll a new trusted device with a fresh keypair and pass the required Guard attestation for protected actions. Using the same Gravit private key is prohibited. The report always returns `readyForCutover:false`; MIG07–MIG13 remain prerequisites for a production cutover. Rollback cannot restore revoked authentication credentials.

## Validation

CI workflow `.github/workflows/gravit-security-migration-0336.yml` runs unit and PostgreSQL tests, API compatibility validation, CLI checks and Admin build. The PostgreSQL test asserts preview non-mutation, session and refresh revocation, signer mismatch rejection, safe replay and continued validity of post-reset device enrollment.
