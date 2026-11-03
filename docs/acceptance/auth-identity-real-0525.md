# NeverLauncher 0.52.5 — Authentication & Identity Acceptance

## Production changes

- OIDC login and both Microsoft/generic browser-link completion paths now **atomically consume** their encrypted transaction's state through the existing durable `used_nonces` PostgreSQL store or SQLite coordinator, prior to exchanging the issuer code. Single-use is enforced across API replicas. Concurrent reuse, re-sealing the same state, a stolen link-state presented to the login endpoint, and unavailable durability are rejected.
- OIDC completion cannot change the device identity sealed at begin. Re-authentication in the last 15 minutes is required for browser identity linking. Link endpoints parse strictly bounded JSON with duplicate/unknown keys rejected.
- No provider secret or authorization code is stored in the nonce record; metadata is limited to provider and operation kind. A consumed state cannot be retried after upstream service failure: start a fresh browser authorization.

## Operator live run (dedicated staging only)

The test **mutates** identity links and **revokes** sessions. It MUST NOT run on personal Microsoft accounts, production customers, shared identities or ordinary deployments. Use a dedicated HTTPS production-like Backend with PostgreSQL, a working genuine SQL auth connector, a local provider, a real OIDC or Microsoft issuer and two independent disposable Never accounts. Use a licensed, operator-owned Minecraft Java entitlement. The native desktop obtains the valid Minecraft access token via the real Microsoft → Xbox → XSTS → Minecraft chain. No secrets should go to CI variables, CLI flags or logs.

Prepare an owner-only (mode `0600`) absolute JSON file containing:

```json
{
  "scope": "dedicated-disposable-accounts",
  "allowIdentityMutation": true,
  "origin": "https://staging.example.org",
  "local": {"providerId":"local", "identifier":"owner@example.org", "password":"<PRIVATE_PASSWORD>"},
  "secondary": {"providerId":"local", "identifier":"second@example.org", "password":"<PRIVATE_PASSWORD>"},
  "sql": {"providerId":"sql", "identifier":"sql-account@example.org", "password":"<PRIVATE_PASSWORD>"},
  "oidc": {"providerId":"oidc", "kind":"generic"},
  "official": {"userType":"msa", "authServerBaseUrl":"", "username":"LicensedTestPlayer", "uuid":"0123456789abcdef0123456789abcdef", "accessToken":"<PRIVATE_MINECRAFT_BEARER>"}
}
```

For a Microsoft OIDC connector, use `"kind":"microsoft"`. For users enforcing TOTP, add a `"totpSecret"` for each test login that requires it. The owner must already have sufficient rights to link external providers; a real SQL account must be configured so its explicit link maps back to this same canonical user, not an independently auto-provisioned one. The second Never account must own a distinct canonical user ID. The test role permissions must be configured so a player cannot read administrative roles.

1. Provision the accounts, real external issuer, and required credentials through an operator's secure secret channel. Apply database migrations, enable HTTPS, and restrict test identities to the isolated project.
2. On the isolated operator machine, run:

   ```sh
   umask 077
   python3 scripts/acceptance/auth_identity_real_0525.py prepare-oidc \
     --secrets /secure/auth-0525-secrets.json \
     --output /secure/auth-0525-oidc-proof.json
   ```
3. Open **both** HTTPS authorization URLs found in the private proof file in real browsers. Authorize with the same controlled external account, and copy each returned provider `code` into its `link.code` and `login.code` fields, respectively. Keep `state`, `transaction`, `generatedAt`, `ownerSha256` unchanged. They expire in 10 minutes. Never send this file to GitHub or to reports.
4. Run immediately:

   ```sh
   python3 scripts/acceptance/auth_identity_real_0525.py run \
     --secrets /secure/auth-0525-secrets.json \
     --oidc-proof /secure/auth-0525-oidc-proof.json \
     --source-commit "<exact_40_hex_commit>" \
     --api-package-sha256 "<independently_pinned_64_hex_backend_package_sha256>" \
     --output /secure/auth-0525-report.json
   ```
5. Capture the **redacted** report with native platform, commit, release-artifact hashes, logs and independent operator signature in the separately controlled 0.52.1 evidence workflow. This script's report alone is **not** a certified GA receipt.

The run first verifies the actual Backend version (0.52.5), source commit supplied by the operator and independently pinned distribution digest; these are recorded in its private report. The run requires 13 observed groups: real local login + bad password, independent account, SQL password identity linking and login, two genuine browser/OIDC flows plus replay rejection, real Minecraft Services profile/join/hasJoined, official UUID link and ownership isolation, forbidden cross-account linking/unlinking, role enforcement, durable unlink, refresh family reuse revocation, and logout. Missing results, malformed credentials, missing provider, expired codes, failed HTTPS or replay acceptance **block** completion. The script deliberately never inserts mocked OAuth responses or bypasses the actual backend.

**Independent GA BLOCKED** until operator-signed external runs, real user accounts and Native/Client/ServerBridge/Guard matrices are actually completed. The on-push CI tests do not constitute that evidence. The manual physical job requires a pre-staged 0600 browser proof and cannot fabricate external OIDC authorization in CI.
