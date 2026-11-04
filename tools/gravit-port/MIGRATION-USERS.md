# NeverLauncher 0.49.4 — перенос пользователей Gravit на работающем Backend

This operator tool **executes the existing PostgreSQL-backed migration**, not
an offline conversion or a new shadow user database. It requires an existing
`prepared` Gravit migration run in `source_assessment` with an inventory of the
**exact same** original ZIP. The 0.49.3 content migration is a separate step.

## миграция аккаунтов

1. Make a consistent backup of the Gravit auth source, Minecraft worlds,
   original TextureProvider objects and target PostgreSQL. Stop the Gravit auth
   writer before final cutover. Create a Gravit migration run and inventory its
   original ZIP in the existing Migration Center. Set a separate NeverLauncher
   JWT signer and Ed25519 manifest signing key; do not copy Gravit keys.
2. Obtain a short-lived, properly permissioned operator API token through the
   normal NeverLauncher login, and supply it **only through the environment**:

   ```sh
   export NEVERLAUNCHER_MIGRATION_TOKEN='your-current-operator-token'
   python3 tools/gravit-port/migrate_users_0494.py \
       --backend https://launcher.example.org --run-id YOUR_RUN_ID \
       --source-zip /private/gravit-source.zip \
       --password-format sha256-hex --mode prepare \
       --receipt /private/gravit-users-preview.json
   ```

   Use the **actual** supported password encoding of the upstream FileAuth
   installation; unknown password hashes require a separate verified reset.
   This prepare mode persists/revalidates an identity **mapping**, but does
   not import passwords or revoke sessions. It is not a read-only database
   operation. Inspect the preview's `manual_reset` and `existing_unchanged`
   counts and manually verify any matches before migration.
3. With the user records reviewed, run the actual import. Use a different
   receipt path; the program refuses to overwrite evidence.

   ```sh
   python3 tools/gravit-port/migrate_users_0494.py \
       --backend https://launcher.example.org --run-id YOUR_RUN_ID \
       --source-zip /private/gravit-source.zip --password-format sha256-hex \
       --mode import --fresh-keys-confirmed \
       --texture-mapping-output /private/texture-map.json \
       --receipt /private/gravit-users-import.json
   ```

   The CLI verifies the original ZIP against the server inventory, maps UUIDs,
   checks the same identities from the database, previews credentials, commits
   supported hashes atomically, reads back the credential receipt, previews
   trust revocation, activates it, and reads the verified reset receipt. Old
   Gravit refresh tokens, live sessions and device keys are **never reused**.
   The original password is never logged; supported legacy verifiers are
   upgraded to Argon2id by the existing password-auth CAS path after login.
   Existing Never identities remain untouched. If any user needs manual
   password reset, the command blocks until `--allow-manual-resets` is given;
   this does **not** create a password or enable login for that user.

## роли проекта (явная проверка и устойчивый к фишингу MFA)

Gravit administrator/root permissions are **not** automatically trusted or
translated to Never global owner/admin roles. To grant project-scoped roles
**only for newly imported accounts**, supply an operator-reviewed file:

```json
{"projectId":"my-project","grants":[{"uuid":"11111111-2222-4333-8444-555555555555","roleId":"operator"}]}
```

Add `--roles-file /private/approved-roles.json` to the import command. The CLI
compares the current project-role map before each update (compare-and-swap),
and uses the existing privileged user endpoint with recent phishing-resistant
MFA; any stale or denied update stops the run. Grants are **not** automatic
source-Gravit RBAC transfers, and only `viewer`, `player`, `developer`,
`operator`, `owner` project roles are recognized. Run the import with a fresh
admin token that satisfies the endpoint's MFA requirement.

## скины и плащи

`--texture-mapping-output` writes a private (0600) one-to-one source/target
UUID map **only** for matched or successfully imported accounts. Use the
existing **real** TextureProvider importer with that mapping and the actual
upstream textures export/PNG objects. First run its dry-run, review
`planSha256`, and explicitly approve it for import:

```sh
# Требуется собранный бинарник services/api/cmd/gravit-textures-import-02510,
# LAUNCHER_DATABASE_DSN и настройки целевого Storage.
gravit-textures-import-02510 --source-id source-one \
    --source-json /private/textures.json --source-root /private/gravit-png \
    --mapping /private/texture-map.json --dry-run \
    --report /private/textures-preview.json

gravit-textures-import-02510 --source-id source-one \
    --source-json /private/textures.json --source-root /private/gravit-png \
    --mapping /private/texture-map.json \
    --approved-plan-sha256 REVIEWED_PLAN_SHA256 \
    --report /private/textures-import.json
```

Texture import is a separate operation with PostgreSQL, verified PNG bytes and
object storage; a successful account receipt does not imply that skins were
imported. Verify counts, assignments and in-game skin/cape rendering before
cutover. Do not reuse upstream private keys or browser sessions.

## ошибка и повторная обработка

The API holds the durable receipts; after an interrupted request **query the
Backend** before retrying. Credential import and trust reset both use
idempotent, run-bound PostgreSQL receipts. Do not turn `manual_reset`,
`existing_unchanged`, partial texture import or a failed role grant into
cutover PASS. Run on an independently provisioned PostgreSQL test environment
before production. This source patch does not certify signed installers or
live official Minecraft login/joins.
