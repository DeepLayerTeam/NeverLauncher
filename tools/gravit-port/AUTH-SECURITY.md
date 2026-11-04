# 0.49.6 — миграция авторизации и защиты: инструкция для оператора

This release modifies **existing execution paths**, not the Gravit module ABI. Its supported outputs are a safer legacy password verifier, an offline FileAuthSystem writer, root-signed certificate rotation, stricter Guard gating, and stricter official Minecraft profile verification. This is **not** evidence that every Gravit AdditionalHash / FileAuthSystem / GenerateCertificate / LauncherGuard / MojangSupport JAR is binary compatible.

## FileAuthSystem Database.json — explicit offline writer

1. Stop LaunchServer/Gravit and **all other users of Database.json**. NeverLauncher's live FileAuth connector is read-only and automatically re-reads the changed source; the offline writer's local advisory lock does not stop a foreign writer that ignores it.
2. Secure `Database.json` (private regular file), take a full backup of any separate `Sessions.json` and Gravit state using your normal backup system, and obtain an exact SHA-256 digest of `Database.json`. The writer **does not read or modify Sessions.json**, revoke all upstream sessions separately before restarting the source.
3. For a rename:

   ```bash
   python3 tools/gravit-port/fileauth_writeback_0496.py \
      --source /srv/gravit/auth/Database.json \
      --backup /srv/gravit/auth/Database.pre-0496-20261102.json \
      --expected-sha256 <64-CHARACTER-HEX-SHA256> \
      --operation rename --uuid <EXISTING-UUID> --username NewMinecraftName \
      --writers-stopped
   ```

   `disable` removes only the selected account (the last account cannot be removed). For legacy SHA256-hash password rotation, use `--operation set-password --password-file /secure/password.txt --password-format sha256-hex --allow-weak-legacy-hash`; **this is compatibility-only**, not recommended for new accounts. The password file must be private, is read as exact bytes, and isn't included in the receipt. Don't put passwords on the command line. Move accounts to NeverLauncher's Argon2id-backed local storage whenever possible.
4. Inspect the JSON receipt (`sourceSha256`, `updatedSha256`, backup path, operation, UUID), verify the result with NeverLauncher FileAuth login, and check revocation and newly issued NeverLauncher sessions. The writer commits by atomic rename and preserves unknown user metadata, while keeping a durable, private hardlink backup to the original inode. Never reuse a stale `--expected-sha256`; a precondition mismatch aborts without touching the source.
5. If the operation fails before commit, the existing source is intact. To restore after commit, stop all writers and recover from the private backup after inspecting intervening writes. **Do not restore old Sessions.json tokens into NeverLauncher**. Offline FileAuth mutation does not itself revoke existing NeverLauncher sessions; use existing admin session/device revocation operations as appropriate.

This maintenance tool is POSIX-only (`flock`, `fsync`, atomic same-directory rename). On Windows, perform the mutation on a supported POSIX administrative host with the storage mounted in a filesystem that supports those guarantees. If not, use the existing NeverLauncher import and account management instead.

## доверие к релизу и делегированные сертификаты

`trust_certificates_0496.py` operates on **root-signed delegated component trust**, not a Windows Authenticode or Mojang-issued certificate. It uses the existing pinned trust root; it never trusts a root advertised by Gravit input or generated at runtime. Run in the offline release-signing environment only. Keep the root seed in the provisioned `LAUNCHER_TRUST_ROOT_ED25519_SEED` environment variable, never the distributed source tree.

1. Inspect and pin the **exact SHA-256 of the existing signed policy file**. Supply the trust root public key from the pre-provisioned binary anchor.
2. Issue a delegated certificate/key:

   ```bash
   python3 scripts/release/trust_certificates_0496.py issue \
      --signed-policy /secure/trust/signed.json --output /secure/trust/signed.json \
      --expected-sha256 <SIGNED-POLICY-SHA256> --root-public <PINNED-ROOT-PUBLIC-HEX> \
      --key-id components-0496 --private-key-output /secure/trust/components-0496.key
   ```

   The private Ed25519 seed is created with mode `0600` and isn't included in the root-signed policy. The trust epoch increments. The real `component_set_sign.py` accepts this key for signing if the policy's validity interval covers the signing time.
3. Revoke this key using `revoke` with a fresh policy SHA-256 and the same pinned root. The trust epoch increments again. New component signatures with the revoked key are rejected by the actual signing path. Distribute the updated root-signed trust policy via the **existing signed update mechanism**; generating it locally does not itself revoke previously installed offline clients. Use the existing receipt/release gates for delivery and enforcement verification.

`sign-trust-policy.py` now refuses duplicate JSON and key IDs, invalid validity windows, symlinked inputs/output and malformed key material. It performs signature verification and atomically writes the signed policy with `0600` permissions.

## действующая защита во время исполнения

- **AdditionalHash:** an imported Argon2id PHC with large memory/iteration/parallelism parameters is rejected by the actual login verifier before allocating Argon2 memory; supported digest and PHPass verifiers remain unchanged. Weak legacy hashes are for supported migration only; a successful NeverLauncher login should rehash them using the existing local-auth flow.
- **LauncherGuard:** malformed or overflowing release version strings can no longer disable the Windows continuous-Guard policy requirement. Module/hook allowlist digest matching and ticket revocation remain enforced by existing Backend paths. This does not imply full anti-cheat coverage or user-mode protection parity across platforms.
- **MojangSupport:** token-authenticated Minecraft profile reads now reject invalid Minecraft usernames, not just invalid UUID strings. The existing OAuth→Xbox→XSTS→Minecraft chain, entitlement and sessionserver mechanisms remain unchanged. **Real Microsoft account / entitlement / game join must be tested separately with authorized credentials**, never test refresh tokens in a public log.

## контроль качества и продвижение релиза

Run targeted Python tests:

```bash
python3 -m unittest discover -s tools/gravit-port -p 'test_fileauth_writeback_0496.py'
python3 -m unittest discover -s scripts/release -p 'test_trust_policy_*.py'
python3 -m unittest discover -s scripts/release -p 'test_trust_certificates_0496.py'
```

Backend tests require **Go 1.27.3**, a clean dependency cache and, for integrated auth/Guard, PostgreSQL + a live API. After passing those, execute: FileAuth external login and external account removal, signed policy issue→component sign→revoke→denial, Windows Guard runtime/replay checks, and Microsoft Minecraft entitlement/session join on production-like runners.

**Status:** this patch has local execution evidence for its standalone Python code and some Go packages. Signed OS installers, PostgreSQL test, real Minecraft sign-in/join, native Guard, all Gravit module variants and independent production GA remain **BLOCKED** pending their physical/credentialled test environments.
