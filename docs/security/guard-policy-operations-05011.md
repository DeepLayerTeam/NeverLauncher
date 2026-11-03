# NeverLauncher 0.50.11 — Guard Diagnostics & Policy Operations

## Trust model

The client may only accept an Ed25519-signed compatibility policy from an **externally pinned** public key. The private signing key must remain offline and outside the Minecraft root, Admin, and release archives. Installing or rolling back an authorized configuration does not disable file/JVM/runtime protection and cannot reduce the accepted epoch. The accepted floor is written before the active envelope for fail-closed crash handling.

Admin's Diagnostics → Guard section verifies submitted envelopes using browser WebCrypto and a pinned **external** public key, prepares unsigned revoke/rollback candidates, verifies an offline-signed replacement, and reads local CLI diagnostic reports. The browser cannot deploy files to a user's computer or sign with a server-held secret. Actual client deployment uses the trusted CLI.

## CLI — verify, inspect and diagnose

Use the compiled `launcher` executable (the following commands refer to its top-level `runtime client-factory` dispatcher):

```sh
launcher runtime client-factory guard-policy-status --client-dir /path/to/minecraft --public-key /external/guard.pub
launcher runtime client-factory guard-policy-history --client-dir /path/to/minecraft --public-key /external/guard.pub
launcher runtime client-factory guard-policy-diagnose --client-dir /path/to/minecraft --public-key /external/guard.pub --project PROJECT_ID --minecraft 1.21.1 --loader fabric
```

`guard-policy-diagnose` hashes the actual authorized artifacts, checks for unknown JARs in `mods` and unauthorized native libraries and ensures scope and epoch match. It emits JSON with `status=pass|blocked`, and a nonzero exit code on failure. It does not claim to inspect arbitrary running memory, bypass SIP, or prove actual game join. Include explicit `--agents /absolute/client/path.jar` and `--plugins ...` for those launch arguments.

History is stored as immutable, signed envelopes at `.launcher/guard/history/<epoch>-<payload_sha256>.json`. It is validated on read against the external key, including expired historical signatures at their issue time. Manual edits of archived bytes are detected. Snapshots are not substitutes for protected backups. A new install records both old and new verified envelopes before raising the accepted floor. If a crash interrupts the floor-first install, re-applying the *same* signed candidate completes recovery; never delete `accepted.json` to force a downgrade.

## Offline revocation

Use the **separate** `guard-policy-sign` utility on an offline operator machine:

```sh
guard-policy-sign --mode revoke \
  --current current.signed.json \
  --private-key /secure/offline/guard-private.hex \
  --revoke-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --revoke-transform com.example.Hook \
  --out revoked.signed.json
launcher runtime client-factory guard-policy-install \
  --client-dir /path/to/minecraft \
  --public-key /external/guard.pub \
  --policy revoked.signed.json
```

The issuer verifies the current signature with the public half of the signing key, increments the epoch, preserves all previous revocations, and issues a fresh seven-day validity window. It writes a new file exclusively rather than overwriting it. The policy must be distributed and installed on every applicable client; this version does not implement a remote live-policy push service.

## Restore an approved historical configuration (rollback)

```sh
guard-policy-sign --mode rollback \
  --current current.signed.json \
  --previous historical.signed.json \
  --private-key /secure/offline/guard-private.hex \
  --out restored.signed.json
launcher runtime client-factory guard-policy-rollback \
  --client-dir /path/to/minecraft \
  --public-key /external/guard.pub \
  --policy restored.signed.json
```

The restored envelope is **not** a replay of the earlier epoch: it uses the latest epoch + 1, copies previously authorized artifacts/settings, and keeps the union of current and historical revocations. The CLI rejects a signed rollback that changes project/game/loader scope, lowers the epoch, or clears any current revocation. This is a configuration restore, not a bypass of previous security decisions. The exact files still must match their signed SHA-256, and previously revoked files remain forbidden. A fully expired policy must first be replaced by a newly signed active version.

## Operator verification and release gates

```sh
cd cli
go test ./cmd/guard-policy-sign -count=1
go test ./cmd/launcher -run 'TestGuardPolicyOperations05011|TestGuardCompatibility0502' -count=1
cd ../apps/admin
node --experimental-strip-types --test tests/guard_policy_05011.test.mjs
npm ci && npm run build
```

Go and WebCrypto tests cover valid signatures, tampering, no-rollback floors, crash recovery, active/historical inspection, unwanted JARs, bad scope, offline revocation, and irreversible revocation-preserving rollback. Independent native Windows/macOS/Linux and real Minecraft+Guard multiplayer acceptance must still be performed on signed release artifacts; GA remains BLOCKED until those results exist.
