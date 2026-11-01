# Gravit modules → Never ServerBridge (0.44.6)

## Source inspection

1. Inventory a ZIP with `nl migrate gravit inventory` and produce a pinned `dry-run` for the target project and selected profile.
2. Run `nl migrate gravit analyze-modules --run <run-id> --source <original-gravit.zip>` using the **same source SHA-256** as the inventory. The report includes each source JAR and module JSON config by path and hash, without persisting configuration secrets.
3. Treat unknown auth/launch modules, missing JARs and invalid configs as blockers. A valid config with a matching JAR is **not** a compatible Never module: port the module's behavior to the supported SDK and independently test it. Never upload or execute foreign Gravit binaries in the backend.

## Connecting a replacement node

1. Resolve the migration blockers. Preview the destination, then import and verify its selected client profile and files. The new game node must reference exactly that imported profile, not any other profile with an equivalent display name.
2. On the *new* ServerBridge host, generate an independent Ed25519 keypair and configure the server plugin/adapter. Never copy Gravit `checkServerToken`, signing keys, authorization tokens or JVM private keys.
3. Enroll using Migration Center or `nl migrate gravit enroll-serverbridge --run <run-id> --wrapper <source-wrapper-path> --server-id <new-node-id> --name <name> --kind paper --profile-id <destination-profile-id> --public-key <new-public-key> --fresh-keys-confirmed true`. The enrolment has an immutable server ID/key fingerprint reservation and can be retried only with the same source wrapper, ID and key.
4. Start the game server with its Never ServerBridge adapter. Check `nl migrate gravit serverbridge-status --run <run-id> --wrapper <source-wrapper-path> --out <private-report.json>`. The command fails unless a **recent signed runtime heartbeat** matches the immutable identity, project and profile. The Admin page can query the same live status. Node registration is not a runtime heartbeat.
5. Prove actual login, one-time session join, player UUID continuity and a real Minecraft connection with the rehearsal runner. A successful `online` status does **not** authorize cutover. Use the separately confirmed cutover/rollback process.

## Failure handling

- `awaiting_registration`: reservation exists but the node was not stored; retry enrollment with exactly the same ID/key after checking the node is absent.
- `awaiting_runtime`: start the adapter, configure its local Ed25519 private key and ensure signed traffic reaches the backend; check runtime ID, identity epoch and last heartbeat.
- `blocked`: node was disabled, key rotated unexpectedly, or project/profile ownership differs. **Do not adopt the existing node or copy a Gravit key.** Reconcile identity and start a new verified migration if necessary.
- HTTP 409 on enrollment: the plan, the imported profile or the reserved node identity no longer matches. Do not bypass the guard with direct SQL.

The current scope is a **single selected profile per migration run**; migrate other profiles independently. Static JAR scanning and signed heartbeat checks are not module behavior or gameplay E2E certification.
