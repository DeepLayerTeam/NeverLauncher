# NeverLauncher 0.33.8 — Module & ServerWrapper Migration (MIG08)

## Supported behavior

MIG08 scans actual Gravit module JAR bytes from the identical ZIP previously
inventoried by MIG03. The entire ZIP SHA-256, byte count and per-file SHA-256
are checked. Nested JAR entries are bounded by size, count, expansion ratio,
unsafe paths and duplicate names. JARs are **never executed, linked, imported
into JVM classpath, downloaded or installed**. Class/service descriptor bytes
are examined for possible authentication and launch hooks. Unknown JARs are
**blockers**, not approved compatible adapters; even an available source tree
requires explicit porting and behavioral tests. Static inspection alone NEVER
permits cutover.

ServerWrapper 5.7.x supports an inline environment with
`SERVERWRAPPER_ADDRESS`, `SERVERWRAPPER_CHECK_SERVER_TOKEN` and
`-Dlauncher.authlib.inlineClass`, or legacy `ServerWrapperConfig.json`.
MIG08 recognizes these sources without storing old addresses, token values or
other secrets. The replacement uses the **existing** ServerBridge registration
with a freshly generated independent Ed25519 keypair. The private key always
stays with the Minecraft server, and the public key is sent via an MFA-protected
Admin request. Registration is linked to the immutable run and wrapper path;
replays may only use the same node identity. The Minecraft server must remove
old Gravit authlib patches and credentials, install/configure the matching Never
ServerBridge connector, and prove fresh signed heartbeat/login/join later.

## Operator steps

1. Create and execute MIG01 and save the matching MIG03 inventory.
2. Analyze the **same ZIP** and inspect every `modules/` JAR. Never override a
   blocker solely because the filename resembles a built-in module. Unknown
   auth/launch hooks require source port + tests or removal.
3. Remove unsupported modules and Gravit authlib/inline flags as a deliberate
   server deployment change; this release does not modify Minecraft binaries.
4. Prepare a new Ed25519 keypair in the server's secret store. Submit only its
   base64url-encoded 32-byte public key and confirm independent key origin.
5. Enroll a new ServerBridge node, with a **fresh MFA session** and exact run ID.
   Follow existing ServerBridge installation docs to use the private key on the
   target host and establish a signed heartbeat. Test login/join in MIG10.

```bash
nl migrate gravit analyze-modules --backend https://never.example \
  --token "$TOKEN" --run "$RUN" --source ./gravit.zip \
  --output ./module-report.json
nl migrate gravit modules --backend https://never.example --token "$TOKEN" --run "$RUN"
nl migrate gravit enroll-serverbridge --backend https://never.example \
  --token "$TOKEN" --run "$RUN" --wrapper server/ServerWrapperConfig.json \
  --server-id never-lobby --name Lobby --kind paper --profile-id lobby \
  --public-key "$NEW_NEVER_ED25519_PUBLIC_BASE64URL" --fresh-keys-confirmed true
```

If HTTP is used, CLI permits only explicit loopback IP addresses; use HTTPS for
production. Do not place raw private keys or legacy token contents in CLI flags.

## Grenzen / limitations

This release does **not** automatically port unknown binary modules or promise
that an unknown JAR implements the same behavior on Never. It does not certify
compatibility for auth/launch modules. New ServerBridge registration does not
prove JVM runtime compatibility, plugin hooks, heartbeat health or successful
join. An explicit MIG10 rehearsal and subsequent staged cutover remain required.
The repository's previous build limitations apply: production readiness needs
the canonical Go toolchain, PostgreSQL integration suite and Admin build.
