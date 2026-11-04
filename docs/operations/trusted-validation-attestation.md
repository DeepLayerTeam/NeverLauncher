> **0.34.7 compatibility:** V07 requires ValidationEvidence v4 and the explicit `authenticationMode` target field. The v3 procedure below is historical; follow [live-authentication-0347.md](live-authentication-0347.md) for new trusted runs. Older evidence never satisfies the new required authentication stage.

# 0.34.5 — Real staged execution with independently signed ValidationEvidence

## Trust boundary

`tools/validation-attestor/attestor.py` is an independently deployed host-side
mTLS service (or one-shot CLI), NOT a job in the normal GitHub runner. An
operator-approved OCI image is built from `tools/validation-attestor/Containerfile`
and published by the operator's trusted image pipeline. The service requires its
immutable `repository@sha256:...` and the expected image digest must be set on
Backend. The host holds the dedicated Ed25519 PKCS#8 key (file mode 0600).
Release signing uses a DIFFERENT key and key store; Backend rejects an attestation key equal to the manifest-signing public key. There is NO attestation
signing key or production database credential in the worker or CI.

## Deployment

1. Provision a non-root account with rootless Podman and dedicated, **firewalled**
   validator egress. Explicitly allow only staged Backend + required upstream
   Minecraft endpoints; block production/private networks. The service creates
   a **unique** container network for each run. Network namespaces by themselves
   do not replace the host egress policy. Avoid privileged containers, Docker
   socket mounts, host network, host PID namespace and shared worker volumes.
2. Build, review and publish the trusted OCI image using the root-level
   `tools/validation-attestor/Containerfile` (`podman build -f
   tools/validation-attestor/Containerfile --build-arg SOURCE_SHA=<git-commit>
   --build-arg BUILD_SHA=<trusted-build-input-sha256> -t registry.example.test/validation/runner:<version> .`).
   Pull/push and approve its immutable `@sha256:` digest, source commit SHA and
   build-input SHA-256. The host verifies BOTH immutable OCI build-provenance
   labels against approved parameters before releasing a grant. Use separate images for other Java
   toolchains. The included image has Java 21; it MUST NOT certify a target
   requiring unavailable Java 8, 17 or 25.
3. Generate an independent Ed25519 key, not a release/manifest signing key:

   `openssl genpkey -algorithm Ed25519 -out /secure/attestor-ed25519.pem`

   `chmod 0600 /secure/attestor-ed25519.pem`

   Export the **raw 32-byte public key** as base64url without padding into
   `LAUNCHER_VALIDATION_ATTESTATION_PUBLIC_KEY`. Set
   `LAUNCHER_VALIDATION_RUNNER_IMAGE_SHA256` to exactly 64 lowercase hex
   characters from the approved image's `@sha256:` reference. Configuration
   absent or mismatched is fail-closed.
4. Store the scoped Backend `release:prepare` operator token in a 0600 file,
   readable by only the host attestor. Use a separate operator identity, never
   a production signing credential.
5. Start the service with `python3 tools/validation-attestor/attestor.py
   --backend https://staging.example.test --operator-token-file /secure/operator-token
   --signing-key /secure/attestor-ed25519.pem
   --image registry.example.test/launcher/runner@sha256:<digest>
   --source-sha <git-commit> --build-sha <sha256> --manifest-key <64-hex-key>
   --tls-cert /secure/server.pem --tls-key /secure/server-key.pem
   --client-ca /secure/clients-ca.pem`. Client certificates are required for
   `POST /v1/attest`, with only `{"packageId":"..."}` accepted. For a one-shot
   validation, supply `--package-id <id>` and omit the mTLS arguments.

For a modded matching server use `--server-bundle-file`, `--server-sha`,
`--server-entry`, `--bridge-path`, `--bridge-sha`, `--bridge-version`. These
are host-controlled, not supplied by the caller. Failure to supply the real
matching server, Java, GUI, account or bridge prevents attestation.

## Execution

The service issues a fresh Backend grant, then hands **only that grant** to
its immutable OCI worker using a read-only mount. It runs Runtime using
normal staged download, transactional install, GUI, loader and gameplay logic.
Worker exit alone is not PASS: the host rehashes downloaded **and installed**
files, recomputes runtime plan/Guard digests and verifies menu frames,
matching server evidence, player positions, game ticks, client input, gameplay
frames and stage hashes. Only after all seven required checks pass does the
HOST sign `launcher.validation-evidence.v2` under a domain-separated
Ed25519 signature and submit it with its scoped operator token.

Backend verifies the pinned public key and OCI image digest, rejects arbitrary
CI signatures, compares the signed evidence to its immutable staged manifest,
artifact digest, current integrity proof and persisted same-run stage hashes,
then commits it once in PostgreSQL. Repeated run IDs are rejected. The
old staged report endpoint stays **untrusted**.

**No success claim without real host provisioning**. V05 will add freshness,
full policy/target applicability and revocation; V11 full stable gate remains
blocked in 0.34.5. Existing CI executes tests but never signs certification.

## Operations

The host deletes its temporary download/game directories after every run and
never mounts the signing key. Ensure rootless Podman's storage and network
are segregated from other services; run only one validation per attestor
instance. Rotate compromised keys by updating the pinned public key and
reviewing already issued attestations. Log redaction and retention are extended
in V12. Do not publish raw logs containing player/session credentials.


**0.34.12 upgrade:** the attestor now additionally requires `--diagnostics-dir` pointing to an owner-only 0700 persistent directory; see `validation-reports-security-03412.md`.
