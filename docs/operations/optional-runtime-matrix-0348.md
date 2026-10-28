# 0.34.8 — actual staged optional runtime matrix

Every required target has a separate backend-issued nonce, scoped staged grant,
rootless OCI worker, fresh installation, selected preset, Minecraft menu, real
matching-server join, gameplay observation, live authentication test and
independently signed ValidationEvidence. A default-preset run is never counted
for a different preset. Stable remains denied pending V11.

## Derivation / fail-closed behavior

The Backend rejects non-executable legacy catalog choices (manifest schema before 3.0 or catalog schema 1.0). It generates mandatory selection IDs from the **signed immutable
release Component Catalog**: every named publishable preset (or `default` when
none), a standalone positive selection for condition-gated optional components
not selected by a named preset, then up to 12 deterministic compatible pair
combinations in lexicographic order. Pair choices use the native signed form
`@custom:v1:<base>:+id,+id`; no replacement, unsigned mod path or local
component graph is accepted. Incompatible pairs are omitted after resolver
validation. Conditional OS/architecture branches explicitly advertised by
the catalog require matching targets; invalid preset/dependency/conflict graphs
block target-policy acceptance. Declared Java/loader conditions are checked by
the actual native resolver on the selected target.

Every reachable condition-bearing component absent from named presets is a mandatory selection (an oversized mandatory matrix is rejected instead of truncated). The max 12 additional pairs and 512 evaluated candidate pairs are **not exhaustive**. The API's validation-attestation
coverage response exposes `requiredComponentSelections`, per-target
`targetCoverage`/`targetBlockers`, and `unverifiedCandidateCombinations`
for compatible-but-not-selected and not-yet-examined candidate choices. Never describe
unexecuted combinations as passed.

Administrators must pin one required-target record for **each** derived
selection in `ValidationRequiredTargetsJSON0346`. Each record also pins
manifest/artifact digest, Java, loader, ServerBridge, signed runtime plan,
adapter, Guard, official/custom auth and platform. The Backend rejects a
matrix missing any required selection at grant issuance and evidence
acceptance. Never fabricate placeholder digest values: produce/test those
values on the target runner and then pin them in the policy.

## Trust boundary

The independent attestor's `execute_matrix()` obtains a fresh grant per target,
launches the approved OCI image by immutable digest with `--preset`, and
verifies the actual component files against the signed catalog, Native
NeverRuntime offline transactional `adopt-staged` and `verify` output, and a newly bound resolved-plan
digest. It rejects unselected optional mod files that remain in the installed
client directory. The attestor signs successful runs only; a failed/blocked
or provider-inconclusive run does not become certified, and the matrix result
is incomplete. No attestation signing key is mounted in the worker.

Run the existing rootless Podman attestor with `--package-id` for a one-shot
full matrix, or submit a package ID to its existing mTLS `/v1/attest` endpoint.
The host requires real official/custom test identities and an appropriately
pinned matching server bundle. GUI-capable Linux/X11 is currently the only
implemented visual worker; other operating systems remain unverified, not
falsely passed. Follow the 0.34.5 and 0.34.7 attestation runbooks for host
hardening and credential isolation.

Before accepting GA: run the V08 Go/Python tests, build the revised OCI image
on the trusted host, pin its new digest, then execute the full matrix against
an actual signed staged package. Tests never substitute for the latter.

The staged workflow first runs the ordinary Go client install/verify into an isolated delivery folder. NeverRuntime then imports only signed selected files into a separate live client root through its durable offline release transaction. This path performs zero network downloads and rejects mismatched source bytes. The attestor verifies this import record before signing evidence.
