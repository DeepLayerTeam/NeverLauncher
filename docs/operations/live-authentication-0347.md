# Launcher 0.34.7 — actual V07 authentication/Guard validation

## Scope and trust boundary

The independent, rootless Podman attestation host (not build/test CI and not a
user-submitted JSON) runs the **exact immutable staged release** and real Minecraft
client/server. The attestation schema is `launcher.validation-evidence.v4`
(domain `Launcher/validation-evidence/v4\0`); v3 signatures do not certify
V07. A new mandatory `authentication` stage, its `authentication.json` SHA-256
and the `authenticationMode` target field are verified before the host signs.
A `passed` from the observational GitHub Actions job is not an attestation.

Stable remains **fail-closed** per 0.34.1. V07 is NOT approval to open stable.

## Required backend matrix change

Each exact target in `NEVERLAUNCHER_VALIDATION_REQUIRED_TARGETS_JSON` now MUST
include `authenticationMode`: `official` or `custom`. A missing mode, a mock,
or a target configured for a different mode is rejected. The entire configured
matrix remains bound to staged manifest/files/source/build/Java/adapter/Guard/
ServerBridge/preset digests and the backend run nonce. Changing this configuration
invalidates previous evidence. Deploy Backend and attestor together.

## Dedicated test accounts (never production accounts)

Run on a dedicated attestation host under an unprivileged local account with
rootless Podman. The Ed25519 signing key and operator API token remain host-only;
account refresh credentials never enter the container. Configure private 0600
credential files, private network and an isolated test backend/server. Do not
put production user accounts, provider refresh tokens, attestor signing keys or
server node keys into source control, GitHub artifacts or OCI images.

### Official Microsoft account

Authorize a **Minecraft Java licensed** staging account using the existing
first-party Microsoft browser PKCE or device flow. Save its `refresh_token` in
host-only `0600` file and use your own public-client application ID. Example:

```
python3 tools/validation-attestor/attestor.py \
  --backend https://staging.example.invalid \
  --operator-token-file /secure/staged-operator-token \
  --signing-key /secure/validation-ed25519.pem \
  --image registry.example.invalid/launcher/runner@sha256:<approved-digest> \
  --source-sha <approved-source-sha> --build-sha <approved-image-build-sha> \
  --manifest-key <pinned-manifest-public-key> \
  --auth-mode official \
  --official-client-id <own-public-client-app-uuid> \
  --official-refresh-token-file /secure/msa-test-refresh-token \
  --package-id <staged-package-id>
```

The trusted host actually performs:

1. Microsoft OAuth refresh with `XboxLive.signin offline_access`; persist a
   rotated refresh token atomically in the host-only file.
2. Xbox Live user authenticate, RETAIL XSTS authorize (same XUID/UHS),
   Minecraft Services `login_with_xbox` and actual Java profile lookup.
3. Pass the *short-lived Minecraft access token* and exact Java profile to
   `Runtime launch --credentials-file` in the isolated worker.
4. Worker independently checks real Mojang sessionserver `join/hasJoined` and
   launches the exact staged client against an isolated matching server using
   `online-mode=true`. The server must accept the player and real gameplay
   smoke must succeed, not just TCP or `joined the game`.

No OAuth refresh token goes into the worker. A transport outage is
`inconclusive`, an invalid/unlicensed account is rejected. No mock fallback.
A Guard-enabled official target without a live negative Guard-policy proof is
currently blocked (not falsely certified).

### Custom Yggdrasil and ServerBridge

Set `--auth-mode custom --credentials-file /secure/custom-test-session.json`
plus `--negative-credentials-file /secure/revocable-test-session.json` and
`--guard-denied-credentials-file /secure/trust-denied-test-session.json`.
Credential files contain `username`, `uuid` (32 hex characters), `accessToken`,
`userType: mojang`, `authServerBaseUrl: https://<dedicated-staging-backend>`.
These are session credentials **issued by the real backend**, bound to the
staging account, trusted device and active policy; do not substitute a test
JSON with an invented token. All three accounts/tokens must be independent.

The real Yggdrasil test performs:

- Backend `/authserver/validate` of active and separately revocable sessions.
- Fresh randomized `/sessionserver/session/minecraft/join` and matching
  `/hasJoined`, with exact profile and one-time replay rejection.
- Real invalidation of the revocable test session and denial of its outstanding
  `hasJoined` ticket.
- Actual trust-denied identity whose **otherwise valid token** is refused by
  backend gameplay-trust policy at join. For Guard-enabled releases a denial
  with a specific `guard` reason is required, not just generic 403.
- Same active identity launched through Runtime with its signed required
  authlib-injector and isolated pinned modded server distribution containing a
  version/SHA-256 verified ServerBridge; gameplay and join are checked as V02.

WARNING: custom provider validation alone must not be interpreted as proof
that an unrelated offline-mode Vanilla server enforced authentication. The
attestor therefore requires the pinned ServerBridge for custom targets.

### Network and access

Do not allow generic outbound internet on production workers. The attestor
network needs only the staging Backend, the approved provider endpoints and
Minecraft artifact delivery. Limit network destinations using host/firewall
controls; rootless Podman network isolation alone is not an egress allowlist.
Do not send credentials in command-line arguments or place private token files
under `/work`, which is inspected as attestation artifacts.

## Status rules and diagnostics

- `passed`: real provider identity, join/hasJoined and required negative
  policy tests, matching online-mode/ServerBridge server, actual gameplay.
- `failed`: account denied, wrong profile, replay allowed, revoked join works,
  Guard trust bypass or actual game failure.
- `inconclusive`: real upstream HTTP 5xx/429, transport outage or timeout.
- `blocked`: no properly provisioned test account, wrong backend/target mode,
  absent ServerBridge/Guard negative session or unsupported GUI capability.

`authentication.json` contains only mode, hashed test profile, status, outcome
flags, run ID and immutable manifest/artifact identity; never token or user name.
The host independently checks the file hash and the signed report stage. Tests
that mock provider HTTP endpoints are unit tests only, and cannot create an
accepted provider certification.

## Acceptance validation

Test 0.34.7 on a dedicated staging cluster with *real provisioned accounts*:
valid account, revoked custom session, replayed join, deleted trusted device,
Guard-denied test device, wrong UUID/name, expired token and provider outage.
A fully successful auth stage alone is insufficient: same-session Minecraft
server join and gameplay smoke are still required. Without live credentials,
real OCI runtime and matching Minecraft servers, **do not declare the feature
production-certified**.


**0.34.12 upgrade:** include the required `--diagnostics-dir` on all live attestor invocations.
