# NeverLauncher 0.35.2 — execution evidence and remaining requirements

## Implemented paths

- Prestarter reuses the already-verified signed bootstrap envelope and hands
  its **exact bytes** to the native Desktop. The owner chooses backend, profile,
  channel, signing public key and optionally ServerBridge ID/public game host.
- Native Desktop verifies the owner signature against its compile-time root,
  and for v2 the root-signed delegated policy and epoch. A malformed or
  unauthorized signed binding fails closed; user preferences cannot override
  owner route and trust key at native read/write boundaries.
- Onboarding uses live API authentication, actual manifest signature checking,
  requirements/Java, optional component presets and server listing,
  transactional NeverRuntime download and a *second* native file verification.
  Only the native completion command can persist the completed flag; flag
  validity is tied to the verified bootstrap digest.
- The player must explicitly click Play; a downloaded artifact is **not**
  reported as a running game or a verified server join.

## Local checks performed

- `cd prestarter && go test -run 'TestOwnerSignedFirstRun0352|TestBootstrapServerPolicy0352|TestSignedConfigCannotBeTamperedWith|TestOfflineFreshInstallAndVerifiedRecovery' -count=1 -timeout 40s .` — PASS.
- `node --experimental-strip-types --test apps/desktop/tests/desktop_experience_0229.test.mjs` — 4 PASS.
- Desktop launch-mode TypeScript compile and 4 real Node tests — PASS.
- TypeScript compiler `transpileModule` TSX syntactic diagnostics — 0.

## Not yet verified locally

- Tauri/Rust compilation and the added Rust signature unit tests: `cargo` is
  not installed in this execution environment.
- Full Desktop npm/React production build: the required pinned npm tarballs
  are not available in the offline npm cache (`npm ci --offline` fails).
- Real live owner-signed branded Desktop → Backend authorization → Minecraft
  launch → ServerBridge join on all OS targets: requires a provisioned signing
  root, credentials, backend and platform-native executables.

The added CI workflow is configured to run native/Go/React checks in an
appropriate environment. Its execution has not been observed in this session.
No GA or cross-platform production certification claim is made.
