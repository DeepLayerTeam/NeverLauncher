# NeverExtensions GA — NeverLauncher 0.21.0

NeverLauncher 0.21.0 freezes the first production NeverExtensions compatibility line. The freeze is behavioral, not only declarative: the registry, lifecycle manager, hosts, SDKs and startup reconciler enforce the same contract.

## Frozen compatibility surface

| Surface | GA version | Enforcement |
| --- | --- | --- |
| Extension Package | v1 (`1.0`) | deterministic `.nlext`, checksums, SBOM, Ed25519 signature, immutable package identity |
| Manifest | v2 (`2.0`) | canonical validation in CLI and Backend |
| Host Protocol | v1 (`1.0`) | authenticated loopback handshake, PID/instance binding, API negotiation, heartbeat |
| Extension API | v1 (`1.0`) | required for new 0.21+ publications and new SDK projects |

`api: "3.7"` is retained only as the 0.20.x compatibility alias. Existing signed packages are never rewritten: the Backend maps that legacy marker to Extension API v1 while loading them. The 0.21 registry refuses new `3.7` publications so new artifacts converge on `1.0`.

## Production lifecycle

Registry publication verifies publisher identity, trusted/non-revoked Ed25519 key, deterministic package identity and signature before immutable storage. Installation and update stage payloads before atomic activation, persist generation-checked lifecycle state and lockfiles, retain rollback backups, and keep package identity bound to the active version.

On Backend startup, GA reconciliation validates every installed extension against its persistent lockfile, manifest/API contract, registry package identity, trust policy, key revocation, quarantine, emergency-disable state, permission catalog, dependency ranges and conflicts. Invalid enabled installations are fail-closed: a persistent emergency-disable is recorded, the lifecycle is transitioned to disabled, and an audit event is emitted. The Admin API exposes read-only GA status plus an MFA-protected manual reconcile action.

## Hosts

Backend and CLI executable targets use Host Protocol v1. The host injects `NEVERLAUNCHER_EXTENSION_API_VERSION=1.0`; GA SDKs send `extensionApiVersion` in `/v1/hello`, and the host validates it. Legacy 0.20 SDK hello payloads without this field are accepted only for manifests carrying the legacy `3.7` marker.

Admin and Desktop targets remain opaque-origin sandboxed UI surfaces. Their typed bridge context now includes `extensionApiVersion: "1.0"`. Desktop `host.context` uses the same nested envelope consumed by the Desktop SDK. Capability access remains deny-by-default and permission-gated.

## SDK and source upgrade

New scaffolds use Extension API `1.0` and SDK `0.21.0`. `nl extension upgrade-source <dir>` atomically upgrades an unpacked 0.20 source manifest from `3.7` to `1.0` and updates known Go SDK module references. Signed `.nlext` files are rejected by this command because package bytes are immutable; they must be rebuilt and re-signed from source.

Use `nl extension ga status` to print the frozen contract. The database migration `0049_neverextensions_ga_0210.sql` records the active GA contract and blocks upgrades containing extension API values outside the supported GA/legacy set.

## Certification

`neverextensions/ga-targets-0210.json` defines the required Linux, Windows and macOS gates. `.github/workflows/neverextensions-ga-0210.yml` executes contract/package/trust/lifecycle/host/dependency/update/security/reconcile/SDK/UI/migration/OpenAPI/build checks on every required OS. `scripts/compatibility/neverextensions_ga_0210.py` aggregates only complete PASS evidence and emits a public compatibility matrix plus a certificate whose evidence SHA-256 values bind the result to the individual runner artifacts.

The checked-in repository does not claim cross-platform certification before CI evidence exists. Certification is produced only by the aggregation job after all required runners pass.
