# ServerBridge Verified Plan Policy (0.24.12)

## Enforcement

Set **all three** environment variables on every API instance:

```sh
NEVERLAUNCHER_SERVERBRIDGE_REQUIRE_PLAN_POLICY=1
NEVERLAUNCHER_SERVERBRIDGE_PLAN_POLICY_FILE=/etc/launcher/bridge-plans.signed.json
NEVERLAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY=<64-char-hex-offline-policy-public-key>
```

Configuring either the policy path or its public key also enables enforcement. A missing file, invalid signature, expired policy, or missing trusted device **denies** protected joins. Without any setting, the previous legacy join flow remains available for explicit staged migration; **legacy mode does not provide component-plan enforcement**. All Backend replicas must use identical policy configuration. Do not put the signing private key on the server.

Policy body (UTF-8 JSON) example; replace dummy hashes and dates with real signed release measurements:

```json
{
  "schemaVersion": "1.0",
  "epoch": 1,
  "issuedAt": "2026-10-21T00:00:00Z",
  "expiresAt": "2026-10-22T00:00:00Z",
  "requireContinuousGuard": true,
  "allowedPlans": [
    {
      "serverId": "survival-main",
      "projectId": "demo-project",
      "profileId": "survival",
      "channel": "stable",
      "releaseSignature": "<128 lowercase hex characters from owner-signed Manifest v3>",
      "catalogDigest": "<64 lowercase hex characters from signed catalog v5>",
      "planSha256": "<64 lowercase hex characters from native resolved-download-plan.v1>"
    }
  ]
}
```

Each allowed-plan entry is a **complete combination** of a signed manifest signature, its catalog digest, and the exact native resolved-download plan SHA-256, bound to ServerBridge server/project/profile/channel. The signature is the existing Ed25519 signature in the *release manifest* (not its hash). Populate the `planSha256` from the trusted Desktop preview after preparing and verifying the particular preset. Never whitelist a digest submitted by an unknown client without approval.

Sign an actual JSON policy with an **offline** Ed25519 seed in hex:

```sh
cd services/api
go run ./cmd/planpolicy-02412 -policy /secure/policy.json -key /secure/offline-policy-seed.hex -out /secure/bridge-plans.signed.json
```

The command emits a policy envelope with `schemaVersion`, base64 of the exact signed policy bytes, and an Ed25519 signature over `Launcher-ServerBridge-Plan-Policy-v1\n` + those bytes, and prints the public key for configuration. This is a **separate operator key**, not the game release signing key or ServerBridge node private key. Store the private seed offline.

## Execution path

1. Desktop launches verified Minecraft and completes Continuous Guard v2 attestation. The Backend produces a one-time Guard ticket containing the attestation digest, runtime PID, hashes and session/device bindings.
2. Authenticated Desktop requests `POST /api/v1/server-bridge/plan-challenge` for server/project/profile/channel; Backend checks authorized project, Device Trust, pinned policy, generates an unpredictable 60-second challenge, and stores it in `device_challenges` (PostgreSQL or in-memory development).
3. Native Tauri reads the signed, installed active release from Runtime; `verified_active_selection_02410` validates all managed files. It recomputes the exact native resolved-download plan and signs a domain-separated proof with the currently bound **hardware P-256 device key**. Arbitrary client-provided component lists and plan hashes are not accepted by the native signing command.
4. `POST /api/v1/session/join` submits this proof together with the one-time Continuous Guard ticket. The API verifies the policy, target, session, device/binding epoch, exact allowlist tuple, Guard attestation digest and P-256 signature; atomically consumes the one-use plan challenge. Only then does the existing ServerBridge issue a one-time join ticket.
5. The registered node cryptographically authenticates `validate-join`; existing checks for session, Guard, trust, release integrity, one-time redemption and routing still run. On policy rotation, unredeemed tickets minted before `issuedAt` are invalidated.

## Limits and threat model

- **Mandatory Continuous Guard v2** is currently certified for Windows. Protected-plan admission deliberately **fails closed** on platforms that lack such proof; it must not silently downgrade to a signed mod list.
- The evidence proves that the installed managed files were verified by the trusted native launcher when the hardware key signed, and binds that measurement to a specific authenticated session and Continuous Guard evidence. It does **not**, by itself, prove that each mod was actually loaded by the Minecraft JVM or that every byte of JVM memory still matches the disk. For that stronger claim, a future measured classloader + remote attestation protocol is needed.
- The policy is time-limited (at most 30 days) and can be revoked by replacing the trusted policy file. Enforce short policy validity windows; persistent anti-rollback of previously signed still-valid policies is not provided by this release.
- A proof can be used only once across PostgreSQL API replicas. A retry after a consumed challenge requires a new challenge and a fresh hardware signature. Expired, tampered, cross-session, cross-server and replayed proofs deny admission.
- `REQUIRE_PLAN_POLICY=1` must be configured on **all** API replicas. Disabling enforcement re-enables the legacy flow and must be treated as a conscious operational change.
