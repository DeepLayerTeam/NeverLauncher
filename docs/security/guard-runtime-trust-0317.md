# Guard 0.31.7 — runtime allowlist and server-side enforcement

The server does **not** infer a protected JVM from a locally hardware-backed
Device Key, a TPM Certify result or a PCR quote. These mechanisms verify
**different** properties. Current Windows Guard v2 is a **device-signed
user-mode observation**; it cannot guarantee that the JVM process is free
from hostile privileged injection, kernel intervention or tampering of the
entire client environment.

## Enabling Windows runtime authorization

Before deploying API `0.31.7`, configure `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`
with Windows `runtimeProfiles` for each allowed Desktop release. On 0.31.7+
backends missing profiles are a **configuration error**, not a downgrade to
Guard v1, when a Windows release is present. This also applies to older
versions kept in the release list during rolling upgrades.

Include your *measured and reviewed* SHA-256 values, never literal placeholders.
The existing `guardSha256` + `launcherSha256` artifact pair requirements remain.

```json
{
  "schemaVersion": "2.0",
  "releases": {
    "0.31.7": {
      "protocolVersion": 4,
      "platforms": {
        "windows": {
          "signingMode": "authenticode",
          "artifacts": [{
            "guardSha256": "<SHA-256 OF APPROVED GUARD BINARY>",
            "launcherSha256": "<SHA-256 OF APPROVED LAUNCHER BINARY>",
            "requireAuthenticode": true
          }],
          "runtimeProfiles": [{
            "javaMajor": 21,
            "moduleSetSha256": "<SHA-256 OF REVIEWED RUNTIME MODULE SET>"
          }]
        }
      }
    }
  }
}
```

`moduleSetSha256` and `javaMajor` are mandatory for every runtime profile.
Optional `codeSetSha256` and `hookSetSha256` can be set to further restrict
code/hook images where those values are sufficiently reproducible. Restrict
permissions on operator policy configuration; approval cannot originate from
an extension manifest or a client-submitted policy object.

**Enforcement path**: authenticated session + active verified trusted device →
server-generated one-time nonce → signed Windows Guard v2 evidence →
release artifact pair verification → exact runtime policy match → one-time,
short-lived ticket → fresh session/device/epoch check → at join, re-check
active device, attestation freshness, current artifact pair and runtime policy
fingerprint. Rotation/removal of an approved module set invalidates previously
issued but unconsumed tickets. This does **not** preserve trust past the
Join boundary; extended playtime protection requires a separate ongoing
challenge/response and a server-side liveness mechanism.

The server returns `runtimeAssurance=device-signed-user-mode-observation`
for a successful v2 submission; it does **not** grant a remotely verified
Guard runtime assurance or `strict` profile on that basis alone.

## Operational recovery and negative tests

- On `412 Guard runtime denied`, inspect approved JVM version/module
  set. Do **not** permit an unrecognized set automatically.
- On `Continuous Guard runtime policy changed after attestation`, restart
  attestation after the administrator has reviewed/approved a new module set.
- On device recovery/key rotation, obtain a new attestation for the current
  device and binding epoch; previous tickets must fail.
- Test a revoked Windows artifact pair, unknown Java major, changed module
  hash, changed policy, replay of a consumed ticket, and revoked device.
- Standard profiles on Linux and macOS retain their platform-specific Guard
  v1 checks. **Windows v2 runtime enforcement is not cross-platform OS
  isolation or an absolute anti-cheat.**

CI: `.github/workflows/guard-runtime-trust-0317.yml`.
