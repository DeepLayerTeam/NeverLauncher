# NeverLauncher 0.36.1: independently signed release policy

The release signer implements a **fail-closed exact-byte gate**. These are the
operational inputs for real protected environments, not fixture certificates.

## Version selection

- 0.36.0: legacy `neverlauncher.ga036.targets.v1` domain and
  `GA_VERIFIED_TARGETS_0360.json`/`GA_TARGET_APPROVAL_0360.{json,sig}`.
- Stable releases >=0.36.1: Ed25519 domain
  `neverlauncher.ga.targets.v2\0` (a *literal NUL byte*),
  `neverlauncher.ga.targets.v2` signed approval schema,
  `neverlauncher.ga.execution.v2` execution trace schema and
  `neverlauncher.ga.verified-targets.v2` receipt schema. Files:
  `GA_VERIFIED_TARGETS.json`, `GA_TARGET_APPROVAL.json`, `GA_TARGET_APPROVAL.sig`.
- Historical single-node SQLite GA 0.33.0 remains specific to 0.33.0. Its
  certificate **does not** authorize a later release.
- A prerelease version is not eligible for **stable GA**. All later stable
  versions require fresh approval for their own commit and final bytes.

## Operator signing and immutable identity

The independent operator must run, for each of Windows/Linux/macOS x64 and
ARM64, `nativeInstall`, `desktopLaunch`, `minecraftLaunch`, `serverJoin`,
`releaseRollback`, `security`, `performance`, `operations`, `osSignature`.
Each trace JSON must describe **actual execution** (`actualExecution:true`,
`simulated:false`) for the exact source SHA/version and tested executable
SHA-256. Store these 54 original reports under `targets/<target>/<check>.json`
and put their individual SHA-256 hashes in a signed `approval.json`.

The approval must contain exactly: `schemaVersion`, `version`, `commit`,
`issuedAtUtc`, `expiresAtUtc`, `targets`. A target contains exactly `target`,
`status` (`certified`), `binarySha256`, `packageSha256`, `checks`. Each check
contains exactly `sha256`. All six target names are mandatory:
`windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`, `darwin-x64`,
`darwin-arm64`. UTC timestamps must use second precision and expire within
seven days of issuance.

Use a protected operator-private Ed25519 key, **different** from the release
signing key and unavailable to regular CI. Sign the raw `approval.json` bytes
prefixed with the policy domain (without JSON reserialization). Store the
64-byte signature as lowercase hexadecimal in `approval.sig`. The public
32-byte raw Ed25519 key is hex-encoded in the independently protected CI
variable `NL_GA_OPERATOR_PUBLIC_KEY_HEX`; do not load it from the evidence
archive, checked-in sources, or release package.

Example for an authorized operator in a protected environment (the private
key is not stored in this repository):

```python
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pathlib import Path
approval = Path('approval.json').read_bytes()
private = load_pem_private_key(Path('/secure/operator-private.pem').read_bytes(), password=None)
Path('approval.sig').write_text(private.sign(b'neverlauncher.ga.targets.v2\x00' + approval).hex() + '\n')
```

The signing snippet signs an existing independently collected evidence set;
it does **not** generate reports or claim to have executed Minecraft.

## Protected workflow

1. CI builds all required jobs for one `GITHUB_SHA`. Independent protected
   execution produces and signs the 54 reports tied to the actual staged
   executable and installer hashes; publication must wait for these results.
2. Upload `approval.json`, `approval.sig`, `targets/` as a protected Actions
   artifact named `neverlauncher-ga-signed-<commit>`. Pass its **workflow run ID**
   to `ga_operator_approval_run_id` when dispatching
   `.github/workflows/production-release-candidate.yml`.
3. Supply pinned `NL_GA_OPERATOR_PUBLIC_KEY_HEX`. The release runner verifies
   the operator signature and exact version/commit before building; during
   release staging it verifies **every file hash and execution report** again.
4. The Go `release sign` command repeats the independent verification of the
   54 execution records and six exact-byte executable/package pairs, validates
   the staged approval and receipt, and rejects a release-signing key equal to
   the independent operator key. A direct CLI invocation cannot bypass this.
5. The approved artifacts enter `RELEASE_MANIFEST.json` and signed
   `SHA256SUMS`, and `release verify`/`publish-check` continue to enforce the
   other mandatory compatibility, device trust, guard and delivery gates.

For offline production use, set `NEVERLAUNCHER_GA_EVIDENCE_DIR` to the
operator-signed evidence directory and
`NEVERLAUNCHER_GA_TRUSTED_PUBLIC_KEY_FILE` to the independently managed raw
public-key hex file. Keep both outside the release output. The source commit
must be a clean Git `HEAD` and match the signed approval exactly.

The historical 0.36.0 inputs remain `NEVERLAUNCHER_GA036_EVIDENCE_DIR` and
`NEVERLAUNCHER_GA036_TRUSTED_PUBLIC_KEY_FILE`; the historical workflow dispatch
uses `ga036_operator_approval_run_id`.

**No operator evidence or no actual execution means BLOCKED, not PASS.**
Tests for signature handling use synthetic fixtures and do not provide a GA
certificate. This change does not claim a live Minecraft cycle has been run.
