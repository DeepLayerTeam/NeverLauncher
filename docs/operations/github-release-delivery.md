# GitHub Release Delivery — NeverLauncher 1.2.0+

This workflow builds and publishes the Desktop distribution only. It is not a substitute for the existing whole-platform GA certification, branded project bootstrap publication, or Backend deployment. No production signing key is stored in the repository.

## Outputs

| Target | First installation (system-managed) | In-app update (user-writable installation) |
|---|---|---|
| Windows x64 / ARM64 | `NeverLauncher-<version>-windows-<arch>.msi` (WiX, Authenticode + RFC3161 timestamp) | `launcher-desktop-<version>-windows-<arch>.zip` |
| Linux x64 / ARM64 | `NeverLauncher-<version>-linux-<arch>.deb` and detached `.asc` (GPG) | `launcher-linux-<arch>-<version>.tar.gz` |
| macOS x64 / ARM64 | `NeverLauncher-<version>-macos-<arch>.pkg` (Developer ID Installer, notarized and stapled) | `launcher-desktop-<version>-macos-<arch>.zip` (Developer ID Application, notarized and stapled) |

Each of the six native installers, six coordinated updater archives and two GPG sidecars has a separate Tauri `.sig`, authenticated with the exact filename and version in the trusted comment. The selected feed (`latest.json` for Stable, `latest-beta.json` for Beta) advertises **only** the six coordinated archives, never the system installers. `SHA256SUMS` and `RELEASE_DELIVERY.json` inventory the final files, sizes, hashes, source commit and repository. The file signatures, not the unsigned checksum list alone, establish payload authenticity. Since 1.1.3, the version-specific `CHANGELOG.md` section is required and is used verbatim for `latest.json` notes and the GitHub release body; missing, duplicate, or oversized notes fail delivery. Notes are checked during publication but are not covered by the package signature.

MSI installs the exact signed adjacent Windows components into `Program Files/NeverLauncher-<arch>` with Windows Installer upgrade/uninstall registration and Start Menu shortcut. DEB installs the Linux component set under `/opt/neverlauncher`, a desktop entry, and runtime package dependencies. PKG installs the complete notarized `Launcher.app` into `/Applications`. System-managed copies should be updated by the OS installer/package manager, not by elevating the in-app updater. For in-app updates use the corresponding coordinated archive extracted into a user-writable directory (macOS: copy the app bundle to a user-writable Applications directory). Windows requires a supported OS with WebView2 Runtime; Linux DEB is for compatible Debian/Ubuntu distributions. Existing project-specific Prestarter installers remain separate.

## Repository configuration

Use a **public** GitHub repository and protect `main` and `v*` tags. Enable immutable releases in repository settings and reserve the GitHub `latest` stable channel for this Desktop workflow. Do not publish another stable release without its matching `latest.json`. Create Actions environments `production-release` (native builds and signing) and `production-publish` (publication); require owner approval and restrict deployment branches to `main`. Do not authorize untrusted branches or pull requests to access production secrets. The signing jobs have `contents: read`; only the final publication job has `contents: write`, with no private signing keys.

Repository variables (keep the same values in both environments if using environment-scoped variables):

| Variable | Value |
|---|---|
| `NL_UPDATER_PUBLIC_KEY` | Exact contents of the existing Stable Tauri updater `.pub` file, one line |
| `NL_UPDATER_BETA_PUBLIC_KEY` | Exact contents of a different Beta Tauri updater `.pub` file, one line |
| `NL_COMPONENT_SET_PUBLIC_KEY` | Existing pinned component-set Ed25519 public key, 64 hex characters |
| `NL_COMPONENT_TRUST_ROOT_PUBLIC_KEY` | Existing offline trust root public key, 64 hex characters |
| `NL_COMPONENT_SECURITY_GENERATION` | Approved positive security generation; must not be lower than deployed clients' floor |
| `NL_COMPONENT_DELEGATED_KEY_ID` | Active component signing key ID from the root-signed policy |
| `NL_COMPONENT_TRUST_POLICY_BASE64` | Base64 of the exact existing signed trust-policy envelope (not an unsigned policy) |
| `NL_LINUX_GPG_FINGERPRINT` | Full fingerprint of the Linux package signing key |
| `NL_MACOS_INSTALLER_IDENTITY` | Exact `Developer ID Installer: … (TEAMID)` identity |

The production build embeds `https://github.com/<owner>/<repo>/releases/latest/download/latest.json` and requires two distinct pinned updater public keys. Neither a fork's release nor a runtime setting can silently change these build-time values. For upgrading existing 1.1.1 installations, use the **same** embedded updater public key and endpoint (or migrate deliberately with a trusted installer); clients built with no updater endpoint must first be reinstalled.

Secrets in **production-release** (never put the private keys in Variables, source files, artifacts or release notes):

| Secret | Value |
|---|---|
| `NL_UPDATER_PRIVATE_KEY_BASE64` | Base64 of the entire Tauri private key file, without line breaks in the outer base64 |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Stable Tauri key password |
| `NL_UPDATER_BETA_PRIVATE_KEY_BASE64` | Base64 of the independent Beta private key file |
| `NL_UPDATER_BETA_KEY_PASSWORD` | Beta Tauri key password |
| `COMPONENT_SET_ED25519_SEED` | Existing component-set signing seed, 64 hex characters |
| `NL_COMPONENT_DELEGATED_ED25519_SEED` | Existing active delegated component seed, 64 hex characters |
| `WINDOWS_CODESIGN_PFX_BASE64`, `WINDOWS_CODESIGN_PFX_PASSWORD` | Trusted Authenticode certificate PFX and password |
| `MACOS_DEVELOPER_ID_P12_BASE64`, `MACOS_DEVELOPER_ID_P12_PASSWORD` | Developer ID Application certificate and password |
| `MACOS_DEVELOPER_ID_APPLICATION`, `MACOS_TEAM_ID` | Application signing identity and Apple Team ID |
| `NL_MACOS_INSTALLER_P12_BASE64`, `NL_MACOS_INSTALLER_P12_PASSWORD` | Separate Developer ID Installer certificate and password |
| `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, `APPLE_NOTARY_PRIVATE_KEY_BASE64` | Notary API credentials (base64 `.p8` file) |
| `LINUX_GPG_PRIVATE_KEY` | ASCII-armored dedicated release key usable noninteractively on an ephemeral runner |

Generate the updater key only once with `cargo tauri signer generate -w /secure/neverlauncher-updater.key` using Tauri CLI 2.12.0+, then securely back it up. The component trust root private key remains offline. For example, encode a key file on Linux with `base64 -w0 /secure/neverlauncher-updater.key`, then save that value securely using GitHub's secret interface. Do not use CI-generated test keys for releases.

## Channel isolation and release sequence

Use a separate Tauri updater key for Beta; the workflow selects the corresponding private key in an explicit conditional signing step, never a fallback to Stable secrets. Both public keys are embedded in the Desktop binaries. Stable retains `latest.json`; Beta publishes only `latest-beta.json` at the version-specific GitHub release URL. Beta is never assigned GitHub Latest. The receipt records the channel and publication verifies the exact expected asset inventory and signing key. Use one monotonically increasing numeric version sequence across both channels; a version cannot be reused or promoted in place. Example: 1.2.0 Stable → 1.2.1 Beta → 1.2.2 Stable. Both keys must be configured in release and publish environments. Beta signing keys do not replace existing platform or component signing requirements.

The signing stage depends on the reusable native-updater CI gate on all three operating systems. After publication a separate verification step in the publish job reads the public GitHub release without credentials, checks the prerelease/Latest flags and complete remote inventory, reads the public feed and downloads all six updater payloads, comparing their size and SHA-256 with the locally verified signed bytes. A failure marks the workflow failed; do not overwrite or delete the published assets to hide the failure. Diagnose and issue a strictly newer corrected build. Real installation/restart testing still requires owner-operated native machines.

## Run and release

1. Commit the complete source change to protected `main`, with `VERSION` and all generated version metadata synchronized (`python scripts/version/manage.py check`).
2. GitHub → Actions → **GitHub Release Delivery** → Run workflow → branch `main`. Select `channel=stable` or `channel=beta` and set `publish=false` for a signed candidate build; all final assets remain in the private Actions artifact. Approve `production-release`. Verify the resulting candidate and test real installs/upgrades before permitting publication.
3. Run the workflow with `publish=true` for an authorized release. Approve the separate `production-publish` job **after** reviewing this run's signed artifact and independent production acceptance. A build from a different run is not reused. Only a complete successful six-target build can reach publication. The public tag is `v<VERSION>` at the exact workflow commit.
4. The publication job revalidates all signatures and metadata, refuses an existing release or a downgrade, creates a draft, uploads every asset without overwrite, compares GitHub's reported SHA-256, size and state for each file, checks the tag again, then publishes Stable as Latest or Beta as prerelease with Latest explicitly disabled. The feed becomes visible with the draft's complete asset set. Any verification/upload failure leaves the draft unpublished; inspect it and remove only that failed draft before retrying. Never delete or overwrite a published release. If a tag already exists, it must resolve to the exact same commit. Rerun **all** jobs, not just failed jobs, because artifact names are scoped to run and attempt.
5. Verify the public feed and install/upgrade on all supported platforms, including wrong-architecture and modified-package rejection. Publishing using the built-in `GITHUB_TOKEN` does not trigger other workflows from its release event; run any required separate public acceptance workflow explicitly. The existing full-platform production release process is unchanged.

Local regression tests:

```sh
python -m pip install 'cryptography==46.0.4'
python -m unittest discover -s scripts/release -p 'test_github_release_delivery.py' -v
python -m unittest discover -s scripts/release -p 'test_native_updater_feed.py' -v
python scripts/version/manage.py check
```

The Linux integration test uses real `dpkg-deb`, GPG, signed component manifests and a temporary test ELF payload/key, not production Desktop binaries. Windows MSI and Apple PKG production execution require their native runners and owner-controlled certificates; passing the Python tests is not evidence of successful production installation. No published release, signing credentials, or native runtime acceptance is implied by this documentation.
