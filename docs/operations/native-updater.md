# Native Updater (1.2.0)

## Trust and installation

Desktop → Настройки → Обновление Launcher. The version check uses `tauri-plugin-updater` 2.14.1; only a strictly newer numeric X.Y.Z version from the selected channel is offered. The offer is retained natively for 15 minutes. An offered version is not proof that the package is authentic. Rust downloads the exact offered URL over HTTPS with a ten-minute deadline and a 512 MiB limit, either on demand or when the user has opted into automatic downloads. It verifies the bytes with `Update::verify`, requiring the signed version in the minisign trusted comment, then checks the version/platform/architecture of `COMPONENT_UPDATE_MANIFEST.json` inside the authenticated archive. The verified package stays in native memory until installation, another check, or application exit. The WebView cannot provide a key, URL, package path or hash, and receives only progress, version and informational release notes. Installation always requires a separate user action.

Existing coordinated component archives are the update payload: Windows and macOS ZIP, Linux TAR.GZ (ZIP also accepted). The Tauri `Update::install` standalone binary replacement is intentionally not used: the existing CLI transactional installer verifies the signed component set, trust policy, security generation and platform requirements and replaces Desktop, Guard, Runtime and required support files together. An arbitrary file path/hash is no longer exposed as an IPC installation command. Running Minecraft and in-flight native game mutations block installation, but not the network check or download. The verified bytes are staged in a private per-update directory and the helper receives their native SHA-256; no user-supplied SHA-256 is trusted. The helper needs write access to the installed component layout and must be present; system-managed installations requiring elevated privileges should use their OS package manager. On Windows/macOS the existing OS code-signing requirements remain independent of the Tauri signature.

## Desktop update experience

- After native configuration loads, the updater checks at startup (after five seconds) and every 24 hours by default. In Settings → Обновление Launcher, choose 6, 24 or 168 hours, disable automatic checks, or opt into automatic download. Preferences are stored locally in the WebView; no private data or trust anchors are stored there. A manual check remains available when automatic checks are disabled.
- The same panel remains mounted across navigation. Available versions and download/verification progress appear on all screens. Check failures back off for 15 minutes; focus/network events also evaluate the next due check. Manual checks remain available after errors. Missing length uses indeterminate progress; known length displays bytes and percentage.
- Download and installation are separate. Click download to retrieve and verify the offered package, then click install/restart explicitly. If the 15-minute offer has expired, check again before downloading. If Minecraft or another native operation blocks installation, the verified package remains available for retry. If scheduling fails after the package is consumed, check and download again. A manual check discards the prepared package; restarting the app also discards it. No automatic installation or forced restart occurs. Network operations are serialized separately from the installation/game lock.
- Release notes are extracted from the exact version heading in `CHANGELOG.md` and published as `notes` in `latest.json` and the GitHub release body. Notes are displayed as bounded plain text (no HTML or clickable remote links) and are informational, not authenticated by the package signature. Older feeds without notes remain supported. Only the signed package and existing component trust policy authorize installation.

## Build with owner-controlled trust

The repository intentionally does not contain a production private key, guessed public key or fictitious release endpoint. Generate a dedicated key on a trusted release host using Tauri CLI 2.12.0 or later:

```sh
cargo tauri signer generate -w /secure/neverlauncher-updater.key
```

Install the CLI using `cargo install tauri-cli --version 2.12.0 --locked` if required. Back up the key securely outside the repository; never expose its password or private contents. Use the contents of the generated `.pub` file in the build environment, not its pathname. Configure the following before executing the existing platform production build scripts (or `cargo build`):

```sh
export NL_UPDATER_PUBLIC_KEY="$(cat /secure/neverlauncher-updater.key.pub)"
export NL_UPDATER_ENDPOINT='https://YOUR-RELEASE-HOST/neverlauncher/latest.json'
export NL_REQUIRE_NATIVE_UPDATER=1
```

On PowerShell, use `$env:NL_UPDATER_PUBLIC_KEY = (Get-Content /secure/neverlauncher-updater.key.pub -Raw).Trim()` and equivalent `$env:` variables for the endpoint and requirement. The endpoint must be your actual HTTPS endpoint. The build embeds the public key and endpoint; runtime environment changes and editable launcher preferences cannot change them. A build with neither variable remains usable but explicitly disables this updater; a build with only one variable or with `NL_REQUIRE_NATIVE_UPDATER=1` and no key fails. Retain existing component trust configuration and signing secrets separately. Never allow untrusted build jobs to access signing secrets.

## GitHub delivery (1.1.2+)

For a public GitHub repository use the protected [GitHub Release Delivery workflow](github-release-delivery.md). It automatically embeds the repository's stable feed URL, builds signed native installers and coordinated updater packages, signs the exact final bytes, verifies all six targets, and publishes a complete draft as Latest. Do not manually overwrite its assets.

## Sign and publish final artifacts

1. Build native coordinated production packages using the existing release scripts and complete the existing platform and component-set verification. Do not sign incomplete development archives or individual desktop executables as updater payloads.
2. On the protected release host, use Tauri CLI to sign the exact finalized bytes; set `TAURI_SIGNING_PRIVATE_KEY_PATH` to the key location and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` via protected environment variables. For each package, run `cargo tauri signer sign --app-version <VERSION> <final-package>` (CLI 2.12+). This produces `<final-package>.sig`. The private key is never needed on clients.
3. Generate `latest.json` from the signed packages and independently trusted public key:

```sh
python -m pip install 'cryptography>=42,<47'
python scripts/release/native_updater_feed.py --version "$(cat VERSION)" \
  --base-url 'https://YOUR-RELEASE-HOST/neverlauncher/releases/v1.1.1' \
  --output latest.json path/to/final-package.zip path/to/final-linux-package.tar.gz
```

The generator checks the real Ed25519 signatures over the final bytes and authenticated version comments using the pinned public key. It checks product/version/target/production trust mode and component roles, rejects duplicate targets and emits the Tauri static feed. It does not replace the pre-existing release verification. Feed keys are `windows-x86_64`, `windows-aarch64`, `linux-x86_64`, `linux-aarch64`, `darwin-x86_64`, `darwin-aarch64` for the targets actually built. Publish only the exact verified packages, then atomically publish `latest.json` at the configured endpoint. Use immutable versioned artifact URLs. Do not advertise unavailable targets. Use separate trusted keys/endpoints for independent distributions.

## Acceptance

Run Desktop `npm run test:native-update`, `python -m unittest discover -s scripts/release -p test_native_updater_feed.py -v`, `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml native_updater` and Desktop `npm run build`. On disposable Windows, Linux and macOS installations: install the configured 1.1.1 build, publish an independently verified strictly newer signed build, check and install it, verify restart/version, component trust, game launch and preserved settings/session. Repeat with an equal/older version, invalid signature, modified package, signed-version mismatch, wrong architecture, offline endpoint and active game; no installation must be scheduled. Real owner credentials and production signed packages are required for this acceptance; tests alone do not prove production installation.

For 1.1.3 acceptance, verify startup without opening Settings, switching screens during download, all three saved intervals, disabling automatic checks, opt-in automatic download without restart, known/unknown length, interrupted network and retry, malicious HTML in notes rendered literally, refusal to install while Minecraft runs, successful retry after it exits, and a restart only after explicit confirmation. Run on a user-writable installation with a real signed newer build.


## Update Recovery (1.1.4)

- Incomplete bytes are retained only in Rust memory, bounded to 512 MiB, and only if the response supplied a strong ETag and known length. Retry uses Range/If-Range for the exact same version, URL and signature. HTTP 200 replaces partial bytes; an invalid 206 or 416 discards the partial buffer and attempts a full request. A process exit discards the buffer; the next launch downloads from zero. Every completed download is authenticated again before it can be installed.
- Temporary failures show Retry download and use the existing 15-minute automatic check backoff. A package rejected by the signature, platform or component preflight is not retried automatically during the same process for the same offer. A new signed offer can be checked normally. There is no automatic install.
- The staged CLI verifies package SHA-256, component manifest, binaries, protocol compatibility, security generation and trust-policy floor before the running Desktop exits. The transactional install repeats security checks. Its output is retained in `update.log` in the private `updater-helpers/<random>/` directory. On an installation failure the helper attempts journal recovery without `--force`; restart is permitted only when the active component state and exact Desktop executable verify. If that verification fails, use the trusted platform installer for repair rather than starting mixed components. A failed restart or missing previous signed state can require manual repair.
- A pending version recorded in local UI preferences suppresses automatic downloads of that same release if it remains offered after restart; manual retry is available. This is not a security boundary. The updater does not resume a download across process restarts or bypass signature/trust checks.
- Acceptance: serve the real signed artifact with a strong ETag, disconnect partway, retry with correct 206; repeat with changed ETag, malformed range, 200 fallback, 416, missing validator and altered bytes. Confirm incompatible signed protocol/generation is rejected before exit; interrupt the installer during staging and committing, then verify old/new coherent set and preserved user files. Confirm live locks refuse startup, a tree-only macOS journal triggers recovery, and recovery refuses a missing/unverified state. Repeat on all supported platforms using actual signed releases. Review `update.log` if the installed state cannot be verified.


## Stable and Beta (1.2.0)

- Stable is the default, including migration from previous versions. Beta is opt-in via Settings → Обновление Launcher → Канал обновлений, with explicit confirmation. Automatic check/download preferences are retained, and installation always requires confirmation.
- Stable keeps the existing `https://github.com/<owner>/<repo>/releases/latest/download/latest.json` route and existing pinned key. Beta scans the public GitHub Releases API of the compile-time configured repository, chooses the highest numeric version with the matching feed asset and release flag, and fetches that exact versioned feed. Drafts, mixed feed names, unrelated tags and older/equal versions are ignored. Stable candidates use the Stable key, Beta candidates use the Beta key. A GitHub API failure is shown as an error rather than silently mixing channels. The scan is bounded to 1,000 releases and 40 seconds; exceptionally large histories must be pruned of obsolete non-product releases or the discovery mechanism extended before reaching that limit.
- A channel change invalidates the native offer, partial and prepared package; download and install commands must match the selected channel. No downgrade, including returning from a newer Beta to Stable. Wait for the next higher Stable release or explicitly reinstall a trusted installer outside the updater, following the component security-generation policy.
- Version numbering is a single strictly increasing sequence of `X.Y.Z` versions across both channels because native MSI and the coordinated product version are numeric. For example, publish 1.2.0 Stable, 1.2.1 Beta, then 1.2.2 Stable. Beta is identified by GitHub prerelease status, `latest-beta.json` and a distinct signing key, not a `-beta.N` suffix. Do not publish the same version in both channels.
- Configure a second independent Tauri key using `cargo tauri signer generate -w /secure/neverlauncher-beta.key`. Preserve the previous Stable public key for existing clients. Set `NL_UPDATER_BETA_PUBLIC_KEY` to the second `.pub` file contents and `NL_UPDATER_GITHUB_REPOSITORY` to `owner/repository`; `NL_REQUIRE_BETA_UPDATER=1` makes both mandatory. GitHub release builds require both keys. A non-GitHub Stable-only build may omit the Beta pair; selecting Beta then produces an explicit configuration error. No keys or release URLs can be provided by the WebView. Identical underlying public key material is rejected even if its comment or key ID differs.

### Auto-Updates GA acceptance

The reusable `native-updater.yml` is a mandatory release gate. It checks signed six-target delivery fixtures and runs Desktop/Rust tests, builds and Go transaction/recovery tests on Windows, Linux and macOS. After publication the GitHub release workflow checks the public release classification, the actual feed and every advertised updater archive by streaming the public download and comparing its size and SHA-256 with the verified signed local artifacts. It does not delete or alter a published release on failure; investigate and publish a newer corrected version through the same protected process.

Before approving `production-publish`, perform owner-controlled testing using signed, user-writable installations on Windows x64/ARM64, Linux x64/ARM64 and macOS x64/ARM64: Stable cannot download Beta under the Stable key; Beta discovers a higher Beta; Beta sees the next higher Stable; returning to Stable from a higher Beta does not downgrade; switching during a prepared update invalidates it; network interruption, invalid signature, wrong platform, rollback and post-install restart preserve the installed component set. CI and public delivery verification are not a substitute for installing these actual builds on each platform. No real signed release or live E2E execution is implied by this source change.
