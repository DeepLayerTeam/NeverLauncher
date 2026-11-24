# Native Updater (1.1.1)

## Trust and installation

Desktop → Настройки → Обновление Launcher. The version check uses `tauri-plugin-updater` 2.14.1; only a strictly newer stable SemVer is offered. The offer is retained natively for 15 minutes. An offered version is not proof that the package is authentic. Only after explicit confirmation does Rust download the exact offered URL over HTTPS with a ten-minute deadline and a 512 MiB limit. It verifies the bytes with `Update::verify`, requiring the signed version in the minisign trusted comment, then checks the version/platform/architecture of `COMPONENT_UPDATE_MANIFEST.json` inside the authenticated archive. The WebView cannot provide a key, URL, package path or hash, and receives only progress and version information.

Existing coordinated component archives are the update payload: Windows and macOS ZIP, Linux TAR.GZ (ZIP also accepted). The Tauri `Update::install` standalone binary replacement is intentionally not used: the existing CLI transactional installer verifies the signed component set, trust policy, security generation and platform requirements and replaces Desktop, Guard, Runtime and required support files together. An arbitrary file path/hash is no longer exposed as an IPC installation command. Running Minecraft and in-flight native game mutations block installation. The verified bytes are staged in a private per-update directory and the helper receives their native SHA-256; no user-supplied SHA-256 is trusted. The helper needs write access to the installed component layout and must be present; system-managed installations requiring elevated privileges should use their OS package manager. On Windows/macOS the existing OS code-signing requirements remain independent of the Tauri signature.

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

Run `python -m unittest discover -s scripts/release -p test_native_updater_feed.py -v`, `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml native_updater` and Desktop `npm run build`. On disposable Windows, Linux and macOS installations: install the configured 1.1.1 build, publish an independently verified strictly newer signed build, check and install it, verify restart/version, component trust, game launch and preserved settings/session. Repeat with an equal/older version, invalid signature, modified package, signed-version mismatch, wrong architecture, offline endpoint and active game; no installation must be scheduled. Real owner credentials and production signed packages are required for this acceptance; tests alone do not prove production installation.
